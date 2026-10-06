// Package client provides a CyberArk PVWA REST API client with authentication,
// retry logic, and methods for fetching users, groups, safes, and accounts.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/parallel"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	// SafePageLimit is the default number of safes to retrieve per page.
	SafePageLimit = 100
	// safeIsolationPageLimit is the page size below which a reduced safes page
	// is treated as a probe to isolate a single unreadable safe rather than as
	// the new working page size for the rest of the collection.
	safeIsolationPageLimit = 10
	// maxConsecutiveSafeSkips caps how many safes in a row may be skipped
	// before ListSafes stops trying to read the remaining pages.
	maxConsecutiveSafeSkips = 25
	// UserExtendedDetailsTimeout is the default timeout for the optional user
	// enrichment endpoint before falling back to the basic user list.
	UserExtendedDetailsTimeout = 60 * time.Second
	// MaxRateLimitRetries is the default number of HTTP 429 responses a single
	// request tolerates before giving up.
	MaxRateLimitRetries = 10
	// maxRetryAfter caps how long a server-supplied Retry-After header can make
	// a request wait, so a bogus value cannot stall the collection for hours.
	maxRetryAfter = 5 * time.Minute

	// AuthMethodCyberArk is the default self-hosted PVWA CyberArk authentication.
	AuthMethodCyberArk = "cyberark"
	// AuthMethodLDAP is self-hosted PVWA LDAP/Directory authentication.
	AuthMethodLDAP = "ldap"
	// AuthMethodRADIUS is self-hosted PVWA RADIUS authentication.
	AuthMethodRADIUS = "radius"
	// AuthMethodWindows is self-hosted PVWA integrated Windows authentication.
	AuthMethodWindows = "windows"
	// AuthMethodIdentity is CyberArk Identity Security Platform Shared Services
	// (ISPSS) OAuth2 authentication, used by Privilege Cloud (SaaS).
	AuthMethodIdentity = "identity"
)

// selfHostedLogonPathSegment maps a normalised auth method to the path segment
// used in the self-hosted PVWA logon endpoint /API/Auth/{segment}/Logon.
var selfHostedLogonPathSegment = map[string]string{
	AuthMethodCyberArk: "CyberArk",
	AuthMethodLDAP:     "LDAP",
	AuthMethodRADIUS:   "radius",
	AuthMethodWindows:  "Windows",
}

// NormalizeAuthMethod lower-cases and validates an auth method string, returning
// the canonical value (defaulting to CyberArk when empty) and whether it is
// recognised.
func NormalizeAuthMethod(method string) (string, bool) {
	m := strings.ToLower(strings.TrimSpace(method))
	if m == "" {
		return AuthMethodCyberArk, true
	}
	switch m {
	case AuthMethodCyberArk, AuthMethodLDAP, AuthMethodRADIUS, AuthMethodWindows, AuthMethodIdentity:
		return m, true
	// Friendly aliases.
	case "ispss", "privilegecloud", "privilege-cloud", "oauth2", "oauth":
		return AuthMethodIdentity, true
	default:
		return m, false
	}
}

// HTTPError represents a non-2xx HTTP response from the PVWA API. It allows
// callers to react to specific status codes (e.g. treat 404 as "not found"
// rather than a hard failure) via errors.As / httpStatus.
type HTTPError struct {
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
}

// httpStatus returns the HTTP status code carried by an *HTTPError in the error
// chain, or 0 if the error is not (or does not wrap) an *HTTPError.
func httpStatus(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.StatusCode
	}
	return 0
}

// Client encapsulates CyberArk PVWA REST API interactions
type Client struct {
	BaseURL  string
	Username string
	Password string
	// AuthMethod selects how Authenticate() obtains a session token. Use the
	// AuthMethod* constants. Defaults to AuthMethodCyberArk (self-hosted PVWA).
	AuthMethod string
	// IdentityTenantURL is the CyberArk Identity (ISPSS) tenant base URL used to
	// obtain an OAuth2 platform token, e.g. https://abc1234.id.cyberark.cloud.
	// Required when AuthMethod is AuthMethodIdentity (Privilege Cloud / SaaS).
	IdentityTenantURL          string
	AuthTimeout                time.Duration
	ReqTimeout                 time.Duration
	UserExtendedDetailsTimeout time.Duration
	UserEnrichmentWorkers      int
	SafePageLimit              int
	// Token is the current session token. Once requests are running
	// concurrently it must only be accessed through tokenSnapshot/setToken.
	Token               string
	HTTPClient          *http.Client
	Logger              *logrus.Logger
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
	RetryMultiplier     float64
	RetryJitter         float64
	MaxReauthAttempts   int
	// MaxRateLimitRetries is how many HTTP 429 responses one request tolerates
	// before failing. Zero or less means retry indefinitely.
	MaxRateLimitRetries int
	// IncludePredefinedSafeMembers asks PVWA to also return built-in safe
	// members (Master, Vault Admins, Auditors, ...), which the Safe members API
	// omits by default.
	IncludePredefinedSafeMembers bool

	// authMu serialises re-authentication so only one goroutine re-auths at a time.
	authMu sync.Mutex
	// tokenMu guards Token and tokenGen: worker goroutines read them on every
	// request while a re-authentication may be replacing them.
	tokenMu sync.RWMutex
	// tokenGen is bumped on every token change; workers compare their snapshot
	// to decide whether someone else already refreshed the token.
	tokenGen uint64

	// ctx bounds every request; cancelling it aborts in-flight requests and
	// retry waits. See SetContext.
	ctx context.Context

	// predefinedFilterRejected is set once PVWA has rejected the
	// includePredefinedUsers filter, so later safes skip it.
	predefinedFilterRejected atomic.Bool

	issuesMu sync.Mutex
	issues   []string

	// setupErr records a configuration problem found by NewClient (such as
	// an unreadable CA bundle). Authenticate returns it before sending any
	// request, so the client never runs with an unintended trust setup.
	setupErr error
}

type cancelOnCloseReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelOnCloseReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

// NormalizeBaseURL turns a user-supplied server address into a base URL the
// HTTP client can use: surrounding whitespace and trailing slashes are removed
// and https:// is assumed when no scheme is given (Go's net/http rejects
// scheme-less URLs with `unsupported protocol scheme ""`). An explicit
// http:// or https:// scheme is preserved. The empty string is returned as is.
func NormalizeBaseURL(raw string) string {
	u := strings.TrimSpace(raw)
	if u == "" {
		return ""
	}
	if !strings.Contains(u, "://") {
		u = "https://" + u
	}
	return strings.TrimRight(u, "/")
}

// NewClient creates a new CyberArk API client. baseURL is normalised with
// NormalizeBaseURL, so a bare hostname such as "pvwa.example.com" is accepted.
// caBundle, when set, is a PEM file of CA certificates trusted in addition to
// the system roots; if it cannot be used, Authenticate reports why.
func NewClient(baseURL, username, password string, insecure bool, caBundle string, logger *logrus.Logger) *Client {
	baseURL = NormalizeBaseURL(baseURL)
	if strings.HasPrefix(baseURL, "http://") && logger != nil {
		logger.Warnf("PVWA URL %s uses plain HTTP; credentials will be sent unencrypted", baseURL)
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}
	jar, err := cookiejar.New(nil)
	if err != nil && logger != nil {
		logger.Warnf("Failed to create HTTP cookie jar; PVWA affinity cookies will not be persisted: %v", err)
	}

	c := &Client{
		BaseURL:    baseURL,
		Username:   username,
		Password:   password,
		AuthMethod: AuthMethodCyberArk,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   360 * time.Second,
			Jar:       jar,
		},
		Logger:                       logger,
		AuthTimeout:                  360 * time.Second,
		ReqTimeout:                   360 * time.Second,
		UserExtendedDetailsTimeout:   UserExtendedDetailsTimeout,
		UserEnrichmentWorkers:        20,
		SafePageLimit:                SafePageLimit,
		RetryInitialBackoff:          1 * time.Second,
		RetryMaxBackoff:              60 * time.Second,
		RetryMultiplier:              2.0,
		RetryJitter:                  0.2,
		MaxReauthAttempts:            5,
		MaxRateLimitRetries:          MaxRateLimitRetries,
		IncludePredefinedSafeMembers: true,
	}
	if caBundle != "" {
		pool, err := loadCABundle(caBundle)
		if err != nil {
			c.setupErr = err
		} else {
			transport.TLSClientConfig.RootCAs = pool
		}
	}
	return c
}

// loadCABundle returns the system roots plus the PEM certificates in path.
func loadCABundle(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA bundle %s contains no PEM certificates", path)
	}
	return pool, nil
}

// SetContext sets the context that bounds every request the client makes.
// Cancelling it aborts in-flight requests and retry waits, so a collection can
// be stopped promptly (e.g. on Ctrl+C). Call it before issuing requests.
func (c *Client) SetContext(ctx context.Context) {
	c.ctx = ctx
}

// context returns the client's base context, defaulting to Background.
func (c *Client) context() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// tokenSnapshot returns the current token and its generation.
func (c *Client) tokenSnapshot() (string, uint64) {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.Token, c.tokenGen
}

// setToken replaces the session token and bumps its generation.
func (c *Client) setToken(token string) {
	c.tokenMu.Lock()
	c.Token = token
	c.tokenGen++
	c.tokenMu.Unlock()
}

// noteIncomplete records a reason the collection does not cover the whole
// environment, so the caller can report it alongside the export.
func (c *Client) noteIncomplete(format string, args ...interface{}) {
	c.issuesMu.Lock()
	c.issues = append(c.issues, fmt.Sprintf(format, args...))
	c.issuesMu.Unlock()
}

// PredefinedMembersExcluded reports whether PVWA rejected the request for
// built-in safe members, so that safes listed since then lack them.
func (c *Client) PredefinedMembersExcluded() bool {
	return c.predefinedFilterRejected.Load()
}

// IncompleteReasons returns, in the order they were recorded, the reasons the
// collection could not cover everything (failed per-object lookups whose data
// is missing from the export).
func (c *Client) IncompleteReasons() []string {
	c.issuesMu.Lock()
	defer c.issuesMu.Unlock()
	return append([]string(nil), c.issues...)
}

// sleepContext waits for d, returning early with the context's error if ctx
// is cancelled first.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// throttle waits for a jittered backoff before a retry. It returns the
// context's error if the wait was cut short by cancellation.
func (c *Client) throttle(ctx context.Context, backoff time.Duration) error {
	jitter := 1.0 + (rand.Float64()*2-1)*c.RetryJitter
	sleepTime := time.Duration(math.Min(float64(backoff)*jitter, float64(c.RetryMaxBackoff)))
	c.Logger.Debugf("Sleeping %.2fs before retry.", sleepTime.Seconds())
	return sleepContext(ctx, sleepTime)
}

// retryAfterDelay parses a Retry-After header, which is either a number of
// seconds or an HTTP date. The second return reports whether a usable value
// was present.
func retryAfterDelay(header string, now time.Time) (time.Duration, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := t.Sub(now); d > 0 {
			return d, true
		}
		return 0, true
	}
	return 0, false
}

// requestWithRetries executes HTTP request with retry logic
func (c *Client) requestWithRetries(method, urlPath string, body interface{}, timeout time.Duration, maxRetries int) (*http.Response, error) {
	return c.requestWithRetriesAndReauth(method, urlPath, body, timeout, maxRetries, c.MaxReauthAttempts)
}

func (c *Client) requestWithRetriesAndReauth(method, urlPath string, body interface{}, timeout time.Duration, maxRetries int, maxReauthAttempts int) (*http.Response, error) {
	return c.doWithRetries(c.context(), method, urlPath, body, timeout, maxRetries, maxReauthAttempts)
}

func (c *Client) doWithRetries(ctx context.Context, method, urlPath string, body interface{}, timeout time.Duration, maxRetries int, maxReauthAttempts int) (*http.Response, error) {
	attempt := 0
	backoff := c.RetryInitialBackoff
	reauthAttempts := 0
	rateLimited := 0

	// Pre-marshal body once to avoid re-marshaling on each retry
	var jsonData []byte
	if body != nil {
		var err error
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	// aborted wraps a cancellation of ctx so callers can tell it apart from
	// an API failure with errors.Is(err, context.Canceled).
	aborted := func() error {
		return fmt.Errorf("request to %s aborted: %w", urlPath, ctx.Err())
	}

	for {
		if ctx.Err() != nil {
			return nil, aborted()
		}
		attempt++
		c.Logger.Debugf("Request attempt %d: %s %s", attempt, method, urlPath)

		// Snapshot the token and its generation together before issuing the
		// request. On a 401 the generation is passed to reauthIfNeeded so it
		// can tell whether another goroutine already refreshed the token.
		token, preReqGen := c.tokenSnapshot()

		var bodyReader io.Reader
		if jsonData != nil {
			bodyReader = bytes.NewReader(jsonData)
		}

		reqCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, timeout)
		}

		req, err := http.NewRequestWithContext(reqCtx, method, urlPath, bodyReader)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		if jsonData != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if header := c.authorizationHeaderValue(token); header != "" {
			req.Header.Set("Authorization", header)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			if ctx.Err() != nil {
				return nil, aborted()
			}
			c.Logger.Warnf("Request error attempt %d for %s: %v", attempt, urlPath, err)
			if maxRetries > 0 && attempt >= maxRetries {
				return nil, fmt.Errorf("max retries reached: %w", err)
			}

			// Wait but don't increase backoff duration
			if c.throttle(ctx, backoff) != nil {
				return nil, aborted()
			}
			continue
		}
		if cancel != nil {
			resp.Body = &cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
		}

		// Handle HTTP status codes
		if resp.StatusCode == http.StatusUnauthorized {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			responseText := strings.TrimSpace(string(bodyBytes))
			if readErr != nil {
				responseText = fmt.Sprintf("failed to read 401 response body: %v", readErr)
			}
			if responseText == "" {
				responseText = "empty response body"
			}
			reauthAttempts++
			if reauthAttempts > maxReauthAttempts {
				return nil, fmt.Errorf("authentication retries exhausted for %s (attempted %d times; last 401 response: %s)", urlPath, reauthAttempts, responseText)
			}
			c.Logger.Warnf("HTTP 401 received for %s (response: %s). Re-authenticating (re-auth attempt %d/%d)...", urlPath, responseText, reauthAttempts, maxReauthAttempts)
			if err := c.reauthIfNeeded(preReqGen); err != nil {
				return nil, fmt.Errorf("re-authentication failed: %w", err)
			}

			// Don't count re-auth attempts against main retry counter
			attempt--

			// wait but don't increase backoff duration
			if c.throttle(ctx, backoff) != nil {
				return nil, aborted()
			}
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter, hasRetryAfter := retryAfterDelay(resp.Header.Get("Retry-After"), time.Now())
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			// HTTP 429 doesn't count against the main retry counter, but has
			// its own cap so a PVWA that keeps throttling cannot stall the
			// collection forever.
			rateLimited++
			if c.MaxRateLimitRetries > 0 && rateLimited > c.MaxRateLimitRetries {
				return nil, fmt.Errorf("rate limited %d times for %s, giving up: %w", rateLimited, urlPath,
					&HTTPError{StatusCode: http.StatusTooManyRequests, Body: "too many requests"})
			}
			attempt--

			var waitErr error
			if hasRetryAfter && retryAfter > 0 {
				if retryAfter > maxRetryAfter {
					retryAfter = maxRetryAfter
				}
				c.Logger.Debugf("HTTP 429 for %s; honouring Retry-After of %s", urlPath, retryAfter)
				waitErr = sleepContext(ctx, retryAfter)
			} else {
				waitErr = c.throttle(ctx, backoff)
			}
			if waitErr != nil {
				return nil, aborted()
			}
			backoff = time.Duration(math.Min(float64(backoff)*c.RetryMultiplier, float64(c.RetryMaxBackoff)))
			continue
		}

		if resp.StatusCode >= 400 {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("HTTP %d: failed to read error response: %w", resp.StatusCode, readErr)
			}
			httpErr := &HTTPError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}

			// Server-side failures are usually transient (PVWA under load, a
			// recycling app pool, a gateway hiccup), so retry them like network
			// errors.  The known safe page mapping bug is excluded: it fails
			// identically on every attempt, so retrying only burns another
			// request timeout, and ListSafes recovers by shrinking the page.
			if resp.StatusCode >= 500 && !isPVWASafePageServerError(httpErr) {
				c.Logger.Warnf("HTTP %d on attempt %d for %s: %s", resp.StatusCode, attempt, urlPath, previewBody(string(bodyBytes)))
				if maxRetries > 0 && attempt >= maxRetries {
					return nil, fmt.Errorf("max retries reached: %w", httpErr)
				}
				if c.throttle(ctx, backoff) != nil {
					return nil, aborted()
				}
				backoff = time.Duration(math.Min(float64(backoff)*c.RetryMultiplier, float64(c.RetryMaxBackoff)))
				continue
			}

			return nil, httpErr
		}

		// Guard against PVWA returning HTML (e.g. IIS login/error page) on
		// an otherwise successful HTTP 200.  Every valid PVWA API response is
		// JSON, so a non-JSON Content-Type is treated as a transient error
		// and retried.
		ct := resp.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, "application/json") && !strings.Contains(ct, "text/json") {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			c.Logger.Warnf("Non-JSON response (Content-Type: %s) for %s: %s", ct, urlPath, previewBody(string(bodyBytes)))
			if maxRetries > 0 && attempt >= maxRetries {
				return nil, fmt.Errorf("non-JSON response for %s (Content-Type: %s)", urlPath, ct)
			}
			if c.throttle(ctx, backoff) != nil {
				return nil, aborted()
			}
			continue
		}

		if attempt > 1 {
			c.Logger.Infof("Request succeeded on attempt %d: %s", attempt, urlPath)
		}

		return resp, nil
	}
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "Client.Timeout exceeded") ||
		strings.Contains(err.Error(), "context deadline exceeded")
}

func isPVWASafePageServerError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "HTTP 500") &&
		(strings.Contains(msg, "CAWS00001E") ||
			strings.Contains(msg, "Error mapping types") ||
			strings.Contains(msg, "IReadOnlyCollection`1 -> List`1"))
}

// isRecoverableSafePageError reports whether a safes page failure is worth
// retrying with a smaller page: a timeout, the known PVWA type-mapping bug, or
// any other server-side failure.
func isRecoverableSafePageError(err error) bool {
	return isTimeoutError(err) || isPVWASafePageServerError(err) || httpStatus(err) >= 500
}

// lowerSafePageLimit halves a safes page size, bottoming out at a single safe
// so that one record PVWA cannot serialise can be isolated and skipped instead
// of taking a whole page (and the rest of the collection) down with it.
func lowerSafePageLimit(limit int) int {
	if limit <= 1 {
		return 1
	}
	return limit / 2
}

// previewBody truncates a response body so it can be logged safely.
func previewBody(body string) string {
	const maxPreview = 200
	body = strings.TrimSpace(body)
	if len(body) > maxPreview {
		return body[:maxPreview] + "..."
	}
	return body
}

func mergeUserDetails(base models.User, details models.User) models.User {
	if details.ID != nil {
		base.ID = details.ID
	}
	if details.Username != "" {
		base.Username = details.Username
	}
	if details.Source != "" {
		base.Source = details.Source
	}
	if details.UserType != "" {
		base.UserType = details.UserType
	}
	if details.Location != "" {
		base.Location = details.Location
	}
	if details.UserDN != "" {
		base.UserDN = details.UserDN
	}
	if len(details.VaultAuthorization) > 0 {
		base.VaultAuthorization = details.VaultAuthorization
	}
	if len(details.AuthorizedInterfaces) > 0 {
		base.AuthorizedInterfaces = details.AuthorizedInterfaces
	}
	if len(details.AllowedAuthenticationMethods) > 0 {
		base.AllowedAuthenticationMethods = details.AllowedAuthenticationMethods
	}
	if len(details.GroupsMembership) > 0 {
		base.GroupsMembership = details.GroupsMembership
	}
	base.ComponentUser = details.ComponentUser
	base.Enabled = details.Enabled
	base.Suspended = details.Suspended
	base.PersonalDetails = details.PersonalDetails
	return base
}

func userHasIdentity(user models.User) bool {
	return user.Username != "" || models.IDString(user.ID) != ""
}

// isIdentityAuth reports whether the client uses CyberArk Identity (ISPSS)
// OAuth2 authentication (Privilege Cloud / SaaS).
func (c *Client) isIdentityAuth() bool {
	method, _ := NormalizeAuthMethod(c.AuthMethod)
	return method == AuthMethodIdentity
}

// authorizationHeaderValue returns the value to set on the Authorization header
// for token. Identity (OAuth2) tokens are bearer tokens and must be prefixed
// with "Bearer "; self-hosted PVWA session tokens are sent verbatim.
func (c *Client) authorizationHeaderValue(token string) string {
	if token == "" {
		return ""
	}
	if c.isIdentityAuth() {
		return "Bearer " + token
	}
	return token
}

// Authenticate obtains a session token from CyberArk. For self-hosted PVWA it
// uses the /API/Auth/{method}/Logon endpoint; for Privilege Cloud (SaaS) it uses
// the CyberArk Identity (ISPSS) OAuth2 client-credentials flow.
func (c *Client) Authenticate() error {
	if c.setupErr != nil {
		return c.setupErr
	}
	if c.isIdentityAuth() {
		return c.authenticateIdentity()
	}
	return c.authenticateSelfHosted()
}

// authenticateIdentity authenticates against CyberArk Identity Security Platform
// Shared Services (ISPSS), used by Privilege Cloud (SaaS). It first tries the
// OAuth2 client-credentials grant (for OAuth confidential client service users);
// if that is rejected it falls back to the interactive CyberArk Identity
// username/password flow (StartAuthentication → AdvanceAuthentication). The
// resulting platform token is a bearer token used against the Privilege Cloud
// PasswordVault REST API.
func (c *Client) authenticateIdentity() error {
	if strings.TrimSpace(c.IdentityTenantURL) == "" {
		return fmt.Errorf("identity authentication requires the CyberArk Identity tenant URL (e.g. https://<tenant>.id.cyberark.cloud)")
	}

	// 1. OAuth2 client_credentials — for OAuth confidential client service users.
	token, ccErr := c.identityClientCredentialsToken()
	if ccErr == nil {
		c.setToken(token)
		c.Logger.Infof("Authenticated to CyberArk Identity via OAuth2 client_credentials (token length: %d chars)", len(token))
		return nil
	}
	c.Logger.Debugf("OAuth2 client_credentials grant not accepted (%v); falling back to CyberArk Identity username/password authentication", ccErr)

	// 2. Interactive username/password — StartAuthentication → AdvanceAuthentication.
	token, err := c.identityInteractiveToken()
	if err != nil {
		return fmt.Errorf("CyberArk Identity authentication failed (OAuth2 client_credentials grant rejected: %v): %w", ccErr, err)
	}
	c.setToken(token)
	c.Logger.Infof("Authenticated to CyberArk Identity via username/password (token length: %d chars)", len(token))
	return nil
}

// identityClientCredentialsToken obtains a platform token via the OAuth2
// client-credentials grant. The service user's username is the client_id and the
// password is the client_secret. Returns the access_token on success.
func (c *Client) identityClientCredentialsToken() (string, error) {
	tokenURL := strings.TrimRight(c.IdentityTenantURL, "/") + "/oauth2/platformtoken"
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.Username)
	form.Set("client_secret", c.Password)

	c.Logger.Debugf("Requesting CyberArk Identity platform token from %s (OAuth2 client_credentials) as %s", tokenURL, c.Username)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	ctx, cancel := context.WithTimeout(c.context(), c.AuthTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}
	token := strings.TrimSpace(tokenResp.AccessToken)
	if token == "" {
		return "", fmt.Errorf("token response did not contain an access_token")
	}
	return token, nil
}

// identityChallengeMechanism is one authentication mechanism (e.g. password,
// OTP, OOB) offered within a CyberArk Identity challenge.
type identityChallengeMechanism struct {
	AnswerType  string `json:"AnswerType"`
	Name        string `json:"Name"`
	MechanismId string `json:"MechanismId"`
}

// identityChallenge is a set of mechanisms the user may satisfy to advance
// authentication. Multiple challenges in sequence indicate additional factors.
type identityChallenge struct {
	Mechanisms []identityChallengeMechanism `json:"Mechanisms"`
}

type identityAuthResult struct {
	SessionId        string              `json:"SessionId"`
	Summary          string              `json:"Summary"`
	Token            string              `json:"Token"`
	Challenges       []identityChallenge `json:"Challenges"`
	IdpRedirectUrl   string              `json:"IdpRedirectUrl"`
	IdpRedirectShort string              `json:"IdpRedirectShort"`
}

type identityAuthResponse struct {
	Success bool               `json:"success"`
	Result  identityAuthResult `json:"Result"`
	Message string             `json:"Message"`
}

// identityInteractiveToken performs the CyberArk Identity username/password flow
// (StartAuthentication → AdvanceAuthentication) and returns the platform bearer
// token. It returns a clear, actionable error when the account requires MFA or
// federated/SAML sign-in, neither of which can be completed non-interactively.
func (c *Client) identityInteractiveToken() (string, error) {
	base := strings.TrimRight(c.IdentityTenantURL, "/")

	var startResp identityAuthResponse
	if err := c.doIdentityJSONPost(base+"/Security/StartAuthentication",
		map[string]string{"User": c.Username, "Version": "1.0"}, &startResp); err != nil {
		return "", fmt.Errorf("StartAuthentication request failed: %w", err)
	}
	if !startResp.Success {
		return "", fmt.Errorf("StartAuthentication rejected for %q: %s", c.Username, firstNonEmpty(startResp.Message, "unknown error"))
	}
	res := startResp.Result

	// Federated / SAML sign-in redirects to an external IdP and cannot be
	// completed non-interactively.
	if res.IdpRedirectUrl != "" || res.IdpRedirectShort != "" || hasFederatedMechanism(res.Challenges) {
		return "", fmt.Errorf("account %q uses federated/SAML sign-in, which cannot be completed non-interactively; use an OAuth confidential client service user with --auth-method identity instead", c.Username)
	}
	if res.SessionId == "" {
		return "", fmt.Errorf("StartAuthentication did not return a session for %q", c.Username)
	}

	upMech, ok := findPasswordMechanism(res.Challenges)
	if !ok {
		return "", fmt.Errorf("CyberArk Identity did not offer a username/password challenge for %q (the account may require a different authentication mechanism)", c.Username)
	}

	var advResp identityAuthResponse
	if err := c.doIdentityJSONPost(base+"/Security/AdvanceAuthentication",
		map[string]string{
			"SessionId":   res.SessionId,
			"MechanismId": upMech.MechanismId,
			"Action":      "Answer",
			"Answer":      c.Password,
		}, &advResp); err != nil {
		return "", fmt.Errorf("AdvanceAuthentication request failed: %w", err)
	}
	if !advResp.Success {
		return "", fmt.Errorf("username/password authentication rejected for %q: %s", c.Username, firstNonEmpty(advResp.Message, "invalid credentials"))
	}

	summary := advResp.Result.Summary
	token := strings.TrimSpace(advResp.Result.Token)
	if summary == "LoginSuccess" {
		if token == "" {
			return "", fmt.Errorf("authentication succeeded but no platform token was returned for %q", c.Username)
		}
		return token, nil
	}

	// A "next challenge" summary unambiguously means another factor is required,
	// even if a partial token is present.
	switch summary {
	case "StartNextChallenge", "NewPackage", "OobPending":
		return "", fmt.Errorf("account %q requires multi-factor authentication (MFA), which cannot be completed non-interactively; create an OAuth confidential client service user that is excluded from MFA and use it with --auth-method identity", c.Username)
	}

	// Some tenants return a token with a non-LoginSuccess summary; accept it.
	if token != "" {
		return token, nil
	}
	return "", fmt.Errorf("account %q requires an additional authentication factor that cannot be completed non-interactively (CyberArk Identity state: %q); use an OAuth confidential client service user excluded from MFA with --auth-method identity", c.Username, firstNonEmpty(summary, "unknown"))
}

// doIdentityJSONPost POSTs a JSON body to a CyberArk Identity endpoint and decodes
// the response into out. The X-IDAP-NATIVE-CLIENT header asks Identity to return
// the platform token in the response body rather than as a session cookie.
func (c *Client) doIdentityJSONPost(reqURL string, body interface{}, out interface{}) error {
	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", reqURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-IDAP-NATIVE-CLIENT", "true")

	ctx, cancel := context.WithTimeout(c.context(), c.AuthTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	if out != nil {
		if err := json.Unmarshal(bodyBytes, out); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}
	return nil
}

// findPasswordMechanism returns the username/password ("UP") mechanism from the
// offered challenges, if present.
func findPasswordMechanism(challenges []identityChallenge) (identityChallengeMechanism, bool) {
	for _, ch := range challenges {
		for _, m := range ch.Mechanisms {
			if strings.EqualFold(m.Name, "UP") {
				return m, true
			}
		}
	}
	return identityChallengeMechanism{}, false
}

// hasFederatedMechanism reports whether any offered mechanism is a federated /
// SAML / IdP-redirect mechanism that cannot be answered non-interactively.
func hasFederatedMechanism(challenges []identityChallenge) bool {
	for _, ch := range challenges {
		for _, m := range ch.Mechanisms {
			name := strings.ToLower(m.Name)
			answerType := strings.ToLower(m.AnswerType)
			if strings.Contains(name, "saml") || strings.Contains(name, "fed") ||
				strings.Contains(answerType, "redirect") || strings.Contains(answerType, "saml") {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// authenticateSelfHosted logs into a self-hosted CyberArk PVWA API using the
// configured authentication method (CyberArk, LDAP, RADIUS, or Windows).
func (c *Client) authenticateSelfHosted() error {
	method, ok := NormalizeAuthMethod(c.AuthMethod)
	if !ok {
		return fmt.Errorf("unsupported auth method %q", c.AuthMethod)
	}
	segment := selfHostedLogonPathSegment[method]
	authURL := fmt.Sprintf("%s/PasswordVault/API/Auth/%s/Logon", c.BaseURL, segment)
	payload := map[string]string{
		"username": c.Username,
		"password": c.Password,
	}

	c.Logger.Debugf("Authenticating to %s as user %s (method %s)", c.BaseURL, c.Username, segment)

	// Don't use retry logic for initial auth request to avoid infinite recursion
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest("POST", authURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(c.context(), c.AuthTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("authentication failed with HTTP %d: failed to read error response: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("authentication failed with HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if len(bodyBytes) == 0 {
		return fmt.Errorf("authentication returned empty response")
	}

	c.Logger.Debugf("Auth response length: %d bytes", len(bodyBytes))

	// Try to parse as JSON first
	var token string
	var tokenData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenData); err == nil {
		c.Logger.Debugf("Auth response is JSON with keys: %v", getKeys(tokenData))
		// Extract token from various possible fields
		if t, ok := tokenData["CyberArkLogonResult"].(string); ok {
			token = strings.TrimSpace(t)
			c.Logger.Debug("Token extracted from CyberArkLogonResult field")
		} else if t, ok := tokenData["token"].(string); ok {
			token = strings.TrimSpace(t)
			c.Logger.Debug("Token extracted from token field")
		} else {
			// Use the whole JSON as token (marshaled, not raw)
			compactJSON, _ := json.Marshal(tokenData)
			token = string(compactJSON)
			c.Logger.Debug("Using entire JSON response as token (compacted)")
		}
	} else {
		// Response is plain text token - trim whitespace and quotes
		token = strings.Trim(strings.TrimSpace(string(bodyBytes)), "\"")
		c.Logger.Debugf("Using plain text response as token (trimmed from %d to %d chars)", len(bodyBytes), len(token))
	}

	if token == "" {
		return fmt.Errorf("authentication succeeded but token is empty")
	}

	// The token itself is never logged, not even a prefix: debug logs are
	// routinely shared when troubleshooting.
	c.setToken(token)
	c.Logger.Infof("Authenticated successfully (token length: %d chars)", len(token))
	return nil
}

// reauthIfNeeded performs single-flight re-authentication.  The caller passes
// the tokenGen snapshot it observed *before* getting the 401.  Under the lock
// we check whether another goroutine already refreshed the token; if so, we
// skip the actual auth call and return immediately.
func (c *Client) reauthIfNeeded(callerGen uint64) error {
	c.authMu.Lock()
	defer c.authMu.Unlock()

	// Another goroutine already re-authenticated since our 401.
	if _, gen := c.tokenSnapshot(); gen != callerGen {
		c.Logger.Debugf("Skipping re-auth: token already refreshed (gen %d → %d)", callerGen, gen)
		return nil
	}

	// Authenticate bumps the token generation through setToken.
	return c.Authenticate()
}

// getKeys returns the keys of a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Logoff terminates the session with PVWA. It deliberately does not use the
// client's base context, so the session is still closed after a collection
// was cancelled.
func (c *Client) Logoff() error {
	if token, _ := c.tokenSnapshot(); token == "" {
		return nil
	}

	// Privilege Cloud (Identity / ISPSS) uses short-lived OAuth2 bearer tokens
	// that expire on their own; there is no PVWA session to terminate.
	if c.isIdentityAuth() {
		c.setToken("")
		c.Logger.Debug("Identity (OAuth2) token discarded; no PVWA logoff required")
		return nil
	}

	logoffURL := fmt.Sprintf("%s/PasswordVault/API/Auth/Logoff", c.BaseURL)
	resp, err := c.doWithRetries(context.Background(), "POST", logoffURL, nil, 30*time.Second, 1, 0)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	c.setToken("")
	c.Logger.Info("Logged off successfully")
	return nil
}

// ListSafes retrieves all safes with pagination.
//
// PVWA can fail server-side while building a safes page (HTTP 500 CAWS00001E
// "Error mapping types") or time out on large ones.  Rather than abandoning a
// collection that may already have run for hours, the page size is halved and
// the same offset retried; once a single safe is shown to be the culprit, that
// record is skipped and enumeration continues.  Safes collected so far are
// always returned, even alongside an error, so the caller can decide whether a
// partial result is usable.
func (c *Client) ListSafes(limitCount *int, search *string) ([]models.Safe, error) {
	safes := make([]models.Safe, 0)
	pageLimit := c.SafePageLimit
	if pageLimit <= 0 {
		pageLimit = SafePageLimit
	}
	limit := pageLimit
	offset := 0
	skipped := 0
	consecutiveSkips := 0

	for {
		safeURL := fmt.Sprintf("%s/PasswordVault/API/safes?limit=%d&offset=%d", c.BaseURL, limit, offset)
		if search != nil && *search != "" {
			safeURL += "&search=" + url.QueryEscape(*search)
		}

		c.Logger.Infof("Fetching safes page: offset=%d limit=%d collected=%d", offset, limit, len(safes))
		resp, err := c.requestWithRetries("GET", safeURL, nil, c.ReqTimeout, 3)
		if err != nil {
			if !isRecoverableSafePageError(err) {
				return safes, fmt.Errorf("failed to list safes: %w", err)
			}

			// The page may simply be more than PVWA can build: halve it and
			// retry the same offset.
			if limit > 1 {
				newLimit := lowerSafePageLimit(limit)
				c.Logger.Warnf("ListSafes failed at offset=%d limit=%d (%v), retrying with limit=%d", offset, limit, err, newLimit)
				limit = newLimit
				continue
			}

			// Down to a single safe and still failing: this one record is
			// unreadable server-side. Skip it so the rest are still collected.
			consecutiveSkips++
			if consecutiveSkips > maxConsecutiveSafeSkips {
				return safes, fmt.Errorf("failed to list safes: %d consecutive safes could not be read (last offset=%d): %w", consecutiveSkips, offset, err)
			}
			skipped++
			c.Logger.Warnf("Skipping safe at offset=%d: PVWA cannot return it (%v). It will be missing from the export.", offset, err)
			offset++
			// Stay at a single safe so a run of bad records is skipped one by
			// one; the next page that succeeds restores the working page size.
			continue
		}

		var data struct {
			Value []models.Safe `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return safes, fmt.Errorf("failed to decode safes response: %w", err)
		}
		resp.Body.Close()

		consecutiveSkips = 0
		safes = append(safes, data.Value...)
		c.Logger.Infof("Fetched safes page: offset=%d limit=%d page_count=%d collected=%d", offset, limit, len(data.Value), len(safes))

		if limitCount != nil && len(safes) >= *limitCount {
			safes = safes[:*limitCount]
			break
		}

		if len(data.Value) < limit {
			break
		}

		offset += len(data.Value)

		if limit < pageLimit {
			if limit >= safeIsolationPageLimit {
				// PVWA could not build pages of the configured size here, so
				// keep the smaller one for the rest of the collection.
				pageLimit = limit
			} else {
				// The tiny page was only a probe to isolate a bad record.
				limit = pageLimit
			}
		}
	}

	if skipped > 0 {
		c.Logger.Warnf("Collected %d safes; skipped %d safe(s) PVWA could not return", len(safes), skipped)
		c.noteIncomplete("%d safe(s) could not be returned by PVWA and are missing, along with their members and accounts", skipped)
	} else {
		c.Logger.Infof("Collected %d safes", len(safes))
	}
	return safes, nil
}

// ListSafeMembers retrieves all members of a safe.
//
// The Safe members API leaves out predefined members (Master, Vault Admins,
// Auditors, Backup Users, ...) unless asked for them, yet those are often the
// most privileged principals in the vault. When IncludePredefinedSafeMembers
// is set they are requested with filter=includePredefinedUsers eq true. If
// PVWA rejects that filter (HTTP 400) but accepts the plain request, the
// filter is dropped for the rest of the run and the gap is recorded.
//
// The safe is addressed by its safeUrlId when PVWA supplied a usable one; see
// safePathSegment.
func (c *Client) ListSafeMembers(safeName, safeURLID string) ([]models.SafeMember, error) {
	segment := safePathSegment(safeName, safeURLID)
	includePredefined := c.IncludePredefinedSafeMembers && !c.predefinedFilterRejected.Load()
	members, err := c.listSafeMembers(segment, includePredefined)
	if err == nil || !includePredefined || httpStatus(err) != http.StatusBadRequest {
		return members, err
	}

	plain, plainErr := c.listSafeMembers(segment, false)
	if plainErr != nil {
		// The safe itself is the problem, not the filter.
		return nil, err
	}
	if c.predefinedFilterRejected.CompareAndSwap(false, true) {
		c.Logger.Warnf("PVWA rejected the includePredefinedUsers safe-member filter (%v); continuing without built-in safe members", err)
		c.noteIncomplete("built-in safe members (Master, Vault Admins, Auditors, ...) were not collected: PVWA rejected the includePredefinedUsers filter")
	}
	return plain, nil
}

// safePathSegment returns the path segment that addresses a safe in
// /API/Safes/{segment}/... PVWA's safeUrlId is the safe's ready-made URL
// identifier — CyberArk's own SDK inserts it into the path verbatim — so it is
// used as is whenever it is a valid escaped path segment. That matters for
// names with characters such as '&', which the server encodes differently
// from url.PathEscape. Without a usable safeUrlId (older PVWA versions, or a
// value that is not URL-safe) the safe name is escaped instead.
func safePathSegment(safeName, safeURLID string) string {
	if safeURLID != "" && isEscapedPathSegment(safeURLID) {
		return safeURLID
	}
	return url.PathEscape(safeName)
}

// isEscapedPathSegment reports whether s can be placed in a URL path as a
// single, already-escaped segment.
func isEscapedPathSegment(s string) bool {
	if strings.Contains(s, "/") {
		return false
	}
	unescaped, err := url.PathUnescape(s)
	if err != nil {
		return false
	}
	// EscapedPath returns RawPath only when it is a valid escaping of Path.
	u := url.URL{Path: "/" + unescaped, RawPath: "/" + s}
	return u.EscapedPath() == "/"+s
}

func (c *Client) listSafeMembers(segment string, includePredefined bool) ([]models.SafeMember, error) {
	members := make([]models.SafeMember, 0)
	limit := 1000
	offset := 0

	for {
		memberURL := fmt.Sprintf("%s/PasswordVault/API/Safes/%s/Members?limit=%d&offset=%d",
			c.BaseURL, segment, limit, offset)
		if includePredefined {
			memberURL += "&filter=" + url.QueryEscape("includePredefinedUsers eq true")
		}

		resp, err := c.requestWithRetries("GET", memberURL, nil, c.ReqTimeout, 3)
		if err != nil {
			return nil, fmt.Errorf("failed to list safe members: %w", err)
		}

		var data struct {
			Value []models.SafeMember `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode members response: %w", err)
		}
		resp.Body.Close()

		members = append(members, data.Value...)

		if len(data.Value) < limit {
			break
		}

		offset += limit
	}

	return members, nil
}

// ListAccounts retrieves all accounts in a safe
func (c *Client) ListAccounts(safeName string) ([]models.Account, error) {
	accounts := make([]models.Account, 0)
	limit := 1000
	offset := 0
	totalAPICount := 0
	firstPage := true
	filterValue := fmt.Sprintf("safeName eq %s", safeName)

	for {
		accountURL := fmt.Sprintf("%s/PasswordVault/API/Accounts?limit=%d&offset=%d&filter=%s",
			c.BaseURL, limit, offset, url.QueryEscape(filterValue))

		c.Logger.Debugf("ListAccounts request: %s", accountURL)

		resp, err := c.requestWithRetries("GET", accountURL, nil, c.ReqTimeout, 3)
		if err != nil {
			return nil, fmt.Errorf("failed to list accounts: %w", err)
		}

		var data struct {
			Value []models.Account `json:"value"`
			Count int              `json:"count"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode accounts response: %w", err)
		}
		resp.Body.Close()

		c.Logger.Debugf("ListAccounts response for safe '%s': %d accounts in page, count=%d", safeName, len(data.Value), data.Count)

		if firstPage {
			totalAPICount = data.Count
			firstPage = false
		}

		accounts = append(accounts, data.Value...)

		if len(data.Value) < limit {
			break
		}

		offset += limit
	}

	if totalAPICount > 0 && len(accounts) < totalAPICount {
		c.Logger.Warnf("ListAccounts: API reports count=%d but collected only %d accounts for safe '%s'. Some accounts may be filtered by the server or inaccessible.", totalAPICount, len(accounts), safeName)
	}

	return accounts, nil
}

// GetAccountDetails retrieves detailed information about an account
func (c *Client) GetAccountDetails(accountID string) (*models.Account, error) {
	accountURL := fmt.Sprintf("%s/PasswordVault/API/Accounts/%s", c.BaseURL, accountID)

	resp, err := c.requestWithRetries("GET", accountURL, nil, c.ReqTimeout, 3)
	if err != nil {
		// A 404 means the account no longer exists or is not visible — treat as
		// "not found" rather than a hard failure so it is not counted as an error.
		if httpStatus(err) == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get account details: %w", err)
	}
	defer resp.Body.Close()

	var account models.Account
	if err := json.NewDecoder(resp.Body).Decode(&account); err != nil {
		return nil, fmt.Errorf("failed to decode account details: %w", err)
	}

	return &account, nil
}

// GetAccountActivities retrieves recent activities for an account
func (c *Client) GetAccountActivities(accountID string, limit int, daysBack *int) ([]models.AccountActivity, error) {
	activitiesURL := fmt.Sprintf("%s/PasswordVault/API/Accounts/%s/Activities", c.BaseURL, accountID)

	resp, err := c.requestWithRetries("GET", activitiesURL, nil, c.ReqTimeout, 3)
	if err != nil {
		// 404 or 403 means no activities available
		if status := httpStatus(err); status == 404 || status == 403 {
			c.Logger.Debugf("No activities available for account %s", accountID)
			return []models.AccountActivity{}, nil
		}
		return nil, fmt.Errorf("failed to get account activities: %w", err)
	}
	defer resp.Body.Close()

	var rawResponse struct {
		Activities []models.AccountActivity `json:"Activities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rawResponse); err != nil {
		return nil, fmt.Errorf("failed to decode activities response: %w", err)
	}

	activities := rawResponse.Activities
	c.Logger.Debugf("Account %s: fetched %d activities", accountID, len(activities))

	// Filter by time if daysBack specified
	if daysBack != nil && *daysBack > 0 && len(activities) > 0 {
		cutoffTimestamp := float64(time.Now().Unix()) - float64(*daysBack*86400)
		filtered := make([]models.AccountActivity, 0)

		for _, act := range activities {
			var activityDate float64

			// Handle potentially different types for Date
			switch v := act.Date.(type) {
			case float64:
				activityDate = v
			case int:
				activityDate = float64(v)
			case int64:
				activityDate = float64(v)
			default:
				// If we can't parse the date, include it to be safe
				filtered = append(filtered, act)
				continue
			}

			if activityDate >= cutoffTimestamp {
				filtered = append(filtered, act)
			}
		}

		activities = filtered
		c.Logger.Debugf("Filtered to %d activities within last %d days", len(activities), *daysBack)
	}

	// Apply limit
	if limit > 0 && len(activities) > limit {
		activities = activities[:limit]
	}

	return activities, nil
}

// ListPlatforms retrieves all platforms via GET /API/Platforms/
func (c *Client) ListPlatforms() ([]models.Platform, error) {
	platformURL := fmt.Sprintf("%s/PasswordVault/API/Platforms/", c.BaseURL)

	resp, err := c.requestWithRetries("GET", platformURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list platforms: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Platforms []models.Platform `json:"Platforms"`
		Total     int               `json:"Total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode platforms response: %w", err)
	}

	c.Logger.Infof("Collected %d platforms", len(data.Platforms))
	return data.Platforms, nil
}

// ListUsers retrieves all users
func (c *Client) ListUsers(limitCount *int) ([]models.User, error) {
	usersURL := fmt.Sprintf("%s/PasswordVault/API/Users?ExtendedDetails=true", c.BaseURL)
	extendedDetailsTimeout := c.UserExtendedDetailsTimeout
	if extendedDetailsTimeout <= 0 || extendedDetailsTimeout > c.ReqTimeout {
		extendedDetailsTimeout = c.ReqTimeout
	}

	resp, err := c.requestWithRetriesAndReauth("GET", usersURL, nil, extendedDetailsTimeout, 1, 1)
	if err != nil {
		c.Logger.Warnf("ExtendedDetails failed after %s; falling back to basic list plus per-user enrichment: %v", extendedDetailsTimeout, err)
		usersURL = fmt.Sprintf("%s/PasswordVault/API/Users", c.BaseURL)
		resp, err = c.requestWithRetriesAndReauth("GET", usersURL, nil, c.ReqTimeout, 3, 1)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
		defer resp.Body.Close()

		users, err := decodeUsersResponse(resp.Body)
		if err != nil {
			return nil, err
		}

		if limitCount != nil && *limitCount > 0 && len(users) > *limitCount {
			users = users[:*limitCount]
		}

		users = c.enrichUsersWithDetails(users, extendedDetailsTimeout)
		c.Logger.Infof("Collected %d users", len(users))
		return users, nil
	}
	defer resp.Body.Close()

	users, err := decodeUsersResponse(resp.Body)
	if err != nil {
		return nil, err
	}

	if limitCount != nil && *limitCount > 0 && len(users) > *limitCount {
		users = users[:*limitCount]
	}

	c.Logger.Infof("Collected %d users", len(users))
	return users, nil
}

func decodeUsersResponse(body io.Reader) ([]models.User, error) {
	var data struct {
		Users []models.User `json:"Users"`
		Value []models.User `json:"value"`
	}
	if err := json.NewDecoder(body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	users := data.Users
	if len(users) == 0 {
		users = data.Value
	}
	return users, nil
}

func (c *Client) GetUserDetails(user models.User, timeout time.Duration) (*models.User, error) {
	identifiers := make([]string, 0, 2)
	if id := models.IDString(user.ID); id != "" {
		identifiers = append(identifiers, id)
	}
	if user.Username != "" && user.Username != models.IDString(user.ID) {
		identifiers = append(identifiers, user.Username)
	}
	if len(identifiers) == 0 {
		return nil, fmt.Errorf("user has no id or username")
	}

	var lastErr error
	for _, identifier := range identifiers {
		userURL := fmt.Sprintf("%s/PasswordVault/API/Users/%s", c.BaseURL, url.PathEscape(identifier))
		resp, err := c.requestWithRetriesAndReauth("GET", userURL, nil, timeout, 2, 1)
		if err != nil {
			lastErr = err
			continue
		}

		details, decodeErr := decodeUserDetailResponse(resp.Body)
		resp.Body.Close()
		if decodeErr != nil {
			lastErr = fmt.Errorf("failed to decode user details for %s: %w", identifier, decodeErr)
			continue
		}
		return details, nil
	}

	return nil, lastErr
}

func decodeUserDetailResponse(body io.Reader) (*models.User, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}

	var user models.User
	if err := json.Unmarshal(bodyBytes, &user); err == nil && userHasIdentity(user) {
		return &user, nil
	}

	var wrapped struct {
		User  models.User   `json:"User"`
		Users []models.User `json:"Users"`
		Value []models.User `json:"value"`
	}
	if err := json.Unmarshal(bodyBytes, &wrapped); err != nil {
		return nil, err
	}
	if userHasIdentity(wrapped.User) {
		return &wrapped.User, nil
	}
	if len(wrapped.Users) > 0 {
		return &wrapped.Users[0], nil
	}
	if len(wrapped.Value) > 0 {
		return &wrapped.Value[0], nil
	}

	return nil, fmt.Errorf("user detail response did not contain a user object")
}

func (c *Client) enrichUsersWithDetails(users []models.User, timeout time.Duration) []models.User {
	if len(users) == 0 {
		return users
	}

	concurrency := c.UserEnrichmentWorkers
	if concurrency <= 0 {
		concurrency = 20
	}
	c.Logger.Infof("Enriching %d users individually in parallel...", len(users))

	enrichedUsers := make([]models.User, len(users))
	copy(enrichedUsers, users)
	var failed atomic.Int64

	parallel.ForEach(c.context(), users, concurrency, func(idx int, user models.User) {
		details, err := c.GetUserDetails(user, timeout)
		if err != nil || details == nil {
			failed.Add(1)
			c.Logger.Debugf("Failed to enrich user %s: %v", user.Username, err)
			return
		}
		enrichedUsers[idx] = mergeUserDetails(user, *details)
	})

	if n := failed.Load(); n > 0 {
		c.Logger.Warnf("Failed to enrich %d/%d users individually; keeping basic user data for those users", n, len(users))
		c.noteIncomplete("details could not be fetched for %d of %d users; their group memberships and vault authorizations may be missing", n, len(users))
	}

	return enrichedUsers
}

// GetGroupDetails retrieves detailed information about a group
func (c *Client) GetGroupDetails(groupID string) (*models.Group, error) {
	if groupID == "" {
		return nil, nil
	}

	groupURL := fmt.Sprintf("%s/PasswordVault/API/UserGroups/%s?includeMembers=true", c.BaseURL, url.PathEscape(groupID))

	resp, err := c.requestWithRetries("GET", groupURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get details for group %s: %w", groupID, err)
	}
	defer resp.Body.Close()

	var details models.Group
	if err := json.NewDecoder(resp.Body).Decode(&details); err != nil {
		return nil, fmt.Errorf("failed to decode group details: %w", err)
	}

	return &details, nil
}

// ListGroups retrieves all groups with enriched details
func (c *Client) ListGroups(limitCount *int, concurrency int) ([]models.Group, error) {
	groupsURL := fmt.Sprintf("%s/PasswordVault/API/UserGroups", c.BaseURL)

	resp, err := c.requestWithRetries("GET", groupsURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Value []models.Group `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode groups response: %w", err)
	}

	groups := data.Value

	if limitCount != nil && *limitCount > 0 && len(groups) > *limitCount {
		groups = groups[:*limitCount]
	}

	c.Logger.Infof("Enriching %d groups in parallel...", len(groups))

	enrichedGroups := make([]models.Group, len(groups))
	copy(enrichedGroups, groups)

	if concurrency <= 0 {
		concurrency = 50
	}
	var failed atomic.Int64

	parallel.ForEach(c.context(), groups, concurrency, func(idx int, g models.Group) {
		// ID is interface{} because PVWA returns it as a number or a string.
		groupID := models.IDString(g.ID)
		if groupID == "" {
			groupID = g.GroupName
		}
		if groupID == "" {
			return
		}

		// The detailed object is a superset of the list item, so it replaces it.
		details, err := c.GetGroupDetails(groupID)
		if err != nil {
			failed.Add(1)
			c.Logger.Warnf("%v", err)
			return
		}
		if details != nil {
			enrichedGroups[idx] = *details
		}
	})

	if n := failed.Load(); n > 0 {
		c.noteIncomplete("details could not be fetched for %d of %d groups; their member lists are missing", n, len(groups))
	}

	c.Logger.Infof("Collected %d groups (enriched)", len(enrichedGroups))
	return enrichedGroups, nil
}

// GetPlatformPSMConnectors retrieves PSM connection components for a specific platform
func (c *Client) GetPlatformPSMConnectors(platformID string) ([]models.PSMConnector, error) {
	connURL := fmt.Sprintf("%s/PasswordVault/API/Platforms/Targets/%s/PrivilegedSessionManagement",
		c.BaseURL, url.PathEscape(platformID))

	resp, err := c.requestWithRetries("GET", connURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get PSM connectors for platform %s: %w", platformID, err)
	}
	defer resp.Body.Close()

	var config models.PlatformPSMConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode PSM connectors response for platform %s: %w", platformID, err)
	}

	return config.PSMConnectors, nil
}

// GetAllPlatformPSMConnectors fetches PSM connectors for multiple platforms concurrently.
// Returns a map of platformID -> enabled connector IDs.
func (c *Client) GetAllPlatformPSMConnectors(platformIDs []string, concurrency int) map[string][]string {
	if concurrency <= 0 {
		concurrency = 50
	}

	result := make(map[string][]string)
	var mu sync.Mutex
	var failed atomic.Int64

	parallel.ForEach(c.context(), platformIDs, concurrency, func(_ int, platformID string) {
		connectors, err := c.GetPlatformPSMConnectors(platformID)
		if err != nil {
			failed.Add(1)
			c.Logger.Warnf("Failed to fetch PSM connectors for platform %s: %v", platformID, err)
			return
		}

		var enabled []string
		for _, conn := range connectors {
			if conn.Enabled {
				enabled = append(enabled, conn.PSMConnectorID)
			}
		}

		if len(enabled) > 0 {
			mu.Lock()
			result[platformID] = enabled
			mu.Unlock()
		}
	})

	if n := failed.Load(); n > 0 {
		c.noteIncomplete("PSM connection components could not be fetched for %d of %d platforms", n, len(platformIDs))
	}
	return result
}

// ListTargetPlatforms retrieves platforms via GET /API/Platforms/Targets
// which includes IsAnException metadata for workflow rules.
func (c *Client) ListTargetPlatforms() ([]models.TargetPlatform, error) {
	platformURL := fmt.Sprintf("%s/PasswordVault/API/Platforms/Targets", c.BaseURL)

	resp, err := c.requestWithRetries("GET", platformURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list target platforms: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Platforms []models.TargetPlatform `json:"Platforms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode target platforms response: %w", err)
	}

	c.Logger.Infof("Collected %d target platforms (with exception data)", len(data.Platforms))
	return data.Platforms, nil
}

// ListApplications retrieves all CyberArk Applications (AppIDs) used with the
// Central Credential Provider (CCP) / Credential Provider (CP) via the
// Application Identity Management API:
//
//	GET /PasswordVault/WebServices/PIMServices.svc/Applications/
//
// These AppIDs are the identities the CCP (AIMWebService) authenticates before
// serving credentials from the Vault. Mapping them — together with their safe
// memberships and authentication restrictions — exposes the "shortest path" to
// privileged accounts described by Marat Nigmatullin (FalconForce) in his
// SO-CON 2026 talk "4 GET requests = 3 Domain admins".
func (c *Client) ListApplications() ([]models.Application, error) {
	appsURL := fmt.Sprintf("%s/PasswordVault/WebServices/PIMServices.svc/Applications/", c.BaseURL)

	resp, err := c.requestWithRetries("GET", appsURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list applications: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		Application []models.Application `json:"application"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode applications response: %w", err)
	}

	c.Logger.Infof("Collected %d applications", len(data.Application))
	return data.Application, nil
}

// GetApplicationAuthentications retrieves the authentication methods / restrictions
// configured on a single Application via:
//
//	GET /PasswordVault/WebServices/PIMServices.svc/Applications/{AppID}/Authentications/
//
// The returned entries determine whether the AppID is restricted (Allowed
// Machines, OS user, path, hash, certificate) or effectively unauthenticated.
func (c *Client) GetApplicationAuthentications(appID string) ([]models.ApplicationAuthentication, error) {
	authURL := fmt.Sprintf("%s/PasswordVault/WebServices/PIMServices.svc/Applications/%s/Authentications/",
		c.BaseURL, url.PathEscape(appID))

	resp, err := c.requestWithRetries("GET", authURL, nil, c.ReqTimeout, 3)
	if err != nil {
		// 404 means the application has no authentication methods defined
		if httpStatus(err) == 404 {
			return []models.ApplicationAuthentication{}, nil
		}
		return nil, fmt.Errorf("failed to get authentications for application %s: %w", appID, err)
	}
	defer resp.Body.Close()

	var data struct {
		Authentication []models.ApplicationAuthentication `json:"authentication"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode authentications response for application %s: %w", appID, err)
	}

	return data.Authentication, nil
}

// ListApplicationsWithAuth fetches all applications and concurrently enriches each
// with its authentication methods / restrictions. Failures to enrich an individual
// application are logged and that application is kept with AuthenticationsUnknown
// set, so it is not mistaken for an application with no restrictions.
func (c *Client) ListApplicationsWithAuth(concurrency int) ([]models.Application, error) {
	apps, err := c.ListApplications()
	if err != nil {
		return nil, err
	}
	if len(apps) == 0 {
		return apps, nil
	}

	if concurrency <= 0 {
		concurrency = 50
	}
	c.Logger.Infof("Enriching %d applications with authentication restrictions...", len(apps))

	var failed atomic.Int64

	// Every application counts as unknown until its restrictions are read,
	// so one left unchecked by an interrupted collection is not mistaken for
	// one without restrictions. Each worker writes only apps[idx].
	for i := range apps {
		apps[i].AuthenticationsUnknown = true
	}
	parallel.ForEach(c.context(), apps, concurrency, func(idx int, app models.Application) {
		if app.AppID == "" {
			return
		}
		auths, err := c.GetApplicationAuthentications(app.AppID)
		if err != nil {
			if c.context().Err() == nil {
				failed.Add(1)
				c.Logger.Warnf("Failed to fetch authentications for application %s: %v", app.AppID, err)
			}
			return
		}
		apps[idx].Authentications = auths
		apps[idx].AuthenticationsUnknown = false
	})

	if n := failed.Load(); n > 0 {
		c.noteIncomplete("authentication restrictions could not be fetched for %d of %d applications; they are not assessed as restricted or unrestricted", n, len(apps))
	}
	return apps, nil
}

// ListPSMServers retrieves all PSM servers via GET /API/PSM/Servers/
func (c *Client) ListPSMServers() ([]models.PSMServer, error) {
	serversURL := fmt.Sprintf("%s/PasswordVault/API/PSM/Servers/", c.BaseURL)

	resp, err := c.requestWithRetries("GET", serversURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list PSM servers: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		PSMServers []models.PSMServer `json:"PSMServers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode PSM servers response: %w", err)
	}

	c.Logger.Infof("Collected %d PSM servers", len(data.PSMServers))
	return data.PSMServers, nil
}

// ListConnectionComponents retrieves all connection components via GET /API/PSM/Connectors/
func (c *Client) ListConnectionComponents() ([]models.ConnectionComponent, error) {
	connectorsURL := fmt.Sprintf("%s/PasswordVault/API/PSM/Connectors/", c.BaseURL)

	resp, err := c.requestWithRetries("GET", connectorsURL, nil, c.ReqTimeout, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to list connection components: %w", err)
	}
	defer resp.Body.Close()

	var data struct {
		PSMConnectors []models.ConnectionComponent `json:"PSMConnectors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode connection components response: %w", err)
	}

	c.Logger.Infof("Collected %d connection components", len(data.PSMConnectors))
	return data.PSMConnectors, nil
}
