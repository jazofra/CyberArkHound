// Package client provides a CyberArk PVWA REST API client with authentication,
// retry logic, and methods for fetching users, groups, safes, and accounts.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	// SafePageLimit is the default number of safes to retrieve per page.
	SafePageLimit = 100
	// UserExtendedDetailsTimeout is the default timeout for the optional user
	// enrichment endpoint before falling back to the basic user list.
	UserExtendedDetailsTimeout = 60 * time.Second

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
	Token                      string
	HTTPClient                 *http.Client
	Logger                     *logrus.Logger
	RetryInitialBackoff        time.Duration
	RetryMaxBackoff            time.Duration
	RetryMultiplier            float64
	RetryJitter                float64
	MaxReauthAttempts          int

	// authMu serialises re-authentication so only one goroutine re-auths at a time.
	authMu sync.Mutex
	// tokenGen is bumped on every successful Authenticate(); workers compare
	// their snapshot to decide whether someone else already refreshed the token.
	tokenGen uint64
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

// NewClient creates a new CyberArk API client
func NewClient(baseURL, username, password string, insecure bool, caBundle string, logger *logrus.Logger) *Client {
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

	return &Client{
		BaseURL:    baseURL,
		Username:   username,
		Password:   password,
		AuthMethod: AuthMethodCyberArk,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   360 * time.Second,
			Jar:       jar,
		},
		Logger:                     logger,
		AuthTimeout:                360 * time.Second,
		ReqTimeout:                 360 * time.Second,
		UserExtendedDetailsTimeout: UserExtendedDetailsTimeout,
		UserEnrichmentWorkers:      20,
		SafePageLimit:              SafePageLimit,
		RetryInitialBackoff:        1 * time.Second,
		RetryMaxBackoff:            60 * time.Second,
		RetryMultiplier:            2.0,
		RetryJitter:                0.2,
		MaxReauthAttempts:          5,
	}
}

func (c *Client) throttleVariableDuration(backoff time.Duration) {
	jitter := 1.0 + (rand.Float64()*2-1)*c.RetryJitter
	sleepTime := time.Duration(math.Min(float64(backoff)*jitter, float64(c.RetryMaxBackoff)))
	c.Logger.Debugf("Sleeping %.2fs before retry.", sleepTime.Seconds())
	time.Sleep(sleepTime)
}

// requestWithRetries executes HTTP request with retry logic
func (c *Client) requestWithRetries(method, urlPath string, body interface{}, timeout time.Duration, maxRetries int) (*http.Response, error) {
	return c.requestWithRetriesAndReauth(method, urlPath, body, timeout, maxRetries, c.MaxReauthAttempts)
}

func (c *Client) requestWithRetriesAndReauth(method, urlPath string, body interface{}, timeout time.Duration, maxRetries int, maxReauthAttempts int) (*http.Response, error) {
	attempt := 0
	backoff := c.RetryInitialBackoff
	reauthAttempts := 0

	// Pre-marshal body once to avoid re-marshaling on each retry
	var jsonData []byte
	if body != nil {
		var err error
		jsonData, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	for {
		attempt++
		c.Logger.Debugf("Request attempt %d: %s %s", attempt, method, urlPath)

		// Snapshot the current token generation before issuing the request.
		// If we get a 401, we pass this to reauthIfNeeded so it can tell
		// whether another goroutine already refreshed the token.
		preReqGen := c.tokenGen

		var bodyReader io.Reader
		if jsonData != nil {
			bodyReader = bytes.NewReader(jsonData)
		}

		req, err := http.NewRequest(method, urlPath, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		if jsonData != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if header := c.authorizationHeaderValue(); header != "" {
			req.Header.Set("Authorization", header)
		}

		var cancel context.CancelFunc
		if timeout > 0 {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			cancel = cancelFunc
			req = req.WithContext(ctx)
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			c.Logger.Warnf("Request error attempt %d for %s: %v", attempt, urlPath, err)
			if maxRetries > 0 && attempt >= maxRetries {
				return nil, fmt.Errorf("max retries reached: %w", err)
			}

			// Wait but don't increase backoff duration
			c.throttleVariableDuration(backoff)
			continue
		}
		if cancel != nil {
			resp.Body = &cancelOnCloseReadCloser{ReadCloser: resp.Body, cancel: cancel}
		}

		// Handle HTTP status codes
		if resp.StatusCode == 401 {
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
			c.throttleVariableDuration(backoff)
			continue
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()

			c.throttleVariableDuration(backoff)
			backoff = time.Duration(math.Min(float64(backoff)*c.RetryMultiplier, float64(c.RetryMaxBackoff)))

			// Don't count HTTP 429 Too Many Requests against main retry counter
			attempt--
			continue
		}

		if resp.StatusCode >= 400 {
			bodyBytes, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, fmt.Errorf("HTTP %d: failed to read error response: %w", resp.StatusCode, readErr)
			}
			return nil, &HTTPError{StatusCode: resp.StatusCode, Body: string(bodyBytes)}
		}

		// Guard against PVWA returning HTML (e.g. IIS login/error page) on
		// an otherwise successful HTTP 200.  Every valid PVWA API response is
		// JSON, so a non-JSON Content-Type is treated as a transient error
		// and retried.
		ct := resp.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, "application/json") && !strings.Contains(ct, "text/json") {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			preview := string(bodyBytes)
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			c.Logger.Warnf("Non-JSON response (Content-Type: %s) for %s: %s", ct, urlPath, preview)
			if maxRetries > 0 && attempt >= maxRetries {
				return nil, fmt.Errorf("non-JSON response for %s (Content-Type: %s)", urlPath, ct)
			}
			c.throttleVariableDuration(backoff)
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

func lowerSafePageLimit(limit int) int {
	if limit <= 50 {
		return limit
	}
	newLimit := limit / 2
	if newLimit < 50 {
		newLimit = 50
	}
	return newLimit
}

func userIDString(id interface{}) string {
	switch v := id.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
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
	return user.Username != "" || userIDString(user.ID) != ""
}

// isIdentityAuth reports whether the client uses CyberArk Identity (ISPSS)
// OAuth2 authentication (Privilege Cloud / SaaS).
func (c *Client) isIdentityAuth() bool {
	method, _ := NormalizeAuthMethod(c.AuthMethod)
	return method == AuthMethodIdentity
}

// authorizationHeaderValue returns the value to set on the Authorization header.
// Identity (OAuth2) tokens are bearer tokens and must be prefixed with "Bearer ";
// self-hosted PVWA session tokens are sent verbatim.
func (c *Client) authorizationHeaderValue() string {
	if c.Token == "" {
		return ""
	}
	if c.isIdentityAuth() {
		return "Bearer " + c.Token
	}
	return c.Token
}

// Authenticate obtains a session token from CyberArk. For self-hosted PVWA it
// uses the /API/Auth/{method}/Logon endpoint; for Privilege Cloud (SaaS) it uses
// the CyberArk Identity (ISPSS) OAuth2 client-credentials flow.
func (c *Client) Authenticate() error {
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
		c.Token = token
		c.Logger.Infof("Authenticated to CyberArk Identity via OAuth2 client_credentials (token length: %d chars)", len(c.Token))
		return nil
	}
	c.Logger.Debugf("OAuth2 client_credentials grant not accepted (%v); falling back to CyberArk Identity username/password authentication", ccErr)

	// 2. Interactive username/password — StartAuthentication → AdvanceAuthentication.
	token, err := c.identityInteractiveToken()
	if err != nil {
		return fmt.Errorf("CyberArk Identity authentication failed (OAuth2 client_credentials grant rejected: %v): %w", ccErr, err)
	}
	c.Token = token
	c.Logger.Infof("Authenticated to CyberArk Identity via username/password (token length: %d chars)", len(c.Token))
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

	ctx, cancel := context.WithTimeout(context.Background(), c.AuthTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), c.AuthTimeout)
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

	ctx, cancel := context.WithTimeout(context.Background(), c.AuthTimeout)
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
	var tokenData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenData); err == nil {
		c.Logger.Debugf("Auth response is JSON with keys: %v", getKeys(tokenData))
		// Extract token from various possible fields
		if token, ok := tokenData["CyberArkLogonResult"].(string); ok {
			c.Token = strings.TrimSpace(token)
			c.Logger.Debug("Token extracted from CyberArkLogonResult field")
		} else if token, ok := tokenData["token"].(string); ok {
			c.Token = strings.TrimSpace(token)
			c.Logger.Debug("Token extracted from token field")
		} else {
			// Use the whole JSON as token (marshaled, not raw)
			compactJSON, _ := json.Marshal(tokenData)
			c.Token = string(compactJSON)
			c.Logger.Debug("Using entire JSON response as token (compacted)")
		}
	} else {
		// Response is plain text token - trim whitespace and quotes
		c.Token = strings.Trim(strings.TrimSpace(string(bodyBytes)), "\"")
		c.Logger.Debugf("Using plain text response as token (trimmed from %d to %d chars)", len(bodyBytes), len(c.Token))
	}

	if c.Token == "" {
		return fmt.Errorf("authentication succeeded but token is empty")
	}

	c.Logger.Infof("Authenticated successfully (token length: %d chars)", len(c.Token))
	c.Logger.Debugf("Token preview: %s...", truncateString(c.Token, 50))
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
	if c.tokenGen != callerGen {
		c.Logger.Debugf("Skipping re-auth: token already refreshed (gen %d → %d)", callerGen, c.tokenGen)
		return nil
	}

	if err := c.Authenticate(); err != nil {
		return err
	}
	c.tokenGen++
	return nil
}

// getKeys returns the keys of a map for debugging
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// truncateString truncates a string to maxLen characters
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// Logoff terminates the session with PVWA
func (c *Client) Logoff() error {
	if c.Token == "" {
		return nil
	}

	// Privilege Cloud (Identity / ISPSS) uses short-lived OAuth2 bearer tokens
	// that expire on their own; there is no PVWA session to terminate.
	if c.isIdentityAuth() {
		c.Token = ""
		c.Logger.Debug("Identity (OAuth2) token discarded; no PVWA logoff required")
		return nil
	}

	logoffURL := fmt.Sprintf("%s/PasswordVault/API/Auth/Logoff", c.BaseURL)
	resp, err := c.requestWithRetries("POST", logoffURL, nil, 30*time.Second, 1)
	if err != nil {
		c.Logger.Warnf("Logoff failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	c.Token = ""
	c.Logger.Info("Logged off successfully")
	return nil
}

// ListSafes retrieves all safes with pagination
func (c *Client) ListSafes(limitCount *int, search *string) ([]models.Safe, error) {
	safes := make([]models.Safe, 0)
	limit := c.SafePageLimit
	if limit <= 0 {
		limit = SafePageLimit
	}
	offset := 0

	for {
		safeURL := fmt.Sprintf("%s/PasswordVault/API/safes?limit=%d&offset=%d", c.BaseURL, limit, offset)
		if search != nil && *search != "" {
			safeURL += "&search=" + url.QueryEscape(*search)
		}

		c.Logger.Infof("Fetching safes page: offset=%d limit=%d collected=%d", offset, limit, len(safes))
		resp, err := c.requestWithRetries("GET", safeURL, nil, c.ReqTimeout, 3)
		if err != nil {
			// PVWA can be slow or fail server-side when building large safe pages.
			// Reduce the page size and retry the same offset for those known cases.
			if (isTimeoutError(err) || isPVWASafePageServerError(err)) && limit > 50 {
				newLimit := lowerSafePageLimit(limit)
				if newLimit != limit {
					c.Logger.Warnf("ListSafes failed at offset=%d limit=%d (%v), retrying with limit=%d", offset, limit, err, newLimit)
					limit = newLimit
					continue
				}
			}
			return nil, fmt.Errorf("failed to list safes: %w", err)
		}

		var data struct {
			Value []models.Safe `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode safes response: %w", err)
		}
		resp.Body.Close()

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
	}

	c.Logger.Infof("Collected %d safes", len(safes))
	return safes, nil
}

// ListSafeMembers retrieves all members of a safe
func (c *Client) ListSafeMembers(safeName, safeURLID string) ([]models.SafeMember, error) {
	members := make([]models.SafeMember, 0)
	limit := 1000
	offset := 0
	safeNameEncoded := url.PathEscape(safeName)

	for {
		memberURL := fmt.Sprintf("%s/PasswordVault/API/Safes/%s/Members?limit=%d&offset=%d",
			c.BaseURL, safeNameEncoded, limit, offset)

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
func (c *Client) ListAccounts(safeName, safeURLID string) ([]models.Account, error) {
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
		c.Logger.Warnf("Failed to get activities for account %s: %v", accountID, err)
		return []models.AccountActivity{}, nil
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
	if id := userIDString(user.ID); id != "" {
		identifiers = append(identifiers, id)
	}
	if user.Username != "" && user.Username != userIDString(user.ID) {
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
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0

	for idx := range enrichedUsers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			details, err := c.GetUserDetails(enrichedUsers[idx], timeout)
			if err != nil || details == nil {
				mu.Lock()
				failed++
				mu.Unlock()
				c.Logger.Debugf("Failed to enrich user %s: %v", enrichedUsers[idx].Username, err)
				return
			}

			enrichedUsers[idx] = mergeUserDetails(enrichedUsers[idx], *details)
		}(idx)
	}

	wg.Wait()
	if failed > 0 {
		c.Logger.Warnf("Failed to enrich %d/%d users individually; keeping basic user data for those users", failed, len(users))
	}

	return enrichedUsers
}

// GetGroupDetails retrieves detailed information about a group
func (c *Client) GetGroupDetails(groupID string) (*models.Group, error) {
	if groupID == "" {
		return nil, nil
	}

	groupURL := fmt.Sprintf("%s/PasswordVault/API/UserGroups/%s?includeMembers=true", c.BaseURL, groupID)

	resp, err := c.requestWithRetries("GET", groupURL, nil, c.ReqTimeout, 3)
	if err != nil {
		c.Logger.Warnf("Failed to get details for group %s: %v", groupID, err)
		return nil, nil
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

	// Parallel enrichment
	// Create a buffered channel for results
	enrichedGroups := make([]models.Group, len(groups))
	copy(enrichedGroups, groups)

	// Create a semaphore to limit concurrency
	if concurrency <= 0 {
		concurrency = 50
	}
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range enrichedGroups {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire
			defer func() { <-semaphore }() // Release

			g := &enrichedGroups[idx]
			groupID := ""

			// Try to get ID as string first
			// ID in models.Group is interface{} because it can be int or string in JSON
			if idStr, ok := g.ID.(string); ok {
				groupID = idStr
			} else if idFloat, ok := g.ID.(float64); ok {
				groupID = fmt.Sprintf("%.0f", idFloat)
			} else if idInt, ok := g.ID.(int); ok {
				groupID = fmt.Sprintf("%d", idInt)
			} else if g.GroupName != "" {
				// Fall back to groupName if id is not available
				groupID = g.GroupName
			}

			if groupID != "" {
				details, err := c.GetGroupDetails(groupID)
				if err == nil && details != nil {
					// Merge details into group
					// We just overwrite the struct with the detailed version,
					// assuming GetGroupDetails returns a superset or complete object.
					// Note: attributes from 'g' (the list item) should be present in 'details'
					enrichedGroups[idx] = *details
				}
			}
		}(i)
	}

	wg.Wait()

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
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, pid := range platformIDs {
		wg.Add(1)
		go func(platformID string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			connectors, err := c.GetPlatformPSMConnectors(platformID)
			if err != nil {
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
		}(pid)
	}

	wg.Wait()
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
// application are logged and that application is kept without authentication data.
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

	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i := range apps {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if apps[idx].AppID == "" {
				return
			}
			auths, err := c.GetApplicationAuthentications(apps[idx].AppID)
			if err != nil {
				c.Logger.Warnf("Failed to fetch authentications for application %s: %v", apps[idx].AppID, err)
				return
			}
			apps[idx].Authentications = auths
		}(i)
	}

	wg.Wait()
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
