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
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

const (
	// SafePageLimit is the maximum number of safes to retrieve per page
	SafePageLimit = 1000
)

// Client encapsulates CyberArk PVWA REST API interactions
type Client struct {
	BaseURL             string
	Username            string
	Password            string
	AuthTimeout         time.Duration
	ReqTimeout          time.Duration
	SafePageLimit       int
	Token               string
	HTTPClient          *http.Client
	Logger              *logrus.Logger
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
	RetryMultiplier     float64
	RetryJitter         float64
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

	return &Client{
		BaseURL:  baseURL,
		Username: username,
		Password: password,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   360 * time.Second,
		},
		Logger:              logger,
		AuthTimeout:         360 * time.Second,
		ReqTimeout:          360 * time.Second,
		SafePageLimit:       SafePageLimit,
		RetryInitialBackoff: 1 * time.Second,
		RetryMaxBackoff:     60 * time.Second,
		RetryMultiplier:     2.0,
		RetryJitter:         0.2,
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
	attempt := 0
	backoff := c.RetryInitialBackoff
	reauthAttempts := 0
	maxReauthAttempts := 2

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
		if c.Token != "" {
			req.Header.Set("Authorization", c.Token)
		}

		// Don't set per-request context timeout - use HTTP client's timeout instead
		// to avoid context cancellation issues
		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			c.Logger.Warnf("Request error attempt %d for %s: %v", attempt, urlPath, err)
			if maxRetries > 0 && attempt >= maxRetries {
				return nil, fmt.Errorf("max retries reached: %w", err)
			}

			// Wait but don't increase backoff duration
			c.throttleVariableDuration(backoff)
			continue
		}

		// Handle HTTP status codes
		if resp.StatusCode == 401 {
			resp.Body.Close()
			reauthAttempts++
			if reauthAttempts > maxReauthAttempts {
				return nil, fmt.Errorf("authentication retries exhausted for %s (attempted %d times)", urlPath, reauthAttempts)
			}
			c.Logger.Warnf("HTTP 401 received for %s. Re-authenticating (re-auth attempt %d/%d)...", urlPath, reauthAttempts, maxReauthAttempts)
			if err := c.Authenticate(); err != nil {
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
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}

		if attempt > 1 {
			c.Logger.Infof("Request succeeded on attempt %d: %s", attempt, urlPath)
		}

		return resp, nil
	}
}

// Authenticate logs into the CyberArk PVWA API
func (c *Client) Authenticate() error {
	authURL := fmt.Sprintf("%s/PasswordVault/API/Auth/CyberArk/Logon", c.BaseURL)
	payload := map[string]string{
		"username": c.Username,
		"password": c.Password,
	}

	c.Logger.Debugf("Authenticating to %s as user %s", c.BaseURL, c.Username)

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

		resp, err := c.requestWithRetries("GET", safeURL, nil, c.ReqTimeout, 3)
		if err != nil {
			// PVWA can be very slow to build large pages of safes; if we timed out,
			// automatically reduce the page size and retry the same offset.
			if (errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout exceeded")) && limit > 50 {
				newLimit := limit / 2
				if newLimit < 50 {
					newLimit = 50
				}
				if newLimit != limit {
					c.Logger.Warnf("ListSafes timed out at offset=%d limit=%d, retrying with limit=%d", offset, limit, newLimit)
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
		// Check for 404
		if resp != nil && resp.StatusCode == 404 {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get account details: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, nil
	}

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
		if resp != nil && (resp.StatusCode == 404 || resp.StatusCode == 403) {
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

// ListPlatforms retrieves all target platforms
func (c *Client) ListPlatforms() ([]models.Platform, error) {
	platforms := make([]models.Platform, 0)
	limit := 500
	offset := 0

	for {
		platformURL := fmt.Sprintf("%s/PasswordVault/API/Platforms/Targets?limit=%d&offset=%d",
			c.BaseURL, limit, offset)

		resp, err := c.requestWithRetries("GET", platformURL, nil, c.ReqTimeout, 3)
		if err != nil {
			return nil, fmt.Errorf("failed to list platforms: %w", err)
		}

		var data struct {
			Platforms []models.Platform `json:"Platforms"`
			Value     []models.Platform `json:"value"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to decode platforms response: %w", err)
		}
		resp.Body.Close()

		page := data.Platforms
		if len(page) == 0 {
			page = data.Value
		}
		platforms = append(platforms, page...)

		if len(page) < limit {
			break
		}
		offset += len(page)
	}

	c.Logger.Infof("Collected %d platforms", len(platforms))
	return platforms, nil
}

// ListUsers retrieves all users
func (c *Client) ListUsers(limitCount *int) ([]models.User, error) {
	usersURL := fmt.Sprintf("%s/PasswordVault/API/Users?ExtendedDetails=true", c.BaseURL)

	resp, err := c.requestWithRetries("GET", usersURL, nil, c.ReqTimeout, 3)
	if err != nil {
		c.Logger.Warn("ExtendedDetails failed; falling back to basic list")
		usersURL = fmt.Sprintf("%s/PasswordVault/API/Users", c.BaseURL)
		resp, err = c.requestWithRetries("GET", usersURL, nil, c.ReqTimeout, 3)
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}
	}
	defer resp.Body.Close()

	var data struct {
		Users []models.User `json:"Users"`
		Value []models.User `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode users response: %w", err)
	}

	users := data.Users
	if len(users) == 0 {
		users = data.Value
	}

	if limitCount != nil && *limitCount > 0 && len(users) > *limitCount {
		users = users[:*limitCount]
	}

	c.Logger.Infof("Collected %d users", len(users))
	return users, nil
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
