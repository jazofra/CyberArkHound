// Package client provides authentication strategies for CyberArk PVWA.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cyberark/ark-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/ark-sdk-golang/pkg/models/auth"
	"github.com/sirupsen/logrus"
)

// Authenticator defines the interface for authentication strategies.
type Authenticator interface {
	// Authenticate performs authentication and returns error if failed.
	Authenticate() error
	// GetToken returns the current authentication token.
	GetToken() string
	// GetBaseURL returns the PVWA base URL for API calls.
	GetBaseURL() string
	// IsISPSS returns true if this is an ISPSS authenticator (affects header format).
	IsISPSS() bool
	// Logoff terminates the session.
	Logoff() error
}

// CyberArkAuthenticator implements on-premise CyberArk PAM authentication.
type CyberArkAuthenticator struct {
	BaseURL     string
	Username    string
	Password    string
	Token       string
	Logger      *logrus.Logger
	HTTPClient  *http.Client
	AuthTimeout time.Duration
}

// NewCyberArkAuthenticator creates a new on-premise authenticator.
func NewCyberArkAuthenticator(baseURL, username, password string, httpClient *http.Client, authTimeout time.Duration, logger *logrus.Logger) *CyberArkAuthenticator {
	return &CyberArkAuthenticator{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		Username:    username,
		Password:    password,
		Logger:      logger,
		HTTPClient:  httpClient,
		AuthTimeout: authTimeout,
	}
}

// Authenticate performs on-premise CyberArk authentication.
func (a *CyberArkAuthenticator) Authenticate() error {
	authURL := fmt.Sprintf("%s/PasswordVault/API/Auth/CyberArk/Logon", a.BaseURL)
	payload := map[string]string{
		"username": a.Username,
		"password": a.Password,
	}

	a.Logger.Debugf("Authenticating to %s as user %s", a.BaseURL, a.Username)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest("POST", authURL, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	ctx, cancel := context.WithTimeout(context.Background(), a.AuthTimeout)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if len(bodyBytes) == 0 {
		return fmt.Errorf("authentication returned empty response")
	}

	// Parse token from response
	var tokenData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &tokenData); err == nil {
		if token, ok := tokenData["CyberArkLogonResult"].(string); ok {
			a.Token = strings.TrimSpace(token)
		} else if token, ok := tokenData["token"].(string); ok {
			a.Token = strings.TrimSpace(token)
		} else {
			compactJSON, _ := json.Marshal(tokenData)
			a.Token = string(compactJSON)
		}
	} else {
		a.Token = strings.Trim(strings.TrimSpace(string(bodyBytes)), "\"")
	}

	if a.Token == "" {
		return fmt.Errorf("authentication succeeded but token is empty")
	}

	a.Logger.Infof("Authenticated successfully (token length: %d chars)", len(a.Token))
	return nil
}

// GetToken returns the current token.
func (a *CyberArkAuthenticator) GetToken() string {
	return a.Token
}

// GetBaseURL returns the PVWA base URL.
func (a *CyberArkAuthenticator) GetBaseURL() string {
	return a.BaseURL
}

// IsISPSS returns false for on-premise authentication.
func (a *CyberArkAuthenticator) IsISPSS() bool {
	return false
}

// Logoff terminates the on-premise session.
func (a *CyberArkAuthenticator) Logoff() error {
	if a.Token == "" {
		return nil
	}

	logoffURL := fmt.Sprintf("%s/PasswordVault/API/Auth/Logoff", a.BaseURL)
	req, err := http.NewRequest("POST", logoffURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logoff request: %w", err)
	}
	req.Header.Set("Authorization", a.Token)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		a.Logger.Warnf("Logoff request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	a.Token = ""
	a.Logger.Info("Logged off successfully")
	return nil
}

// ISPSSAuthenticator implements ISPSS (Privilege Cloud) authentication via ARK SDK.
type ISPSSAuthenticator struct {
	Username    string
	Password    string
	IdentityURL string // Optional override for GovCloud/custom
	Token       string
	PVWAURL     string // Auto-discovered
	Logger      *logrus.Logger
	ispAuth     auth.ArkAuth
}

// NewISPSSAuthenticator creates a new ISPSS authenticator.
func NewISPSSAuthenticator(username, password, identityURL string, logger *logrus.Logger) *ISPSSAuthenticator {
	return &ISPSSAuthenticator{
		Username:    username,
		Password:    password,
		IdentityURL: identityURL,
		Logger:      logger,
	}
}

// Authenticate performs ISPSS authentication using the ARK SDK.
func (a *ISPSSAuthenticator) Authenticate() error {
	a.ispAuth = auth.NewArkISPAuth(false) // No caching - in-memory only

	// Build auth method settings
	settings := &authmodels.IdentityServiceUserArkAuthMethodSettings{}
	if a.IdentityURL != "" {
		settings.IdentityURL = a.IdentityURL
	}

	a.Logger.Debugf("Authenticating to ISPSS as user %s", a.Username)

	// Authenticate using Identity Service User method
	token, err := a.ispAuth.Authenticate(
		nil, // No profile storage
		&authmodels.ArkAuthProfile{
			Username:           a.Username,
			AuthMethod:         authmodels.IdentityServiceUser,
			AuthMethodSettings: settings,
		},
		&authmodels.ArkSecret{
			Secret: a.Password,
		},
		true,  // Force fresh token
		false, // Don't use keyring cache
	)
	if err != nil {
		return fmt.Errorf("ISPSS authentication failed: %w", err)
	}

	// Store JWT token
	a.Token = token.Token

	// Extract tenant subdomain from Identity endpoint
	// e.g., "https://abc123.id.cyberark.cloud" -> "abc123"
	tenantSubdomain, err := extractTenantSubdomain(token.Endpoint)
	if err != nil {
		return fmt.Errorf("failed to extract tenant subdomain from endpoint '%s': %w", token.Endpoint, err)
	}

	// Construct PVWA URL
	a.PVWAURL = fmt.Sprintf("https://%s.privilegecloud.cyberark.cloud", tenantSubdomain)

	a.Logger.Infof("ISPSS authentication successful")
	a.Logger.Infof("Identity endpoint: %s", token.Endpoint)
	a.Logger.Infof("PVWA URL (auto-discovered): %s", a.PVWAURL)

	return nil
}

// GetToken returns the current JWT token.
func (a *ISPSSAuthenticator) GetToken() string {
	return a.Token
}

// GetBaseURL returns the auto-discovered PVWA URL.
func (a *ISPSSAuthenticator) GetBaseURL() string {
	return a.PVWAURL
}

// IsISPSS returns true for ISPSS authentication.
func (a *ISPSSAuthenticator) IsISPSS() bool {
	return true
}

// Logoff clears the token (ISPSS doesn't require explicit logoff).
func (a *ISPSSAuthenticator) Logoff() error {
	a.Token = ""
	a.Logger.Info("ISPSS session cleared")
	return nil
}

// extractTenantSubdomain extracts the subdomain from an Identity URL.
// "https://abc123.id.cyberark.cloud" -> "abc123"
func extractTenantSubdomain(identityURL string) (string, error) {
	if identityURL == "" {
		return "", fmt.Errorf("identity URL is empty")
	}

	parsed, err := url.Parse(identityURL)
	if err != nil {
		return "", fmt.Errorf("invalid identity URL: %w", err)
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("no hostname in identity URL")
	}

	parts := strings.Split(host, ".")
	if len(parts) < 1 || parts[0] == "" {
		return "", fmt.Errorf("cannot extract subdomain from hostname: %s", host)
	}

	return parts[0], nil
}
