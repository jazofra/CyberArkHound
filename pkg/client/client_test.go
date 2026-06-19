package client

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func testClient(baseURL string) *Client {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	client := NewClient(baseURL, "user", "pass", true, "", logger)
	client.ReqTimeout = time.Second
	client.HTTPClient.Timeout = time.Second
	client.RetryInitialBackoff = time.Millisecond
	client.RetryMaxBackoff = time.Millisecond
	client.RetryJitter = 0
	return client
}

func TestListSafesReducesPageLimitOnPVWAMappingError(t *testing.T) {
	var requestedLimits []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/PasswordVault/API/safes" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
		if err != nil {
			t.Fatalf("invalid limit: %v", err)
		}
		requestedLimits = append(requestedLimits, limit)

		w.Header().Set("Content-Type", "application/json")
		if limit > 50 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00001E","ErrorMessage":"Error mapping types. IReadOnlyCollection` + "`" + `1 -> List` + "`" + `1"}`))
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"value": []map[string]string{{"safeName": "SafeA", "safeUrlId": "SafeA"}},
		})
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.SafePageLimit = 200

	safes, err := client.ListSafes(nil, nil)
	if err != nil {
		t.Fatalf("ListSafes returned error: %v", err)
	}
	if len(safes) != 1 || safes[0].SafeName != "SafeA" {
		t.Fatalf("unexpected safes: %+v", safes)
	}

	wantLimits := []int{200, 100, 50}
	if !reflect.DeepEqual(requestedLimits, wantLimits) {
		t.Fatalf("requested limits = %v, want %v", requestedLimits, wantLimits)
	}
}

func TestListUsersFallsBackWhenExtendedDetailsTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("ExtendedDetails") == "true" {
			<-r.Context().Done()
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Users": []map[string]string{{"username": "basic-user"}},
		})
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.UserExtendedDetailsTimeout = 10 * time.Millisecond

	users, err := client.ListUsers(nil)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 1 || users[0].Username != "basic-user" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestListUsersEnrichesIndividuallyWhenBulkExtendedDetailsTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/PasswordVault/API/Users":
			if r.URL.Query().Get("ExtendedDetails") == "true" {
				<-r.Context().Done()
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Users": []map[string]string{{"id": "42", "username": "alice"}},
			})
		case "/PasswordVault/API/Users/42":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       "42",
				"username": "alice",
				"source":   "LDAP",
				"userDN":   "CN=alice,OU=Users,DC=corp,DC=local",
				"personalDetails": map[string]string{
					"email": "alice@corp.local",
				},
				"groupsMembership": []map[string]string{{"groupName": "Vault Admins"}},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.UserExtendedDetailsTimeout = 10 * time.Millisecond
	client.UserEnrichmentWorkers = 2

	users, err := client.ListUsers(nil)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].UserDN != "CN=alice,OU=Users,DC=corp,DC=local" {
		t.Fatalf("expected enriched userDN, got %q", users[0].UserDN)
	}
	if users[0].PersonalDetails.Email != "alice@corp.local" {
		t.Fatalf("expected enriched email, got %q", users[0].PersonalDetails.Email)
	}
	if len(users[0].GroupsMembership) != 1 || users[0].GroupsMembership[0].GroupName != "Vault Admins" {
		t.Fatalf("expected enriched groups, got %+v", users[0].GroupsMembership)
	}
}

func TestListUsersDecodesBodyAfterHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		time.Sleep(10 * time.Millisecond)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"Users": []map[string]string{{"username": "delayed-user"}},
		})
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.UserExtendedDetailsTimeout = time.Second

	users, err := client.ListUsers(nil)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 1 || users[0].Username != "delayed-user" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestListUsersLimitsReauthAttemptsOnUnauthorized(t *testing.T) {
	logons := 0
	userRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/PasswordVault/API/Auth/CyberArk/Logon":
			logons++
			_, _ = fmt.Fprintf(w, "%q", fmt.Sprintf("token-%d", logons))
		case "/PasswordVault/API/Users":
			userRequests++
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ErrorCode":"CAWS00006E","ErrorMessage":"not authorized for users"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.UserExtendedDetailsTimeout = 10 * time.Millisecond
	client.Token = "initial-token"

	_, err := client.ListUsers(nil)
	if err == nil {
		t.Fatal("expected ListUsers to return an authorization error")
	}
	if !strings.Contains(err.Error(), "not authorized for users") {
		t.Fatalf("expected 401 response body in error, got: %v", err)
	}
	if logons != 2 {
		t.Fatalf("logons = %d, want 2", logons)
	}
	if userRequests != 4 {
		t.Fatalf("user requests = %d, want 4", userRequests)
	}
}

func TestAuthenticatePersistsCookiesForAPIRequests(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/PasswordVault/API/Auth/CyberArk/Logon":
			http.SetCookie(w, &http.Cookie{Name: "PVWAAffinity", Value: "node-a", Path: "/"})
			_, _ = w.Write([]byte(`"token"`))
		case "/PasswordVault/API/Users":
			cookie, err := r.Cookie("PVWAAffinity")
			if err != nil || cookie.Value != "node-a" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"ErrorCode":"ITACM040S","ErrorMessage":"User was automatically logged off from Vault"}`))
				return
			}

			if r.Header.Get("Authorization") != "token" {
				t.Fatalf("Authorization header = %q, want token", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Users": []map[string]string{{"username": "cookie-user"}},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.UserExtendedDetailsTimeout = 10 * time.Millisecond
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}

	users, err := client.ListUsers(nil)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 1 || users[0].Username != "cookie-user" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestNormalizeAuthMethod(t *testing.T) {
	cases := map[string]struct {
		want string
		ok   bool
	}{
		"":               {AuthMethodCyberArk, true},
		"CyberArk":       {AuthMethodCyberArk, true},
		"ldap":           {AuthMethodLDAP, true},
		"RADIUS":         {AuthMethodRADIUS, true},
		"Windows":        {AuthMethodWindows, true},
		"identity":       {AuthMethodIdentity, true},
		"ISPSS":          {AuthMethodIdentity, true},
		"privilegecloud": {AuthMethodIdentity, true},
		"bogus":          {"bogus", false},
	}
	for in, want := range cases {
		got, ok := NormalizeAuthMethod(in)
		if got != want.want || ok != want.ok {
			t.Errorf("NormalizeAuthMethod(%q) = (%q, %v), want (%q, %v)", in, got, ok, want.want, want.ok)
		}
	}
}

func TestAuthenticateUsesConfiguredSelfHostedMethod(t *testing.T) {
	var logonPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logonPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`"ldap-token"`))
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.AuthMethod = AuthMethodLDAP
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if logonPath != "/PasswordVault/API/Auth/LDAP/Logon" {
		t.Fatalf("logon path = %q, want /PasswordVault/API/Auth/LDAP/Logon", logonPath)
	}
	if client.authorizationHeaderValue() != "ldap-token" {
		t.Fatalf("self-hosted auth header = %q, want raw token", client.authorizationHeaderValue())
	}
}

func TestAuthenticateIdentityOAuthFlow(t *testing.T) {
	var gotGrant, gotID, gotSecret string
	authReqs := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/platformtoken":
			authReqs++
			if err := r.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			gotGrant = r.PostForm.Get("grant_type")
			gotID = r.PostForm.Get("client_id")
			gotSecret = r.PostForm.Get("client_secret")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "abc.def.ghi",
				"token_type":   "Bearer",
				"expires_in":   900,
			})
		case "/PasswordVault/API/Users":
			if r.Header.Get("Authorization") != "Bearer abc.def.ghi" {
				t.Fatalf("Authorization = %q, want Bearer abc.def.ghi", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Users": []map[string]string{{"username": "cloud-user"}},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.AuthMethod = AuthMethodIdentity
	client.IdentityTenantURL = server.URL
	client.UserExtendedDetailsTimeout = 10 * time.Millisecond

	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate returned error: %v", err)
	}
	if authReqs != 1 {
		t.Fatalf("token requests = %d, want 1", authReqs)
	}
	if gotGrant != "client_credentials" || gotID != "user" || gotSecret != "pass" {
		t.Fatalf("token form = (grant=%q, id=%q, secret=%q)", gotGrant, gotID, gotSecret)
	}
	if client.Token != "abc.def.ghi" {
		t.Fatalf("token = %q, want abc.def.ghi", client.Token)
	}

	users, err := client.ListUsers(nil)
	if err != nil {
		t.Fatalf("ListUsers returned error: %v", err)
	}
	if len(users) != 1 || users[0].Username != "cloud-user" {
		t.Fatalf("unexpected users: %+v", users)
	}

	// Logoff for identity must not call the PVWA Logoff endpoint.
	if err := client.Logoff(); err != nil {
		t.Fatalf("Logoff returned error: %v", err)
	}
	if client.Token != "" {
		t.Fatalf("token should be cleared after Logoff, got %q", client.Token)
	}
}

func TestAuthenticateIdentityRequiresTenantURL(t *testing.T) {
	client := testClient("https://example.invalid")
	client.AuthMethod = AuthMethodIdentity
	if err := client.Authenticate(); err == nil {
		t.Fatal("expected error when IdentityTenantURL is empty")
	}
}

func TestListApplicationsWithAuthEnrichesAuthentications(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/PasswordVault/WebServices/PIMServices.svc/Applications/":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"application": []map[string]interface{}{
					{"AppID": "OpenApp", "Disabled": "No"},
					{"AppID": "LockedApp", "Disabled": "No"},
				},
			})
		case strings.Contains(r.URL.Path, "/Applications/OpenApp/Authentications"):
			// No restrictions configured.
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"authentication": []map[string]interface{}{},
			})
		case strings.Contains(r.URL.Path, "/Applications/LockedApp/Authentications"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"authentication": []map[string]interface{}{
					{"AuthType": "machineAddress", "AuthValue": "10.0.0.5"},
				},
			})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	apps, err := client.ListApplicationsWithAuth(4)
	if err != nil {
		t.Fatalf("ListApplicationsWithAuth returned error: %v", err)
	}
	if len(apps) != 2 {
		t.Fatalf("expected 2 applications, got %d", len(apps))
	}

	byID := map[string][]string{}
	for _, a := range apps {
		var types []string
		for _, auth := range a.Authentications {
			types = append(types, auth.AuthType)
		}
		byID[a.AppID] = types
	}
	if len(byID["OpenApp"]) != 0 {
		t.Errorf("OpenApp should have no authentications, got %v", byID["OpenApp"])
	}
	if len(byID["LockedApp"]) != 1 || byID["LockedApp"][0] != "machineAddress" {
		t.Errorf("LockedApp should have a machineAddress authentication, got %v", byID["LockedApp"])
	}
}
