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
