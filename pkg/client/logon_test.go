package client

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthenticateRADIUSAnswersChallenge(t *testing.T) {
	var passwords []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/PasswordVault/API/Auth/radius/Logon" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		passwords = append(passwords, body["password"])
		w.Header().Set("Content-Type", "application/json")
		if body["password"] != "123456" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"ErrorCode":"ITATS542I","ErrorMessage":"Enter your one-time code"}`))
			return
		}
		_, _ = w.Write([]byte(`"radius-token"`))
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.AuthMethod = AuthMethodRADIUS
	var asked []string
	client.ChallengePrompt = func(challenge string) (string, error) {
		asked = append(asked, challenge)
		return "123456", nil
	}
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if client.Token != "radius-token" {
		t.Errorf("token = %q", client.Token)
	}
	if len(asked) != 1 || asked[0] != "Enter your one-time code" {
		t.Errorf("challenge prompts = %q", asked)
	}
	if len(passwords) != 2 || passwords[0] != "pass" || passwords[1] != "123456" {
		t.Errorf("passwords sent = %q", passwords)
	}
}

func TestAuthenticateRADIUSChallengeFailures(t *testing.T) {
	challenged := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenged++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ErrorCode":"ITATS542I","ErrorMessage":"Code?"}`))
	}))
	defer server.Close()

	t.Run("no terminal", func(t *testing.T) {
		client := testClient(server.URL)
		client.AuthMethod = AuthMethodRADIUS
		err := client.Authenticate()
		if err == nil || !strings.Contains(err.Error(), "interactive") || !strings.Contains(err.Error(), "Code?") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("prompt fails", func(t *testing.T) {
		client := testClient(server.URL)
		client.AuthMethod = AuthMethodRADIUS
		client.ChallengePrompt = func(string) (string, error) { return "", errors.New("closed") }
		if err := client.Authenticate(); err == nil || !strings.Contains(err.Error(), "closed") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("endless challenges", func(t *testing.T) {
		challenged = 0
		client := testClient(server.URL)
		client.AuthMethod = AuthMethodRADIUS
		client.ChallengePrompt = func(string) (string, error) { return "000000", nil }
		if err := client.Authenticate(); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Errorf("err = %v", err)
		}
		if challenged != maxRADIUSChallenges+1 {
			t.Errorf("server was asked %d times, want %d", challenged, maxRADIUSChallenges+1)
		}
	})
	// Only RADIUS logons are challenged; the same error from another method is a failure.
	t.Run("other method", func(t *testing.T) {
		client := testClient(server.URL)
		client.ChallengePrompt = func(string) (string, error) {
			t.Error("prompted for a non-RADIUS logon")
			return "x", nil
		}
		if err := client.Authenticate(); err == nil {
			t.Error("expected an error")
		}
	})
}

// ntlmChallenge builds a minimal NTLM CHALLENGE_MESSAGE (type 2).
func ntlmChallenge() []byte {
	const flags = 0x00000001 | 0x00000200 | 0x00080000 | 0x00800000 // unicode, NTLM, extended session security, target info
	targetInfo := []byte{0, 0, 0, 0}                                // MsvAvEOL
	var b bytes.Buffer
	b.WriteString("NTLMSSP\x00")
	_ = binary.Write(&b, binary.LittleEndian, uint32(2))
	_ = binary.Write(&b, binary.LittleEndian, [2]uint16{0, 0}) // target name: empty
	_ = binary.Write(&b, binary.LittleEndian, uint32(48))
	_ = binary.Write(&b, binary.LittleEndian, uint32(flags))
	b.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}) // server challenge
	b.Write(make([]byte, 8))                // reserved
	_ = binary.Write(&b, binary.LittleEndian, [2]uint16{uint16(len(targetInfo)), uint16(len(targetInfo))})
	_ = binary.Write(&b, binary.LittleEndian, uint32(48))
	b.Write(targetInfo)
	return b.Bytes()
}

// ntlmMessageType returns the NTLM message type carried by an Authorization
// header, or 0 when there is none.
func ntlmMessageType(header string) uint32 {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, "NTLM "))
	if err != nil || len(raw) < 12 || !bytes.HasPrefix(raw, []byte("NTLMSSP\x00")) {
		return 0
	}
	return binary.LittleEndian.Uint32(raw[8:12])
}

func TestAuthenticateWindowsUsesNTLMAndKeepsCredentialsOutOfTheBody(t *testing.T) {
	var steps []uint32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/PasswordVault/API/Auth/Windows/Logon" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "pass") || strings.Contains(string(body), "user") {
			t.Errorf("credentials were sent in the body: %s", body)
		}
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Basic ") {
			t.Error("credentials were sent as Basic authentication")
		}
		step := ntlmMessageType(auth)
		steps = append(steps, step)
		switch step {
		case 1:
			w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ntlmChallenge()))
			w.WriteHeader(http.StatusUnauthorized)
		case 3:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`"windows-token"`))
		default:
			w.Header().Add("Www-Authenticate", "Negotiate")
			w.Header().Add("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.Username = `CORP\user`
	client.AuthMethod = AuthMethodWindows
	if err := client.Authenticate(); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if client.Token != "windows-token" {
		t.Errorf("token = %q", client.Token)
	}
	if len(steps) != 3 || steps[0] != 0 || steps[1] != 1 || steps[2] != 3 {
		t.Errorf("NTLM message types = %v, want [0 1 3]", steps)
	}
}

func TestAuthenticateWindowsExplainsMissingIntegratedAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // no NTLM/Negotiate offered
	}))
	defer server.Close()

	client := testClient(server.URL)
	client.AuthMethod = AuthMethodWindows
	err := client.Authenticate()
	if err == nil || !strings.Contains(err.Error(), "IIS") {
		t.Errorf("err = %v", err)
	}
}
