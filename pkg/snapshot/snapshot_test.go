package snapshot

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	in := &Snapshot{
		FormatVersion: FormatVersion,
		CollectedAt:   time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC),
		PVWAURL:       "https://pvwa.example.com",
		PVWATag:       "PVEX",
		Incomplete:    []string{"something was skipped"},
		Users:         []models.User{{ID: float64(3), Username: "alice"}},
		Groups:        []models.Group{{ID: float64(7), GroupName: "Ops", Members: []models.GroupMember{{Username: "alice"}}}},
		Safes:         []models.Safe{{SafeName: "S1", SafeUrlId: "S1"}},
		SafeMembers:   []models.SafeMember{{MemberName: "alice", SafeName: "S1", Permissions: map[string]interface{}{"useAccounts": true}}},
		Accounts: []models.Account{{ID: "1_1", SafeName: "S1", LinkedAccounts: []models.LinkedAccount{
			{AccountID: "1_2", ExtraPassID: 3, Name: "recon"},
		}}},
		AccountActivities:  map[string][]models.AccountActivity{"1_1": {{User: "alice", Action: "Retrieve", Date: float64(1700000000)}}},
		PlatformConnectors: map[string][]string{"WinServer": {"PSM-RDP"}},
		Applications: []models.Application{
			{AppID: "App1", Authentications: []models.ApplicationAuthentication{{AuthType: "machineAddress", AuthValue: "10.0.0.1"}}},
			{AppID: "App2", AuthenticationsUnknown: true},
		},
		Progress: &Progress{
			Options:            Options{LimitSafes: 5, ActivityDays: 3, ActivityLimit: 100, IncludePredefinedMembers: true},
			Stages:             []string{StageUsers, StageGroups},
			ScannedSafes:       []string{"S1"},
			DiscoveredAccounts: []AccountRef{{ID: "1_1", SafeName: "S1"}},
			DetailedAccounts:   []string{"1_1"},
			ActivityFetched:    []string{"1_1"},
			ResumedAt:          []time.Time{time.Date(2026, 5, 2, 9, 0, 0, 0, time.UTC)},
		},
	}

	path := filepath.Join(t.TempDir(), "raw.json")
	if err := Save(path, in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip mismatch:\n in: %+v\nout: %+v", in, out)
	}
}

func TestLoadRejectsOtherFormatVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raw.json")
	if err := os.WriteFile(path, []byte(`{"formatVersion":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "format version 99") {
		t.Fatalf("expected a format version error, got %v", err)
	}
}
