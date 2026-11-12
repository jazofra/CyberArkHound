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

func TestSaveCompressesGzPaths(t *testing.T) {
	dir := t.TempDir()
	snap := &Snapshot{FormatVersion: FormatVersion, PVWATag: "TEST"}
	for i := 0; i < 500; i++ {
		snap.Safes = append(snap.Safes, models.Safe{SafeName: "Safe", Description: "the same description for every safe"})
	}
	plain, packed := filepath.Join(dir, "raw.json"), filepath.Join(dir, "raw.json.gz")
	for _, path := range []string{plain, packed} {
		if err := Save(path, snap); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatalf("load %s: %v", path, err)
		}
		if len(got.Safes) != 500 || got.PVWATag != "TEST" {
			t.Errorf("%s did not round-trip: %d safes, tag %q", path, len(got.Safes), got.PVWATag)
		}
	}
	plainInfo, _ := os.Stat(plain)
	packedInfo, _ := os.Stat(packed)
	if packedInfo.Size()*5 > plainInfo.Size() {
		t.Errorf("compressed file is %d bytes, uncompressed %d", packedInfo.Size(), plainInfo.Size())
	}

	// Compression is recognised from the content, so a renamed file loads.
	renamed := filepath.Join(dir, "renamed.json")
	if err := os.Rename(packed, renamed); err != nil {
		t.Fatal(err)
	}
	if got, err := Load(renamed); err != nil || len(got.Safes) != 500 {
		t.Errorf("renamed compressed file: %v", err)
	}
}
