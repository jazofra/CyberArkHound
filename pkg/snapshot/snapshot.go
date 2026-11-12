// Package snapshot saves and loads the raw data a collection gathered from
// PVWA, so the graph can be rebuilt (for example with different target domains
// or after a CyberArkHound upgrade) without collecting again, and so real
// collections can serve as test fixtures.
package snapshot

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jazofra/CyberArkHound/internal/atomicfile"
	"github.com/jazofra/CyberArkHound/pkg/models"
)

// FormatVersion is the on-disk format written by Save. Load rejects other
// versions rather than silently misreading them.
const FormatVersion = 1

// Snapshot is everything CyberArkHound collected in one run. It never holds
// credentials: the API password and session token are not part of it.
type Snapshot struct {
	FormatVersion int       `json:"formatVersion"`
	CollectedAt   time.Time `json:"collectedAt"`
	PVWAURL       string    `json:"pvwaUrl"`
	PVWATag       string    `json:"pvwaTag"`
	// CollectorVersion is the CyberArkHound version that collected the data
	// (the latest one, for a resumed collection).
	CollectorVersion string `json:"collectorVersion,omitempty"`
	// Incomplete lists why the collection did not cover the whole environment.
	Incomplete []string `json:"incomplete,omitempty"`

	Users                []models.User                       `json:"users"`
	Groups               []models.Group                      `json:"groups"`
	Safes                []models.Safe                       `json:"safes"`
	SafeMembers          []models.SafeMember                 `json:"safeMembers"`
	Accounts             []models.Account                    `json:"accounts"`
	AccountActivities    map[string][]models.AccountActivity `json:"accountActivities,omitempty"`
	Platforms            []models.Platform                   `json:"platforms,omitempty"`
	PlatformConnectors   map[string][]string                 `json:"platformConnectors,omitempty"`
	TargetPlatforms      []models.TargetPlatform             `json:"targetPlatforms,omitempty"`
	PSMServers           []models.PSMServer                  `json:"psmServers,omitempty"`
	ConnectionComponents []models.ConnectionComponent        `json:"connectionComponents,omitempty"`
	// Applications is serialized through application below, because the
	// models type keeps its authentication data out of JSON.
	Applications []models.Application `json:"-"`

	// Progress records how far the collection got, so it can be resumed.
	Progress *Progress `json:"progress,omitempty"`
}

// Collection stages, in the order they run. A resumed collection skips the
// stages an earlier run completed.
const (
	StageUsers          = "users"
	StageGroups         = "groups"
	StageSafes          = "safes"
	StagePlatforms      = "platforms"
	StagePSM            = "psm"
	StageApplications   = "applications"
	StageSafeContents   = "safe-contents"   // members and account lists of every safe
	StageAccountDetails = "account-details" // details of every discovered account
	StageActivity       = "activity"        // activity of every collected account
)

// Progress records how far a collection got, so that an interrupted or
// failed collection can be resumed without fetching completed work again.
// A stage or item is recorded only once it was fetched without errors, so a
// resumed collection also retries everything that failed.
type Progress struct {
	// Options are the collection options that decide what is fetched. A
	// resumed collection reuses them so that its parts fit together.
	Options Options `json:"options"`
	// Stages lists the stages completed in full.
	Stages []string `json:"stages,omitempty"`
	// ScannedSafes lists the safes whose members and accounts were listed.
	ScannedSafes []string `json:"scannedSafes,omitempty"`
	// DiscoveredAccounts are the accounts listed in scanned safes; their
	// details are fetched in the next stage.
	DiscoveredAccounts []AccountRef `json:"discoveredAccounts,omitempty"`
	// DetailedAccounts lists the discovered accounts whose details were
	// fetched (including disabled, archived or vanished accounts, which are
	// then left out of Accounts).
	DetailedAccounts []string `json:"detailedAccounts,omitempty"`
	// ActivityFetched lists the accounts whose activity was fetched.
	ActivityFetched []string `json:"activityFetched,omitempty"`
	// PredefinedMembersExcluded records that PVWA rejected the request for
	// built-in safe members, so they are missing from the scanned safes.
	PredefinedMembersExcluded bool `json:"predefinedMembersExcluded,omitempty"`
	// ResumedAt lists when the collection was resumed.
	ResumedAt []time.Time `json:"resumedAt,omitempty"`
}

// Options are the collection options a resumed collection must reuse.
type Options struct {
	LimitUsers               int    `json:"limitUsers,omitempty"`
	LimitGroups              int    `json:"limitGroups,omitempty"`
	LimitSafes               int    `json:"limitSafes,omitempty"`
	TestSafe                 string `json:"testSafe,omitempty"`
	ActivityDays             int    `json:"activityDays"`
	ActivityLimit            int    `json:"activityLimit"`
	IncludePredefinedMembers bool   `json:"includePredefinedMembers"`
}

// AccountRef identifies an account discovered in a safe.
type AccountRef struct {
	ID       string `json:"id"`
	SafeName string `json:"safeName"`
}

// application is the on-disk form of a models.Application, including the
// authentication data that models.Application excludes from JSON.
type application struct {
	models.Application
	Authentications        []models.ApplicationAuthentication `json:"authentications,omitempty"`
	AuthenticationsUnknown bool                               `json:"authenticationsUnknown,omitempty"`
}

type onDisk struct {
	*Snapshot
	Applications []application `json:"applications,omitempty"`
}

// Save writes s to path as JSON, atomically and with mode 0600: the snapshot
// describes the vault in detail. A path ending in ".gz" is written
// gzip-compressed. Snapshots are repetitive JSON and compress to a small
// fraction of their size, which matters for large vaults whose progress is
// saved again every minute while collecting.
func Save(path string, s *Snapshot) error {
	d := onDisk{Snapshot: s}
	for _, app := range s.Applications {
		d.Applications = append(d.Applications, application{
			Application:            app,
			Authentications:        app.Authentications,
			AuthenticationsUnknown: app.AuthenticationsUnknown,
		})
	}
	return atomicfile.Write(path, func(w io.Writer) error {
		buffered := bufio.NewWriterSize(w, 1<<20)
		var out io.Writer = buffered
		var zw *gzip.Writer
		if IsCompressedPath(path) {
			// The fastest level already removes most of the redundancy and
			// keeps a save from taking much longer than an uncompressed one.
			zw, _ = gzip.NewWriterLevel(buffered, gzip.BestSpeed)
			out = zw
		}
		enc := json.NewEncoder(out)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(d); err != nil {
			return err
		}
		if zw != nil {
			if err := zw.Close(); err != nil {
				return err
			}
		}
		return buffered.Flush()
	})
}

// IsCompressedPath reports whether Save compresses the file at path.
func IsCompressedPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".gz")
}

// Load reads a snapshot written by Save. Compression is recognised from the
// file's content, not its name, so a renamed file still loads.
func Load(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	in := bufio.NewReaderSize(f, 1<<20)
	var r io.Reader = in
	if magic, _ := in.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(in)
		if err != nil {
			return nil, fmt.Errorf("decompress snapshot %s: %w", path, err)
		}
		defer zr.Close()
		r = zr
	}

	d := onDisk{Snapshot: &Snapshot{}}
	if err := json.NewDecoder(r).Decode(&d); err != nil {
		return nil, fmt.Errorf("decode snapshot %s: %w", path, err)
	}
	if d.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("snapshot %s has format version %d; this build reads version %d", path, d.FormatVersion, FormatVersion)
	}
	for _, app := range d.Applications {
		a := app.Application
		a.Authentications = app.Authentications
		a.AuthenticationsUnknown = app.AuthenticationsUnknown
		d.Snapshot.Applications = append(d.Snapshot.Applications, a)
	}
	return d.Snapshot, nil
}
