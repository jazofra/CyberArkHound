package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/atomicfile"
	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/siemens-healthineers/cyberarkhound/pkg/exporter"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/siemens-healthineers/cyberarkhound/pkg/snapshot"
	"github.com/sirupsen/logrus"
)

// pvwaTag returns the node-ID namespace tag for a live collection: --pvwa-tag
// when given, otherwise the tag derived from the PVWA URL.
func pvwaTag(cfg *config) string {
	if cfg.pvwaTag != "" {
		return cfg.pvwaTag
	}
	return graph.PVWATagFromArg(cfg.pvwaURL)
}

// warnGenericTag points out derived tags that are likely to collide with
// another vault's in a shared BloodHound.
func warnGenericTag(cfg *config, logger *logrus.Logger) {
	if cfg.pvwaTag != "" {
		return
	}
	host := cfg.pvwaURL
	if u, err := url.Parse(client.NormalizeBaseURL(cfg.pvwaURL)); err == nil {
		host = u.Hostname()
	}
	if net.ParseIP(host) != nil {
		logger.Warnf("The PVWA is addressed by IP, so its node-ID tag (%s) is generic; if you import several vaults into one BloodHound, give each a distinct --pvwa-tag", pvwaTag(cfg))
	}
}

// run performs one collection (or offline rebuild) and returns the process
// exit code. Cancelling ctx stops the collection early; the data gathered so
// far is still built and exported, and run returns exitInterrupted.
func run(ctx context.Context, cfg *config, logger *logrus.Logger) int {
	exitCode := exitOK

	var snap *snapshot.Snapshot
	if cfg.fromRaw != "" {
		var err error
		snap, err = snapshot.Load(cfg.fromRaw)
		if err != nil {
			logger.Errorf("Failed to load raw collection: %v", err)
			return exitError
		}
		logger.Infof("Loaded raw collection from %s (collected %s from %s, PVWA tag %s)",
			cfg.fromRaw, snap.CollectedAt.Format(time.RFC3339), snap.PVWAURL, snap.PVWATag)
		if cfg.pvwaURL != "" {
			logger.Warnf("--pvwa is ignored with --from-raw; use --pvwa-tag to change the node-ID tag (%s)", snap.PVWATag)
		}
		if cfg.pvwaTag != "" && cfg.pvwaTag != snap.PVWATag {
			logger.Infof("Re-tagging node IDs from %s to %s", snap.PVWATag, cfg.pvwaTag)
			snap.PVWATag = cfg.pvwaTag
		}
	} else {
		var base *snapshot.Snapshot
		checkpointPath := cfg.saveRaw
		if cfg.resume != "" {
			var err error
			if base, err = loadResumable(cfg, logger); err != nil {
				logger.Errorf("Cannot resume: %v", err)
				return exitError
			}
			if checkpointPath == "" {
				checkpointPath = cfg.resume
			}
			// Keep the original collection's tag unless one is given.
			if cfg.pvwaTag == "" {
				cfg.pvwaTag = base.PVWATag
			}
			base.PVWATag = cfg.pvwaTag
		}

		logger.Infof("PVWA tag: %s", pvwaTag(cfg))
		warnGenericTag(cfg, logger)
		api := newClient(ctx, cfg, logger)

		if cfg.authMethod == client.AuthMethodIdentity {
			logger.Infof("Authenticating to CyberArk Identity (Privilege Cloud) at %s...", cfg.identityURL)
		} else {
			logger.Infof("Authenticating to CyberArk PVWA (method: %s)...", cfg.authMethod)
		}
		if err := api.Authenticate(); err != nil {
			logger.Errorf("Authentication failed: %v", err)
			if hint := tlsHint(err); hint != "" {
				logger.Warn(hint)
			}
			return exitError
		}

		// Log off as soon as the collection is done, and on every early
		// return, so a failed run never leaves a PVWA session open.
		logoff := sync.OnceFunc(func() {
			if err := api.Logoff(); err != nil {
				logger.Warnf("Logoff failed: %v", err)
			}
		})
		defer logoff()

		logger.Infof("Target domains: %s", cfg.targetDomains)
		if cfg.parseSAM {
			logger.Info("Enabled: parse sAMAccountName from distinguishedName CN for CyberArk_SyncsToUser edges")
		}

		c := newCollector(ctx, cfg, api, logger, base, checkpointPath)
		var err error
		snap, err = c.run()
		if err != nil {
			logger.Errorf("%v", err)
			return exitError
		}
		logoff()
		if c.saveFailed {
			exitCode = exitError
		}
	}

	logger.Info("Building OpenGraph...")
	og, err := graph.BuildOpenGraph(buildInput(snap, cfg), logger)
	if err != nil {
		logger.Errorf("Failed to build OpenGraph: %v", err)
		return exitError
	}

	logger.Info("Exporting to BloodHound JSON...")
	if err := exporter.ExportToBloodHoundJSON(og, cfg.outputFile, logger); err != nil {
		logger.Errorf("Failed to export: %v", err)
		return exitError
	}

	if len(snap.Incomplete) > 0 {
		logger.Warn("Export completed with INCOMPLETE data:")
		for _, reason := range snap.Incomplete {
			logger.Warnf("  - %s", reason)
		}
		logger.Warn("The exported graph does not represent the full CyberArk environment.")
	} else {
		logger.Info("Export completed successfully!")
	}

	logSummary(og, logger)

	// Surface computed security findings (highest-value misconfigurations) so
	// operators see them without writing Cypher. Findings are derived from the
	// collected data only — no extra API calls.
	findings := graph.ComputeFindings(og)
	if len(findings) > 0 {
		logger.Info("=== Security Findings ===")
		for _, f := range findings {
			logger.Warnf("[%s] %s: %d — %s", f.Severity, f.Title, f.Count, f.Detail)
		}
		logger.Info("Run with --include-applications and --include-platforms for complete findings coverage.")
	} else {
		logger.Info("=== Security Findings === none detected from the collected data")
	}

	if cfg.findingsOutput != "" {
		if err := writeFindings(cfg.findingsOutput, snap, findings); err != nil {
			logger.Errorf("Failed to write findings to %s: %v", cfg.findingsOutput, err)
			exitCode = exitError
		} else {
			logger.Infof("Wrote %d findings to %s", len(findings), cfg.findingsOutput)
		}
	}

	if cfg.fromRaw == "" && ctx.Err() != nil {
		return exitInterrupted
	}
	return exitCode
}

// loadResumable loads the --resume file and makes cfg match the collection it
// continues: the PVWA URL defaults to the file's, and the options that decide
// what is fetched are taken from the original run.
func loadResumable(cfg *config, logger *logrus.Logger) (*snapshot.Snapshot, error) {
	snap, err := snapshot.Load(cfg.resume)
	if err != nil {
		return nil, err
	}
	if snap.Progress == nil {
		return nil, fmt.Errorf("%s does not record collection progress, so it cannot be resumed", cfg.resume)
	}
	if cfg.pvwaURL == "" {
		cfg.pvwaURL = snap.PVWAURL
	} else if got, want := client.NormalizeBaseURL(cfg.pvwaURL), client.NormalizeBaseURL(snap.PVWAURL); got != want {
		return nil, fmt.Errorf("%s was collected from %s, not %s", cfg.resume, want, got)
	}

	o := snap.Progress.Options
	ignored := func(flag string, given, original interface{}) {
		if cfg.explicit[flag] && given != original {
			logger.Warnf("--%s=%v is ignored when resuming; the collection continues with the original value %v", flag, given, original)
		}
	}
	ignored("limit-users", cfg.limitUsers, o.LimitUsers)
	ignored("limit-groups", cfg.limitGroups, o.LimitGroups)
	ignored("limit-safes", cfg.limitSafes, o.LimitSafes)
	ignored("test-safe", cfg.testSafe, o.TestSafe)
	ignored("activity-days", cfg.activityDays, o.ActivityDays)
	ignored("activity-limit", cfg.activityLimit, o.ActivityLimit)
	ignored("include-predefined-members", cfg.includePredefinedMembers, o.IncludePredefinedMembers)
	cfg.limitUsers, cfg.limitGroups, cfg.limitSafes, cfg.testSafe = o.LimitUsers, o.LimitGroups, o.LimitSafes, o.TestSafe
	cfg.activityDays, cfg.activityLimit = o.ActivityDays, o.ActivityLimit
	cfg.includePredefinedMembers = o.IncludePredefinedMembers

	p := snap.Progress
	logger.Infof("Resuming the collection from %s (started %s; done: %d stages, %d/%d safes scanned, %d/%d accounts detailed)",
		cfg.resume, snap.CollectedAt.Format(time.RFC3339), len(p.Stages),
		len(p.ScannedSafes), len(snap.Safes), len(p.DetailedAccounts), len(p.DiscoveredAccounts))
	return snap, nil
}

// tlsHint suggests a fix when a connection failed during the TLS handshake or
// certificate verification, or returns "" for any other error.
func tlsHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509: certificate signed by unknown authority"):
		return "The server's certificate is not trusted. Pass the issuing CA certificate(s) with --ca-bundle rather than disabling verification with --insecure."
	case strings.Contains(msg, "tls:") || strings.Contains(msg, "x509:"):
		return "The TLS connection failed. If this PVWA only offers legacy TLS options, see \"TLS troubleshooting\" in the README for the GODEBUG settings that re-enable them."
	}
	return ""
}

// buildInput turns a collection into graph-builder input. The --include-*
// flags also apply here, so an offline rebuild can leave out data the raw
// collection contains.
func buildInput(snap *snapshot.Snapshot, cfg *config) graph.BuildInput {
	in := graph.BuildInput{
		Users:                     snap.Users,
		Groups:                    snap.Groups,
		Safes:                     snap.Safes,
		SafeMembers:               snap.SafeMembers,
		Accounts:                  snap.Accounts,
		TargetDomains:             cfg.targetDomains,
		ParseSAMAccountNameFromDN: cfg.parseSAM,
		PVWATag:                   snap.PVWATag,
	}
	if cfg.includeActivity {
		in.AccountActivities = snap.AccountActivities
	}
	if cfg.includePlatforms {
		in.Platforms = snap.Platforms
		in.PlatformConnectors = snap.PlatformConnectors
		in.TargetPlatforms = snap.TargetPlatforms
	}
	if cfg.includePSM {
		in.PSMServers = snap.PSMServers
		in.ConnectionComponents = snap.ConnectionComponents
	}
	if cfg.includeApplications {
		in.Applications = snap.Applications
	}
	// Linked accounts arrive embedded in the account details.
	if cfg.includeLinkedAccounts {
		in.LinkedAccounts = make(map[string][]models.LinkedAccount)
		for _, acc := range snap.Accounts {
			if acc.ID != "" && len(acc.LinkedAccounts) > 0 {
				in.LinkedAccounts[acc.ID] = acc.LinkedAccounts
			}
		}
	}
	return in
}

// findingsReport is the document written by --findings-output.
type findingsReport struct {
	GeneratedAt time.Time       `json:"generatedAt"`
	CollectedAt time.Time       `json:"collectedAt"`
	PVWAURL     string          `json:"pvwaUrl"`
	PVWATag     string          `json:"pvwaTag"`
	Incomplete  []string        `json:"incomplete,omitempty"`
	Findings    []graph.Finding `json:"findings"`
}

func writeFindings(path string, snap *snapshot.Snapshot, findings []graph.Finding) error {
	if findings == nil {
		findings = []graph.Finding{}
	}
	report := findingsReport{
		GeneratedAt: time.Now().UTC(),
		CollectedAt: snap.CollectedAt,
		PVWAURL:     snap.PVWAURL,
		PVWATag:     snap.PVWATag,
		Incomplete:  snap.Incomplete,
		Findings:    findings,
	}
	return atomicfile.Write(path, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	})
}

// logSummary prints node and edge counts by kind, in a stable order.
func logSummary(og *graph.OpenGraph, logger *logrus.Logger) {
	summary := og.GetSummary()
	logCounts := func(title string, counts map[string]int) {
		if len(counts) == 0 {
			return
		}
		kinds := make([]string, 0, len(counts))
		for kind := range counts {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		logger.Info(title)
		for _, kind := range kinds {
			logger.Infof("  %s: %d", kind, counts[kind])
		}
	}

	logger.Info("=== Collection Summary ===")
	logger.Infof("Total Nodes: %d", summary["total_nodes"])
	if counts, ok := summary["nodes_by_kind"].(map[string]int); ok {
		logCounts("Nodes by Type:", counts)
	}
	logger.Infof("Total Internal Edges: %d", summary["total_internal_edges"])
	if counts, ok := summary["internal_edges_by_kind"].(map[string]int); ok {
		logCounts("Internal Edges by Type:", counts)
	}
	logger.Infof("Total External Edges: %d", summary["total_external_edges"])
	if counts, ok := summary["external_edges_by_kind"].(map[string]int); ok {
		logCounts("External Edges by Type:", counts)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	logger.Infof("Memory stats: Alloc=%dMB Sys=%dMB NumGC=%d", m.Alloc/1024/1024, m.Sys/1024/1024, m.NumGC)
}
