package main

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/parallel"
	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/siemens-healthineers/cyberarkhound/pkg/snapshot"
	"github.com/sirupsen/logrus"
)

// newClient creates an API client configured from cfg.
func newClient(ctx context.Context, cfg *config, logger *logrus.Logger) *client.Client {
	api := client.NewClient(cfg.pvwaURL, cfg.username, cfg.password, cfg.insecure, cfg.caBundle, logger)
	api.SetContext(ctx)
	api.AuthMethod = cfg.authMethod
	api.IdentityTenantURL = client.NormalizeBaseURL(cfg.identityURL)
	api.ReqTimeout = cfg.requestTimeout
	api.AuthTimeout = cfg.authTimeout
	api.UserExtendedDetailsTimeout = cfg.userExtendedDetailsTimeout
	api.UserEnrichmentWorkers = cfg.workers
	api.SafePageLimit = cfg.safePageLimit
	api.MaxReauthAttempts = cfg.maxReauthAttempts
	api.MaxRateLimitRetries = cfg.maxRateLimitRetries
	api.IncludePredefinedSafeMembers = cfg.includePredefinedMembers
	api.HTTPClient.Timeout = api.ReqTimeout
	return api
}

// limitPtr turns a "0 = no limit" flag into the optional limit the client takes.
func limitPtr(n int) *int {
	if n <= 0 {
		return nil
	}
	return &n
}

// summarizeErr shortens an error for the incomplete-collection report; API
// errors can carry whole HTML error pages.
func summarizeErr(err error) string {
	const maxLen = 200
	s := err.Error()
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// collect gathers everything the graph is built from.
//
// It returns whatever it collected even when it stops early — because ctx was
// cancelled, or because safe enumeration failed partway with
// --continue-on-error — with the reasons recorded in Snapshot.Incomplete. An
// error is returned only when the collection cannot produce a usable result.
func collect(ctx context.Context, cfg *config, api *client.Client, logger *logrus.Logger) (*snapshot.Snapshot, error) {
	snap := &snapshot.Snapshot{
		FormatVersion: snapshot.FormatVersion,
		CollectedAt:   time.Now().UTC(),
		PVWAURL:       api.BaseURL,
		PVWATag:       pvwaTag(cfg),
	}

	var incomplete []string
	note := func(format string, args ...interface{}) {
		incomplete = append(incomplete, fmt.Sprintf(format, args...))
	}
	interrupted := func() bool { return ctx.Err() != nil }
	finish := func() (*snapshot.Snapshot, error) {
		reasons := incomplete
		if interrupted() {
			reasons = append([]string{"the collection was interrupted before it finished"}, reasons...)
		}
		snap.Incomplete = append(reasons, api.IncompleteReasons()...)
		return snap, nil
	}
	// optional reports a failed lookup the export can do without, unless the
	// failure was only the collection being interrupted.
	optional := func(err error, what, consequence string) {
		if err == nil || interrupted() {
			return
		}
		logger.Warnf("Failed to fetch %s: %v (%s)", what, err, consequence)
		note("%s could not be fetched (%s): %s", what, consequence, summarizeErr(err))
	}

	logger.Info("Fetching users...")
	users, err := api.ListUsers(limitPtr(cfg.limitUsers))
	if err != nil {
		if interrupted() {
			return finish()
		}
		return nil, fmt.Errorf("failed to fetch users: %w", err)
	}
	snap.Users = users

	logger.Info("Fetching groups...")
	groups, err := api.ListGroups(limitPtr(cfg.limitGroups), cfg.workers)
	if err != nil {
		if interrupted() {
			return finish()
		}
		return nil, fmt.Errorf("failed to fetch groups: %w", err)
	}
	snap.Groups = groups
	if interrupted() {
		return finish()
	}

	logger.Info("Fetching safes...")
	var testSafe *string
	if cfg.testSafe != "" {
		testSafe = &cfg.testSafe
		logger.Infof("Searching for safe: %s", cfg.testSafe)
	}
	// ListSafes returns whatever it collected before failing, so a run that
	// dies on a single bad page does not throw away hours of collection.
	safes, err := api.ListSafes(limitPtr(cfg.limitSafes), testSafe)
	snap.Safes = safes
	if err != nil {
		switch {
		case interrupted():
			return finish()
		case !cfg.continueOnError || len(safes) == 0:
			return nil, fmt.Errorf("failed to fetch safes: %w", err)
		}
		logger.Errorf("Failed to fetch safes: %v", err)
		logger.Warnf("Continuing with the %d safes collected before the failure (disable with --continue-on-error=false)", len(safes))
		note("safe enumeration stopped early after %d safes: %s", len(safes), summarizeErr(err))
	}
	if testSafe != nil {
		if len(safes) == 0 {
			return nil, fmt.Errorf("no safes found matching '%s'", cfg.testSafe)
		}
		logger.Infof("Found %d safes matching '%s'", len(safes), cfg.testSafe)
	}

	if cfg.includePlatforms && !interrupted() {
		logger.Info("Fetching platforms...")
		platforms, err := api.ListPlatforms()
		optional(err, "platforms", "platform details will be limited to the Targets data")
		snap.Platforms = platforms

		// Fetch PSM connection components per platform
		if len(platforms) > 0 {
			logger.Info("Fetching PSM connection components per platform...")
			platformIDs := make([]string, 0, len(platforms))
			for _, p := range platforms {
				pid := p.General.ID
				if pid == "" {
					pid = p.General.Name
				}
				if pid != "" {
					platformIDs = append(platformIDs, pid)
				}
			}
			snap.PlatformConnectors = api.GetAllPlatformPSMConnectors(platformIDs, cfg.workers)
			logger.Infof("Fetched PSM connectors for %d platforms", len(snap.PlatformConnectors))
		}

		// Fetch target platform data for Master Policy exception flags
		logger.Info("Fetching platform exception data...")
		targets, err := api.ListTargetPlatforms()
		optional(err, "target platform data", "Master Policy exception flags will be omitted")
		snap.TargetPlatforms = targets
	}

	if cfg.includePSM && !interrupted() {
		logger.Info("Fetching PSM servers...")
		servers, err := api.ListPSMServers()
		optional(err, "PSM servers", "PSM server nodes will be missing")
		snap.PSMServers = servers

		logger.Info("Fetching connection components...")
		components, err := api.ListConnectionComponents()
		optional(err, "connection components", "connection component nodes will be missing")
		snap.ConnectionComponents = components
	}

	// Tradecraft reference: Marat Nigmatullin (FalconForce), SO-CON 2026 —
	// "4 GET requests = 3 Domain admins: CyberArk magic you didn't know about".
	if cfg.includeApplications && !interrupted() {
		logger.Info("Fetching applications (CCP/AIMWebService AppIDs)...")
		applications, err := api.ListApplicationsWithAuth(cfg.workers)
		optional(err, "applications", "CCP mapping will be omitted; the collector user may lack the 'Manage Users' authorization")
		snap.Applications = applications
	}
	if interrupted() {
		return finish()
	}

	// --- Phase 1: Discovery (Parallel Safe Processing) ---
	logger.Infof("Phase 1: Discovering members and accounts for %d safes...", len(safes))

	// Results are stored per safe and flattened in safe order afterwards, so
	// the collected data (and everything derived from it) does not depend on
	// which worker finished first.
	safeMembers := make([][]models.SafeMember, len(safes))
	safeAccounts := make([][]models.Account, len(safes))
	var memberFailures, accountFailures, safesProcessed atomic.Int64

	parallel.ForEach(ctx, safes, cfg.workers, func(idx int, safe models.Safe) {
		if n := safesProcessed.Add(1); n%10 == 0 || int(n) == len(safes) {
			logger.Infof("Processing safe %d/%d: '%s'", n, len(safes), safe.SafeName)
		}

		members, err := api.ListSafeMembers(safe.SafeName, safe.SafeUrlId)
		if err != nil {
			if !interrupted() {
				memberFailures.Add(1)
				logger.Warnf("Failed to fetch members for safe '%s': %v", safe.SafeName, err)
			}
		} else {
			safeMembers[idx] = members
		}

		accounts, err := api.ListAccounts(safe.SafeName)
		if err != nil {
			if !interrupted() {
				accountFailures.Add(1)
				logger.Warnf("Failed to fetch accounts for safe '%s': %v", safe.SafeName, err)
			}
		} else {
			safeAccounts[idx] = accounts
		}
	})

	var skeletonAccounts []models.Account
	for i := range safes {
		snap.SafeMembers = append(snap.SafeMembers, safeMembers[i]...)
		skeletonAccounts = append(skeletonAccounts, safeAccounts[i]...)
	}
	if n := memberFailures.Load(); n > 0 {
		note("members could not be fetched for %d of %d safes; access granted through those safes is missing", n, len(safes))
	}
	if n := accountFailures.Load(); n > 0 {
		note("accounts could not be listed for %d of %d safes; those accounts are missing", n, len(safes))
	}
	logger.Infof("Phase 1 Complete. Found %d safe members and %d accounts (pre-filter).", len(snap.SafeMembers), len(skeletonAccounts))
	if interrupted() {
		return finish()
	}

	// --- Phase 2: Enrichment (Parallel Account Details) ---
	logger.Infof("Phase 2: Fetching details for %d accounts...", len(skeletonAccounts))

	details := make([]*models.Account, len(skeletonAccounts))
	var failedDetails, skippedDisabled, skippedArchived, processedAccounts atomic.Int64

	parallel.ForEach(ctx, skeletonAccounts, cfg.workers, func(idx int, acc models.Account) {
		if acc.ID == "" {
			return
		}

		d, err := api.GetAccountDetails(acc.ID)
		if err != nil {
			if !interrupted() {
				failedDetails.Add(1)
				logger.Warnf("Failed to get details for account %s: %v", acc.ID, err)
			}
			return
		}
		if d == nil {
			return
		}

		// Skip disabled or archived accounts
		if d.Disabled || d.Status == "Archived" {
			if d.Disabled {
				skippedDisabled.Add(1)
			}
			if d.Status == "Archived" {
				skippedArchived.Add(1)
			}
			return
		}

		details[idx] = d
		if n := processedAccounts.Add(1); n%100 == 0 {
			logger.Infof("  Fetched details for %d/%d accounts", n, len(skeletonAccounts))
		}
	})

	for _, d := range details {
		if d != nil {
			snap.Accounts = append(snap.Accounts, *d)
		}
	}
	if skippedDisabled.Load() > 0 || skippedArchived.Load() > 0 {
		logger.Warnf("Phase 2: Skipped %d disabled and %d archived accounts out of %d total.", skippedDisabled.Load(), skippedArchived.Load(), len(skeletonAccounts))
	}
	if n := failedDetails.Load(); n > 0 {
		logger.Warnf("Phase 2: Failed to retrieve details for %d out of %d accounts (API errors).", n, len(skeletonAccounts))
		note("details could not be fetched for %d of %d accounts; those accounts are missing", n, len(skeletonAccounts))
	}
	logger.Infof("Phase 2 Complete. Collected %d active accounts (discovered: %d, failed: %d, disabled: %d, archived: %d).",
		len(snap.Accounts), len(skeletonAccounts), failedDetails.Load(), skippedDisabled.Load(), skippedArchived.Load())
	if interrupted() {
		return finish()
	}

	// Fetch account activities if requested
	if cfg.includeActivity && len(snap.Accounts) > 0 {
		logger.Infof("Fetching account activities (last %d days)...", cfg.activityDays)
		activities := make([][]models.AccountActivity, len(snap.Accounts))
		var failed, processed atomic.Int64
		activityDays := cfg.activityDays

		parallel.ForEach(ctx, snap.Accounts, cfg.workers, func(idx int, acc models.Account) {
			if acc.ID == "" {
				return
			}
			acts, err := api.GetAccountActivities(acc.ID, cfg.activityLimit, &activityDays)
			if err != nil {
				if !interrupted() {
					failed.Add(1)
					logger.Warnf("Failed to get activities for account %s: %v", acc.ID, err)
				}
				return
			}
			activities[idx] = acts
			if n := processed.Add(1); n%100 == 0 {
				logger.Infof("  Fetched activities for %d/%d accounts", n, len(snap.Accounts))
			}
		})

		snap.AccountActivities = make(map[string][]models.AccountActivity)
		for i, acts := range activities {
			if len(acts) > 0 {
				snap.AccountActivities[snap.Accounts[i].ID] = acts
			}
		}
		if n := failed.Load(); n > 0 {
			note("activity could not be fetched for %d of %d accounts; their CyberArk_UsedAccount edges are missing", n, len(snap.Accounts))
		}
		logger.Infof("Collected activities for %d accounts", len(snap.AccountActivities))
	}

	return finish()
}
