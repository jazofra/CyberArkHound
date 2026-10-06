package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/internal/parallel"
	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/siemens-healthineers/cyberarkhound/pkg/snapshot"
	"github.com/sirupsen/logrus"
)

// defaultCheckpointInterval is how often collection progress is saved while
// a collection with --save-raw (or --resume) runs.
const defaultCheckpointInterval = time.Minute

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

// collectionOptions returns the options a resumed collection must reuse.
func collectionOptions(cfg *config) snapshot.Options {
	return snapshot.Options{
		LimitUsers:               cfg.limitUsers,
		LimitGroups:              cfg.limitGroups,
		LimitSafes:               cfg.limitSafes,
		TestSafe:                 cfg.testSafe,
		ActivityDays:             cfg.activityDays,
		ActivityLimit:            cfg.activityLimit,
		IncludePredefinedMembers: cfg.includePredefinedMembers,
	}
}

// errPartial marks a stage that finished with some items missing; the
// details have already been logged and noted.
var errPartial = errors.New("stage finished with missing items")

// collector gathers everything the graph is built from.
//
// It records its progress in the snapshot, so a collection that was
// interrupted or failed can be resumed from a --save-raw file: completed
// stages and items are not fetched again, and anything that failed is
// retried. With a checkpoint path set, progress is saved periodically and
// whenever the collection stops.
type collector struct {
	ctx    context.Context
	cfg    *config
	api    *client.Client
	logger *logrus.Logger

	checkpointPath     string
	checkpointInterval time.Duration

	// mu guards snap, the progress sets and the checkpoint state while
	// workers run. Only the collecting goroutine writes stages.
	mu       sync.Mutex
	snap     *snapshot.Snapshot
	stages   map[string]bool
	scanned  map[string]string // lower-cased safe name -> safe name
	detailed map[string]bool
	activity map[string]bool
	// notes are this run's reasons the collection is incomplete.
	notes      []string
	lastSave   time.Time
	saveFailed bool
	// predefinedExcludedBefore records that an earlier run of a resumed
	// collection could not collect built-in safe members.
	predefinedExcludedBefore bool
}

// newCollector starts a collection, or resumes the one in base when base is
// not nil.
func newCollector(ctx context.Context, cfg *config, api *client.Client, logger *logrus.Logger, base *snapshot.Snapshot, checkpointPath string) *collector {
	now := time.Now().UTC()
	snap := base
	if snap == nil {
		snap = &snapshot.Snapshot{
			FormatVersion: snapshot.FormatVersion,
			CollectedAt:   now,
			PVWAURL:       api.BaseURL,
			PVWATag:       pvwaTag(cfg),
			Progress:      &snapshot.Progress{Options: collectionOptions(cfg)},
		}
	} else {
		snap.Progress.ResumedAt = append(snap.Progress.ResumedAt, now)
	}

	interval := cfg.checkpointInterval
	if interval == 0 {
		interval = defaultCheckpointInterval
	}
	p := snap.Progress
	return &collector{
		ctx:                      ctx,
		cfg:                      cfg,
		api:                      api,
		logger:                   logger,
		checkpointPath:           checkpointPath,
		checkpointInterval:       interval,
		snap:                     snap,
		stages:                   toSet(p.Stages),
		scanned:                  safeNameSet(p.ScannedSafes),
		detailed:                 toSet(p.DetailedAccounts),
		activity:                 toSet(p.ActivityFetched),
		predefinedExcludedBefore: p.PredefinedMembersExcluded,
	}
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}

// safeNameSet indexes safe names case-insensitively, keeping their spelling.
func safeNameSet(names []string) map[string]string {
	set := make(map[string]string, len(names))
	for _, name := range names {
		set[strings.ToLower(name)] = name
	}
	return set
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (c *collector) interrupted() bool { return c.ctx.Err() != nil }

// note records why the collection is incomplete. Only the collecting
// goroutine calls it.
func (c *collector) note(format string, args ...interface{}) {
	c.notes = append(c.notes, fmt.Sprintf(format, args...))
}

// optional reports a failed lookup the export can do without, unless the
// failure was only the collection being interrupted.
func (c *collector) optional(err error, what, consequence string) {
	if err == nil || c.interrupted() {
		return
	}
	c.logger.Warnf("Failed to fetch %s: %v (%s)", what, err, consequence)
	c.note("%s could not be fetched (%s): %s", what, consequence, summarizeErr(err))
}

// stage runs fn unless an earlier run of this collection completed it. The
// stage is recorded as complete only if fn succeeds, the client noted no new
// gaps while it ran, and the collection was not interrupted, so a resumed
// collection retries anything that came back partial.
func (c *collector) stage(name, what string, fn func() error) error {
	if c.stages[name] {
		c.logger.Infof("Skipping %s: already collected by an earlier run", what)
		return nil
	}
	gapsBefore := len(c.api.IncompleteReasons())
	err := fn()
	if err == nil && !c.interrupted() && len(c.api.IncompleteReasons()) == gapsBefore {
		c.mu.Lock()
		c.stages[name] = true
		c.mu.Unlock()
	}
	c.checkpoint(true)
	return err
}

// checkpoint saves the collection so far, at most once per checkpoint
// interval unless force is set.
func (c *collector) checkpoint(force bool) {
	if c.checkpointPath == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && time.Since(c.lastSave) < c.checkpointInterval {
		return
	}
	c.snap.Incomplete = []string{fmt.Sprintf("the collection had not finished when this file was saved; continue it with --resume %s", c.checkpointPath)}
	c.saveLocked()
}

func (c *collector) saveLocked() {
	c.syncProgressLocked()
	if err := snapshot.Save(c.checkpointPath, c.snap); err != nil {
		if !c.saveFailed {
			c.logger.Errorf("Failed to save collection progress to %s: %v", c.checkpointPath, err)
		}
		c.saveFailed = true
		return
	}
	c.lastSave = time.Now()
}

func (c *collector) syncProgressLocked() {
	p := c.snap.Progress
	p.Stages = sortedKeys(c.stages)
	p.ScannedSafes = make([]string, 0, len(c.scanned))
	for _, name := range c.scanned {
		p.ScannedSafes = append(p.ScannedSafes, name)
	}
	sort.Strings(p.ScannedSafes)
	p.DetailedAccounts = sortedKeys(c.detailed)
	p.ActivityFetched = sortedKeys(c.activity)
	p.PredefinedMembersExcluded = c.predefinedExcludedBefore || c.api.PredefinedMembersExcluded()
}

// run performs (or continues) the collection. It returns an error only when
// the collection cannot produce a usable result; even then the progress so
// far is saved to the checkpoint path.
func (c *collector) run() (*snapshot.Snapshot, error) {
	err := c.collect()
	c.finish(err)
	return c.snap, err
}

func (c *collector) collect() error {
	logger, api, cfg := c.logger, c.api, c.cfg

	if err := c.stage(snapshot.StageUsers, "users", func() error {
		logger.Info("Fetching users...")
		users, err := api.ListUsers(limitPtr(cfg.limitUsers))
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.snap.Users = users
		c.mu.Unlock()
		return nil
	}); err != nil {
		if c.interrupted() {
			return nil
		}
		return fmt.Errorf("failed to fetch users: %w", err)
	}
	if c.interrupted() {
		return nil
	}

	if err := c.stage(snapshot.StageGroups, "groups", func() error {
		logger.Info("Fetching groups...")
		groups, err := api.ListGroups(limitPtr(cfg.limitGroups), cfg.workers)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.snap.Groups = groups
		c.mu.Unlock()
		return nil
	}); err != nil {
		if c.interrupted() {
			return nil
		}
		return fmt.Errorf("failed to fetch groups: %w", err)
	}
	if c.interrupted() {
		return nil
	}

	var testSafe *string
	if cfg.testSafe != "" {
		testSafe = &cfg.testSafe
	}
	if err := c.stage(snapshot.StageSafes, "safes", func() error {
		logger.Info("Fetching safes...")
		if testSafe != nil {
			logger.Infof("Searching for safe: %s", cfg.testSafe)
		}
		// ListSafes returns whatever it collected before failing, so a run
		// that dies on a single bad page does not throw away hours of
		// collection. A shorter partial list must not replace a longer one
		// from an earlier run of a resumed collection.
		safes, err := api.ListSafes(limitPtr(cfg.limitSafes), testSafe)
		c.mu.Lock()
		if err == nil || len(safes) > len(c.snap.Safes) {
			c.snap.Safes = safes
		}
		c.mu.Unlock()
		return err
	}); err != nil {
		switch {
		case c.interrupted():
			return nil
		case !cfg.continueOnError || len(c.snap.Safes) == 0:
			return fmt.Errorf("failed to fetch safes: %w", err)
		}
		logger.Errorf("Failed to fetch safes: %v", err)
		logger.Warnf("Continuing with the %d safes collected before the failure (disable with --continue-on-error=false)", len(c.snap.Safes))
		c.note("safe enumeration stopped early after %d safes: %s", len(c.snap.Safes), summarizeErr(err))
	}
	if testSafe != nil {
		if len(c.snap.Safes) == 0 {
			return fmt.Errorf("no safes found matching '%s'", cfg.testSafe)
		}
		logger.Infof("Found %d safes matching '%s'", len(c.snap.Safes), cfg.testSafe)
	}

	if cfg.includePlatforms && !c.interrupted() {
		_ = c.stage(snapshot.StagePlatforms, "platforms", c.collectPlatforms)
	}
	if cfg.includePSM && !c.interrupted() {
		_ = c.stage(snapshot.StagePSM, "PSM servers and connection components", c.collectPSM)
	}
	// Tradecraft reference: Marat Nigmatullin (FalconForce), SO-CON 2026 —
	// "4 GET requests = 3 Domain admins: CyberArk magic you didn't know about".
	if cfg.includeApplications && !c.interrupted() {
		_ = c.stage(snapshot.StageApplications, "applications", func() error {
			logger.Info("Fetching applications (CCP/AIMWebService AppIDs)...")
			applications, err := api.ListApplicationsWithAuth(cfg.workers)
			c.optional(err, "applications", "CCP mapping will be omitted; the collector user may lack the 'Manage Users' authorization")
			c.mu.Lock()
			c.snap.Applications = applications
			c.mu.Unlock()
			return err
		})
	}
	if c.interrupted() {
		return nil
	}

	_ = c.stage(snapshot.StageSafeContents, "safe members and accounts", c.collectSafeContents)
	if c.interrupted() {
		return nil
	}
	_ = c.stage(snapshot.StageAccountDetails, "account details", c.collectAccountDetails)
	if c.interrupted() {
		return nil
	}
	if cfg.includeActivity {
		_ = c.stage(snapshot.StageActivity, "account activity", c.collectActivity)
	}
	return nil
}

func (c *collector) collectPlatforms() error {
	logger, api := c.logger, c.api
	var failed error

	logger.Info("Fetching platforms...")
	platforms, err := api.ListPlatforms()
	c.optional(err, "platforms", "platform details will be limited to the Targets data")
	if err != nil {
		failed = err
	}

	// Fetch PSM connection components per platform
	var connectors map[string][]string
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
		connectors = api.GetAllPlatformPSMConnectors(platformIDs, c.cfg.workers)
		logger.Infof("Fetched PSM connectors for %d platforms", len(connectors))
	}

	// Fetch target platform data for Master Policy exception flags
	logger.Info("Fetching platform exception data...")
	targets, err := api.ListTargetPlatforms()
	c.optional(err, "target platform data", "Master Policy exception flags will be omitted")
	if err != nil {
		failed = err
	}

	c.mu.Lock()
	c.snap.Platforms = platforms
	c.snap.PlatformConnectors = connectors
	c.snap.TargetPlatforms = targets
	c.mu.Unlock()
	return failed
}

func (c *collector) collectPSM() error {
	logger, api := c.logger, c.api
	var failed error

	logger.Info("Fetching PSM servers...")
	servers, err := api.ListPSMServers()
	c.optional(err, "PSM servers", "PSM server nodes will be missing")
	if err != nil {
		failed = err
	}

	logger.Info("Fetching connection components...")
	components, err := api.ListConnectionComponents()
	c.optional(err, "connection components", "connection component nodes will be missing")
	if err != nil {
		failed = err
	}

	c.mu.Lock()
	c.snap.PSMServers = servers
	c.snap.ConnectionComponents = components
	c.mu.Unlock()
	return failed
}

// collectSafeContents lists the members and accounts of every safe not yet
// scanned (Phase 1).
func (c *collector) collectSafeContents() error {
	var pending []models.Safe
	for _, safe := range c.snap.Safes {
		if _, done := c.scanned[strings.ToLower(safe.SafeName)]; !done {
			pending = append(pending, safe)
		}
	}
	total := len(c.snap.Safes)
	c.logger.Infof("Phase 1: Discovering members and accounts for %d safes (%d already done)...", len(pending), total-len(pending))

	var memberFailures, accountFailures, processed atomic.Int64
	parallel.ForEach(c.ctx, pending, c.cfg.workers, func(_ int, safe models.Safe) {
		if n := processed.Add(1); n%10 == 0 || int(n) == len(pending) {
			c.logger.Infof("Processing safe %d/%d: '%s'", n, len(pending), safe.SafeName)
		}

		members, membersErr := c.api.ListSafeMembers(safe.SafeName, safe.SafeUrlId)
		if membersErr != nil && !c.interrupted() {
			memberFailures.Add(1)
			c.logger.Warnf("Failed to fetch members for safe '%s': %v", safe.SafeName, membersErr)
		}
		accounts, accountsErr := c.api.ListAccounts(safe.SafeName)
		if accountsErr != nil && !c.interrupted() {
			accountFailures.Add(1)
			c.logger.Warnf("Failed to fetch accounts for safe '%s': %v", safe.SafeName, accountsErr)
		}

		c.recordSafe(safe.SafeName, members, membersErr == nil, accounts, accountsErr == nil)
		c.checkpoint(false)
	})

	c.mu.Lock()
	memberCount, accountCount := len(c.snap.SafeMembers), len(c.snap.Progress.DiscoveredAccounts)
	c.mu.Unlock()
	c.logger.Infof("Phase 1 Complete. Found %d safe members and %d accounts (pre-filter).", memberCount, accountCount)

	if n := memberFailures.Load(); n > 0 {
		c.note("members could not be fetched for %d of %d safes; access granted through those safes is missing", n, total)
	}
	if n := accountFailures.Load(); n > 0 {
		c.note("accounts could not be listed for %d of %d safes; those accounts are missing", n, total)
	}
	if memberFailures.Load()+accountFailures.Load() > 0 {
		return errPartial
	}
	return nil
}

// recordSafe stores what was fetched for one safe, replacing whatever an
// earlier attempt recorded for the parts fetched now. The safe counts as
// scanned only when both its members and its accounts were fetched.
func (c *collector) recordSafe(safeName string, members []models.SafeMember, membersOK bool, accounts []models.Account, accountsOK bool) {
	key := strings.ToLower(safeName)
	c.mu.Lock()
	defer c.mu.Unlock()

	if membersOK {
		c.snap.SafeMembers = removeWhere(c.snap.SafeMembers, func(m models.SafeMember) bool {
			return strings.ToLower(m.SafeName) == key
		})
		for _, m := range members {
			if m.SafeName == "" {
				m.SafeName = safeName
			}
			c.snap.SafeMembers = append(c.snap.SafeMembers, m)
		}
	}
	if accountsOK {
		p := c.snap.Progress
		p.DiscoveredAccounts = removeWhere(p.DiscoveredAccounts, func(a snapshot.AccountRef) bool {
			return strings.ToLower(a.SafeName) == key
		})
		for _, a := range accounts {
			if a.ID != "" {
				p.DiscoveredAccounts = append(p.DiscoveredAccounts, snapshot.AccountRef{ID: a.ID, SafeName: safeName})
			}
		}
	}
	if membersOK && accountsOK {
		c.scanned[key] = safeName
	}
}

// removeWhere filters s in place, keeping the elements drop rejects.
func removeWhere[T any](s []T, drop func(T) bool) []T {
	kept := s[:0]
	for _, v := range s {
		if !drop(v) {
			kept = append(kept, v)
		}
	}
	return kept
}

// collectAccountDetails fetches the details of every discovered account not
// yet detailed (Phase 2).
func (c *collector) collectAccountDetails() error {
	var pending []snapshot.AccountRef
	for _, ref := range c.snap.Progress.DiscoveredAccounts {
		if !c.detailed[ref.ID] {
			pending = append(pending, ref)
		}
	}
	total := len(c.snap.Progress.DiscoveredAccounts)
	c.logger.Infof("Phase 2: Fetching details for %d accounts (%d already done)...", len(pending), total-len(pending))

	var failed, disabled, archived, processed atomic.Int64
	parallel.ForEach(c.ctx, pending, c.cfg.workers, func(_ int, ref snapshot.AccountRef) {
		d, err := c.api.GetAccountDetails(ref.ID)
		if err != nil {
			if !c.interrupted() {
				failed.Add(1)
				c.logger.Warnf("Failed to get details for account %s: %v", ref.ID, err)
			}
			return
		}

		// Skip disabled or archived accounts; a nil result means the account
		// no longer exists. Either way its details stage is done.
		keep := d != nil && !d.Disabled && d.Status != "Archived"
		if d != nil && d.Disabled {
			disabled.Add(1)
		}
		if d != nil && d.Status == "Archived" {
			archived.Add(1)
		}

		c.mu.Lock()
		if keep {
			c.snap.Accounts = append(c.snap.Accounts, *d)
		}
		c.detailed[ref.ID] = true
		c.mu.Unlock()

		if n := processed.Add(1); n%100 == 0 {
			c.logger.Infof("  Fetched details for %d/%d accounts", n, len(pending))
		}
		c.checkpoint(false)
	})

	if disabled.Load() > 0 || archived.Load() > 0 {
		c.logger.Warnf("Phase 2: Skipped %d disabled and %d archived accounts out of %d total.", disabled.Load(), archived.Load(), len(pending))
	}
	c.mu.Lock()
	accountCount := len(c.snap.Accounts)
	c.mu.Unlock()
	c.logger.Infof("Phase 2 Complete. Collected %d active accounts (fetched now: %d, failed: %d, disabled: %d, archived: %d).",
		accountCount, len(pending), failed.Load(), disabled.Load(), archived.Load())

	if n := failed.Load(); n > 0 {
		c.note("details could not be fetched for %d of %d accounts; those accounts are missing", n, total)
		return errPartial
	}
	return nil
}

// collectActivity fetches the activity of every collected account whose
// activity was not fetched yet.
func (c *collector) collectActivity() error {
	var pending []string
	for _, acc := range c.snap.Accounts {
		if acc.ID != "" && !c.activity[acc.ID] {
			pending = append(pending, acc.ID)
		}
	}
	total := len(c.snap.Accounts)
	c.logger.Infof("Fetching account activities (last %d days) for %d accounts (%d already done)...", c.cfg.activityDays, len(pending), total-len(pending))

	activityDays := c.cfg.activityDays
	var failed, processed atomic.Int64
	parallel.ForEach(c.ctx, pending, c.cfg.workers, func(_ int, id string) {
		acts, err := c.api.GetAccountActivities(id, c.cfg.activityLimit, &activityDays)
		if err != nil {
			if !c.interrupted() {
				failed.Add(1)
				c.logger.Warnf("Failed to get activities for account %s: %v", id, err)
			}
			return
		}

		c.mu.Lock()
		if len(acts) > 0 {
			if c.snap.AccountActivities == nil {
				c.snap.AccountActivities = make(map[string][]models.AccountActivity)
			}
			c.snap.AccountActivities[id] = acts
		}
		c.activity[id] = true
		c.mu.Unlock()

		if n := processed.Add(1); n%100 == 0 {
			c.logger.Infof("  Fetched activities for %d/%d accounts", n, len(pending))
		}
		c.checkpoint(false)
	})

	c.logger.Infof("Collected activities for %d accounts", len(c.snap.AccountActivities))
	if n := failed.Load(); n > 0 {
		c.note("activity could not be fetched for %d of %d accounts; their CyberArk_UsedAccount edges are missing", n, total)
		return errPartial
	}
	return nil
}

// finish puts the collected data into a deterministic order, records why it
// is incomplete, and saves it to the checkpoint path.
func (c *collector) finish(fatal error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.normalizeLocked()

	var reasons []string
	switch {
	case fatal != nil:
		reasons = append(reasons, "the collection failed: "+summarizeErr(fatal))
	case c.interrupted():
		reasons = append(reasons, "the collection was interrupted before it finished")
	}
	reasons = append(reasons, c.notes...)
	reasons = append(reasons, c.api.IncompleteReasons()...)
	if c.predefinedExcludedBefore && !c.api.PredefinedMembersExcluded() {
		reasons = append(reasons, "built-in safe members (Master, Vault Admins, Auditors, ...) are missing from safes listed by an earlier run: PVWA rejected the includePredefinedUsers filter")
	}
	c.snap.Incomplete = reasons

	if c.checkpointPath == "" {
		return
	}
	c.saveLocked()
	switch {
	case c.saveFailed:
		c.logger.Errorf("The collection could not be saved to %s", c.checkpointPath)
	case fatal != nil || c.interrupted():
		c.logger.Warnf("Collection progress saved to %s; continue it with --resume %s", c.checkpointPath, c.checkpointPath)
	default:
		c.logger.Infof("Saved raw collection to %s", c.checkpointPath)
	}
}

// normalizeLocked orders the collected data as an uninterrupted collection
// would have — safe members and discovered accounts by safe, accounts by
// discovery order — and drops data of safes that are no longer listed (a
// resumed collection may have re-listed the safes). A resumed collection
// therefore exports exactly what a single run would have.
func (c *collector) normalizeLocked() {
	safeIndex := make(map[string]int, len(c.snap.Safes))
	for i, s := range c.snap.Safes {
		key := strings.ToLower(s.SafeName)
		if _, dup := safeIndex[key]; !dup {
			safeIndex[key] = i
		}
	}
	listed := func(safeName string) (int, bool) {
		i, ok := safeIndex[strings.ToLower(safeName)]
		return i, ok
	}

	members := removeWhere(c.snap.SafeMembers, func(m models.SafeMember) bool {
		_, ok := listed(m.SafeName)
		return !ok
	})
	sort.SliceStable(members, func(i, j int) bool {
		a, _ := listed(members[i].SafeName)
		b, _ := listed(members[j].SafeName)
		return a < b
	})
	c.snap.SafeMembers = members

	p := c.snap.Progress
	discovered := removeWhere(p.DiscoveredAccounts, func(a snapshot.AccountRef) bool {
		_, ok := listed(a.SafeName)
		return !ok
	})
	sort.SliceStable(discovered, func(i, j int) bool {
		a, _ := listed(discovered[i].SafeName)
		b, _ := listed(discovered[j].SafeName)
		return a < b
	})
	p.DiscoveredAccounts = discovered

	discoveredIndex := make(map[string]int, len(discovered))
	for i, a := range discovered {
		if _, dup := discoveredIndex[a.ID]; !dup {
			discoveredIndex[a.ID] = i
		}
	}
	accounts := removeWhere(c.snap.Accounts, func(a models.Account) bool {
		_, ok := discoveredIndex[a.ID]
		return !ok
	})
	sort.SliceStable(accounts, func(i, j int) bool {
		return discoveredIndex[accounts[i].ID] < discoveredIndex[accounts[j].ID]
	})
	c.snap.Accounts = accounts

	collected := make(map[string]bool, len(accounts))
	for _, a := range accounts {
		collected[a.ID] = true
	}
	for id := range c.snap.AccountActivities {
		if !collected[id] {
			delete(c.snap.AccountActivities, id)
		}
	}
	for key := range c.scanned {
		if _, ok := safeIndex[key]; !ok {
			delete(c.scanned, key)
		}
	}
	for id := range c.detailed {
		if _, ok := discoveredIndex[id]; !ok {
			delete(c.detailed, id)
		}
	}
	for id := range c.activity {
		if !collected[id] {
			delete(c.activity, id)
		}
	}
}
