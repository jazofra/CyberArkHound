package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/siemens-healthineers/cyberarkhound/pkg/exporter"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

func main() {
	// Define command-line flags
	pvwaURL := pflag.String("pvwa", "", "PVWA base URL (required)")
	username := pflag.String("username", "", "API username (required)")
	password := pflag.String("password", "", "API password (required)")
	outputFile := pflag.String("output", "", "Output JSON file (required)")
	targetDomains := pflag.StringSlice("target-domains", []string{}, "Target AD domain(s) for SyncsToADUser edges (required)")
	parseSAMAccountName := pflag.Bool("parse-samaccountname", false, "Parse sAMAccountName/GID from LDAP distinguishedName CN for SyncsToCyberArkUser edges (optional)")

	workers := pflag.Int("workers", 50, "Concurrent workers for account detail retrieval")

	quiet := pflag.Bool("quiet", false, "Suppress verbose logs")
	insecure := pflag.Bool("insecure", false, "Disable SSL verification (insecure)")
	caBundle := pflag.String("ca-bundle", "", "Path to CA bundle file")
	debug := pflag.Bool("debug", false, "Enable debug logging")
	logLevel := pflag.String("log-level", "INFO", "Set logging level: DEBUG, INFO, WARNING, ERROR")
	requestTimeout := pflag.Duration("request-timeout", 360*time.Second, "HTTP request timeout (e.g. 10m, 600s)")
	authTimeout := pflag.Duration("auth-timeout", 360*time.Second, "Authentication timeout (e.g. 2m, 120s)")
	safePageLimit := pflag.Int("safe-page-limit", client.SafePageLimit, "Safes page size for /API/safes pagination (lower can help slow PVWA)")

	// Activity tracking flags
	includeActivity := pflag.Bool("include-activity", false, "Include account activity data (creates CyberArkUsedAccount edges)")
	activityDays := pflag.Int("activity-days", 3, "Number of days to look back for activity")
	activityLimit := pflag.Int("activity-limit", 100, "Max activities per account")

	// Linked accounts and platforms flags
	includeLinkedAccounts := pflag.Bool("include-linked-accounts", false, "Include linked account data (creates CyberArkLinkedTo edges for logon/reconcile/enable chains)")
	includePlatforms := pflag.Bool("include-platforms", false, "Include platform data (creates CyberArkPlatform nodes and CyberArkUsesPlatform edges)")

	// Testing limits
	limitUsers := pflag.Int("limit-users", 0, "Limit number of users (0 = no limit)")
	limitGroups := pflag.Int("limit-groups", 0, "Limit number of groups (0 = no limit)")
	limitSafes := pflag.Int("limit-safes", 0, "Limit number of safes (0 = no limit)")
	testSafe := pflag.String("test-safe", "", "Fetch single safe by search term")

	pflag.Parse()

	// Handle leftover arguments as target domains (supports space-separated domains)
	if len(pflag.Args()) > 0 {
		*targetDomains = append(*targetDomains, pflag.Args()...)
	}

	// Validate required flags
	if *pvwaURL == "" || *username == "" || *password == "" || *outputFile == "" || len(*targetDomains) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Missing required flags\n\n")
		fmt.Fprintf(os.Stderr, "Usage: cyberarkhound [OPTIONS]\n\n")
		fmt.Fprintf(os.Stderr, "Required flags:\n")
		fmt.Fprintf(os.Stderr, "  --pvwa string              PVWA base URL\n")
		fmt.Fprintf(os.Stderr, "  --username string          API username\n")
		fmt.Fprintf(os.Stderr, "  --password string          API password\n")
		fmt.Fprintf(os.Stderr, "  --output string            Output JSON file\n")
		fmt.Fprintf(os.Stderr, "  --target-domains strings   Target AD domains (comma-separated or space-separated)\n\n")
		pflag.PrintDefaults()
		os.Exit(1)
	}

	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Set log level
	level := logrus.InfoLevel
	if *debug {
		level = logrus.DebugLevel
	} else {
		switch *logLevel {
		case "DEBUG":
			level = logrus.DebugLevel
		case "INFO":
			level = logrus.InfoLevel
		case "WARNING":
			level = logrus.WarnLevel
		case "ERROR":
			level = logrus.ErrorLevel
		}
	}
	logger.SetLevel(level)

	if *quiet && !*debug {
		logger.SetLevel(logrus.WarnLevel)
	}

	pvwaTag := graph.PVWATagFromArg(*pvwaURL)
	logger.Infof("PVWA tag: %s", pvwaTag)

	// Create CyberArk client
	apiClient := client.NewClient(*pvwaURL, *username, *password, *insecure, *caBundle, logger)
	apiClient.ReqTimeout = *requestTimeout
	apiClient.AuthTimeout = *authTimeout
	apiClient.SafePageLimit = *safePageLimit
	apiClient.HTTPClient.Timeout = apiClient.ReqTimeout

	// Authenticate
	logger.Info("Authenticating to CyberArk PVWA...")
	if err := apiClient.Authenticate(); err != nil {
		logger.Fatalf("Authentication failed: %v", err)
	}

	logger.Infof("Target domains: %s", *targetDomains)
	if *parseSAMAccountName {
		logger.Info("Enabled: parse sAMAccountName from distinguishedName CN for SyncsToCyberArkUser edges")
	}

	// Fetch users
	logger.Info("Fetching users...")
	var limitUsersPtr *int
	if *limitUsers > 0 {
		limitUsersPtr = limitUsers
	}
	users, err := apiClient.ListUsers(limitUsersPtr)
	if err != nil {
		logger.Fatalf("Failed to fetch users: %v", err)
	}

	// Fetch groups
	logger.Info("Fetching groups...")
	var limitGroupsPtr *int
	if *limitGroups > 0 {
		limitGroupsPtr = limitGroups
	}
	groups, err := apiClient.ListGroups(limitGroupsPtr, *workers)
	if err != nil {
		logger.Fatalf("Failed to fetch groups: %v", err)
	}

	// Fetch safes
	logger.Info("Fetching safes...")
	var limitSafesPtr *int
	if *limitSafes > 0 {
		limitSafesPtr = limitSafes
	}
	var testSafePtr *string
	if *testSafe != "" {
		testSafePtr = testSafe
		logger.Infof("Searching for safe: %s", *testSafe)
	}

	safes, err := apiClient.ListSafes(limitSafesPtr, testSafePtr)
	if err != nil {
		logger.Fatalf("Failed to fetch safes: %v", err)
	}

	if testSafePtr != nil && len(safes) == 0 {
		logger.Fatalf("No safes found matching '%s'", *testSafe)
	}
	if testSafePtr != nil {
		logger.Infof("Found %d safes matching '%s'", len(safes), *testSafe)
	}

	// Fetch platforms if requested
	var platforms []models.Platform
	if *includePlatforms {
		logger.Info("Fetching platforms...")
		platforms, err = apiClient.ListPlatforms()
		if err != nil {
			logger.Warnf("Failed to fetch platforms: %v", err)
			platforms = []models.Platform{}
		}
	}

	// --- Phase 1: Discovery (Parallel Safe Processing) ---
	logger.Infof("Phase 1: Discovering members and accounts for %d safes...", len(safes))

	var safeMembers []models.SafeMember
	var skeletonAccounts []models.Account
	var memberMu sync.Mutex
	var accountMu sync.Mutex

	safeSemaphore := make(chan struct{}, *workers)
	var safeWg sync.WaitGroup

	for idx, safe := range safes {
		safeWg.Add(1)
		go func(idx int, safe models.Safe) {
			defer safeWg.Done()
			safeSemaphore <- struct{}{}        // Acquire
			defer func() { <-safeSemaphore }() // Release

			// Progress logging (roughly every 10 safes or if few safes)
			if (idx+1)%10 == 0 || idx+1 == len(safes) {
				logger.Infof("Processing safe %d/%d: '%s'", idx+1, len(safes), safe.SafeName)
			}

			// Fetch safe members
			members, err := apiClient.ListSafeMembers(safe.SafeName, safe.SafeUrlId)
			if err != nil {
				logger.Warnf("Failed to fetch members for safe '%s': %v", safe.SafeName, err)
			} else {
				memberMu.Lock()
				safeMembers = append(safeMembers, members...)
				memberMu.Unlock()
			}

			// Fetch accounts list (skeleton)
			safeAccounts, err := apiClient.ListAccounts(safe.SafeName, safe.SafeUrlId)
			if err != nil {
				logger.Warnf("Failed to fetch accounts for safe '%s': %v", safe.SafeName, err)
			} else if len(safeAccounts) > 0 {
				accountMu.Lock()
				skeletonAccounts = append(skeletonAccounts, safeAccounts...)
				accountMu.Unlock()
			}
		}(idx, safe)
	}

	safeWg.Wait()
	logger.Infof("Phase 1 Complete. Found %d safe members and %d accounts (pre-filter).", len(safeMembers), len(skeletonAccounts))

	// --- Phase 2: Enrichment (Parallel Account Details) ---
	logger.Infof("Phase 2: Fetching details for %d accounts...", len(skeletonAccounts))

	var accounts []models.Account
	var accountsMu sync.Mutex

	// Reset processed count for logging
	processedAccounts := 0
	var processedMu sync.Mutex

	accountSemaphore := make(chan struct{}, *workers)
	var accountWg sync.WaitGroup

	for _, acc := range skeletonAccounts {
		accountWg.Add(1)
		go func(acc models.Account) {
			defer accountWg.Done()
			accountSemaphore <- struct{}{}        // Acquire
			defer func() { <-accountSemaphore }() // Release

			accountID := acc.ID
			if accountID == "" {
				return
			}

			details, err := apiClient.GetAccountDetails(accountID)
			if err != nil {
				logger.Warnf("Failed to get details for account %s: %v", accountID, err)
				return
			}

			if details == nil {
				return
			}

			// Skip disabled or archived accounts
			if details.Disabled || details.Status == "Archived" {
				return
			}

			accountsMu.Lock()
			accounts = append(accounts, *details)
			accountsMu.Unlock()

			processedMu.Lock()
			processedAccounts++
			if processedAccounts%100 == 0 {
				logger.Infof("  Fetched details for %d/%d accounts", processedAccounts, len(skeletonAccounts))
			}
			processedMu.Unlock()

		}(acc)
	}

	accountWg.Wait()
	logger.Infof("Phase 2 Complete. Collected %d active accounts.", len(accounts))

	// Fetch account activities if requested
	var accountActivities map[string][]models.AccountActivity
	if *includeActivity && len(accounts) > 0 {
		logger.Infof("Fetching account activities (last %d days)...", *activityDays)
		accountActivities = make(map[string][]models.AccountActivity)

		activitiesChan := make(chan struct {
			accountID  string
			activities []models.AccountActivity
		}, len(accounts))

		var wg sync.WaitGroup
		semaphore := make(chan struct{}, *workers)
		processedCount := 0
		var mu sync.Mutex

		for _, acc := range accounts {
			wg.Add(1)
			go func(acc models.Account) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire
				defer func() { <-semaphore }() // Release

				accountID := acc.ID
				if accountID == "" {
					return
				}

				activities, err := apiClient.GetAccountActivities(accountID, *activityLimit, activityDays)
				if err != nil {
					logger.Warnf("Failed to get activities for account %s: %v", accountID, err)
					return
				}

				if len(activities) > 0 {
					activitiesChan <- struct {
						accountID  string
						activities []models.AccountActivity
					}{accountID, activities}
				}

				mu.Lock()
				processedCount++
				if processedCount%100 == 0 {
					logger.Infof("  Fetched activities for %d/%d accounts", processedCount, len(accounts))
				}
				mu.Unlock()
			}(acc)
		}

		// Wait for all goroutines to complete
		wg.Wait()
		close(activitiesChan)

		// Collect results
		for result := range activitiesChan {
			accountActivities[result.accountID] = result.activities
		}

		logger.Infof("Collected activities for %d accounts", len(accountActivities))
	}

	// Fetch linked accounts if requested
	var linkedAccounts map[string][]models.LinkedAccount
	if *includeLinkedAccounts && len(accounts) > 0 {
		logger.Infof("Fetching linked accounts for %d accounts...", len(accounts))
		linkedAccounts = make(map[string][]models.LinkedAccount)

		linkedChan := make(chan struct {
			accountID string
			linked    []models.LinkedAccount
		}, len(accounts))

		var linkedWg sync.WaitGroup
		linkedSemaphore := make(chan struct{}, *workers)
		linkedProcessed := 0
		var linkedMu sync.Mutex

		for _, acc := range accounts {
			linkedWg.Add(1)
			go func(acc models.Account) {
				defer linkedWg.Done()
				linkedSemaphore <- struct{}{}        // Acquire
				defer func() { <-linkedSemaphore }() // Release

				accountID := acc.ID
				if accountID == "" {
					return
				}

				linked, err := apiClient.GetLinkedAccounts(accountID)
				if err != nil {
					logger.Warnf("Failed to get linked accounts for %s: %v", accountID, err)
					return
				}

				if len(linked) > 0 {
					linkedChan <- struct {
						accountID string
						linked    []models.LinkedAccount
					}{accountID, linked}
				}

				linkedMu.Lock()
				linkedProcessed++
				if linkedProcessed%100 == 0 {
					logger.Infof("  Fetched linked accounts for %d/%d accounts", linkedProcessed, len(accounts))
				}
				linkedMu.Unlock()
			}(acc)
		}

		linkedWg.Wait()
		close(linkedChan)

		for result := range linkedChan {
			linkedAccounts[result.accountID] = result.linked
		}

		logger.Infof("Collected linked accounts for %d accounts", len(linkedAccounts))
	}

	// Build OpenGraph
	logger.Info("Building OpenGraph...")
	og, err := graph.BuildOpenGraph(
		users,
		groups,
		safes,
		safeMembers,
		accounts,
		*targetDomains,
		*parseSAMAccountName,
		pvwaTag,
		accountActivities,
		platforms,
		linkedAccounts,
		logger,
		*debug,
		*logLevel,
	)
	if err != nil {
		logger.Fatalf("Failed to build OpenGraph: %v", err)
	}

	// Export to BloodHound JSON
	logger.Info("Exporting to BloodHound JSON...")
	if err := exporter.ExportToBloodHoundJSON(og, *outputFile, logger, *debug, *logLevel); err != nil {
		logger.Fatalf("Failed to export: %v", err)
	}

	// Logoff
	if err := apiClient.Logoff(); err != nil {
		logger.Warnf("Logoff failed: %v", err)
	}

	logger.Info("Export completed successfully!")

	// Print summary statistics
	summary := og.GetSummary()
	logger.Info("=== Collection Summary ===")
	logger.Infof("Total Nodes: %d", summary["total_nodes"])

	if nodeCounts, ok := summary["nodes_by_kind"].(map[string]int); ok {
		logger.Info("Nodes by Type:")
		for kind, count := range nodeCounts {
			logger.Infof("  %s: %d", kind, count)
		}
	}

	logger.Infof("Total Internal Edges: %d", summary["total_internal_edges"])
	if edgeCounts, ok := summary["internal_edges_by_kind"].(map[string]int); ok && len(edgeCounts) > 0 {
		logger.Info("Internal Edges by Type:")
		for kind, count := range edgeCounts {
			logger.Infof("  %s: %d", kind, count)
		}
	}

	logger.Infof("Total External Edges: %d", summary["total_external_edges"])
	if edgeCounts, ok := summary["external_edges_by_kind"].(map[string]int); ok && len(edgeCounts) > 0 {
		logger.Info("External Edges by Type:")
		for kind, count := range edgeCounts {
			logger.Infof("  %s: %d", kind, count)
		}
	}

	logger.Infof("Memory stats: Alloc=%dMB Sys=%dMB NumGC=%d",
		getMemStats().Alloc/1024/1024,
		getMemStats().Sys/1024/1024,
		getMemStats().NumGC)
}

func getMemStats() *runtime.MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return &m
}
