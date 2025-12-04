package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/siemens-healthineers/cyberarkhound/pkg/exporter"
	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
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

	workers := pflag.Int("workers", 50, "Concurrent workers for account detail retrieval")

	quiet := pflag.Bool("quiet", false, "Suppress verbose logs")
	insecure := pflag.Bool("insecure", false, "Disable SSL verification (insecure)")
	caBundle := pflag.String("ca-bundle", "", "Path to CA bundle file")
	debug := pflag.Bool("debug", false, "Enable debug logging")
	logLevel := pflag.String("log-level", "INFO", "Set logging level: DEBUG, INFO, WARNING, ERROR")

	// Activity tracking flags
	includeActivity := pflag.Bool("include-activity", false, "Include account activity data (creates CyberArkUsedAccount edges)")
	activityDays := pflag.Int("activity-days", 3, "Number of days to look back for activity")
	activityLimit := pflag.Int("activity-limit", 100, "Max activities per account")

	// Testing limits
	limitUsers := pflag.Int("limit-users", 0, "Limit number of users (0 = no limit)")
	limitGroups := pflag.Int("limit-groups", 0, "Limit number of groups (0 = no limit)")
	limitSafes := pflag.Int("limit-safes", 0, "Limit number of safes (0 = no limit)")
	testSafe := pflag.String("test-safe", "", "Fetch single safe by search term")

	pflag.Parse()

	// Validate required flags
	if *pvwaURL == "" || *username == "" || *password == "" || *outputFile == "" || len(*targetDomains) == 0 {
		fmt.Fprintf(os.Stderr, "Error: Missing required flags\n\n")
		fmt.Fprintf(os.Stderr, "Usage: cyberarkhound [OPTIONS]\n\n")
		fmt.Fprintf(os.Stderr, "Required flags:\n")
		fmt.Fprintf(os.Stderr, "  --pvwa string              PVWA base URL\n")
		fmt.Fprintf(os.Stderr, "  --username string          API username\n")
		fmt.Fprintf(os.Stderr, "  --password string          API password\n")
		fmt.Fprintf(os.Stderr, "  --output string            Output JSON file\n")
		fmt.Fprintf(os.Stderr, "  --target-domains strings   Target AD domains (comma-separated)\n\n")
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

	// Create CyberArk client
	apiClient := client.NewClient(*pvwaURL, *username, *password, *insecure, *caBundle, logger)

	// Authenticate
	logger.Info("Authenticating to CyberArk PVWA...")
	if err := apiClient.Authenticate(); err != nil {
		logger.Fatalf("Authentication failed: %v", err)
	}

	logger.Infof("Target domains: %s", *targetDomains)

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
	groups, err := apiClient.ListGroups(limitGroupsPtr)
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

	// Fetch safe members and accounts
	var safeMembers []map[string]interface{}
	var accounts []map[string]interface{}

	for idx, safe := range safes {
		safeName := graph.GetString(safe, "safeName", "")
		safeURLID := graph.GetString(safe, "safeUrlId", "")
		logger.Infof("Processing safe %d/%d: '%s'", idx+1, len(safes), safeName)

		// Fetch safe members
		members, err := apiClient.ListSafeMembers(safeName, safeURLID)
		if err != nil {
			logger.Warnf("Failed to fetch members for safe '%s': %v", safeName, err)
			continue
		}

		// Fix member structure to match Python version (uppercase keys)
		for _, member := range members {
			// Add uppercase versions of keys for compatibility
			if memberName := graph.GetString(member, "memberName", ""); memberName != "" {
				member["MemberName"] = memberName
			}
			if memberType := graph.GetString(member, "memberType", ""); memberType != "" {
				member["MemberType"] = memberType
			}
			member["SafeName"] = safeName
			member["SafeUrlId"] = safeURLID
			if perms, ok := member["permissions"].(map[string]interface{}); ok {
				member["Permissions"] = perms
			}
		}

		safeMembers = append(safeMembers, members...)

		// Fetch accounts in this safe
		safeAccounts, err := apiClient.ListAccounts(safeName, safeURLID)
		if err != nil {
			logger.Warnf("Failed to fetch accounts for safe '%s': %v", safeName, err)
			continue
		}

		if len(safeAccounts) == 0 {
			logger.Infof("No accounts in safe '%s'", safeName)
			continue
		}

		// Fetch detailed info for each account in parallel
		logger.Infof("Fetching details for %d accounts in safe '%s'...", len(safeAccounts), safeName)

		accountsChan := make(chan map[string]interface{}, len(safeAccounts))
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, *workers)

		for _, acc := range safeAccounts {
			wg.Add(1)
			go func(acc map[string]interface{}) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire
				defer func() { <-semaphore }() // Release

				accountID := graph.GetString(acc, "id", "")
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
				if graph.GetBool(details, "disabled", false) || graph.GetString(details, "status", "") == "Archived" {
					return
				}

				accountsChan <- details
			}(acc)
		}

		// Wait for all goroutines to complete
		wg.Wait()
		close(accountsChan)

		// Collect results
		for account := range accountsChan {
			accounts = append(accounts, account)
		}
	}

	logger.Infof("Collected %d total accounts", len(accounts))

	// Fetch account activities if requested
	var accountActivities map[string][]map[string]interface{}
	if *includeActivity && len(accounts) > 0 {
		logger.Infof("Fetching account activities (last %d days)...", *activityDays)
		accountActivities = make(map[string][]map[string]interface{})

		activitiesChan := make(chan struct {
			accountID  string
			activities []map[string]interface{}
		}, len(accounts))

		var wg sync.WaitGroup
		semaphore := make(chan struct{}, *workers)
		processedCount := 0
		var mu sync.Mutex

		for _, acc := range accounts {
			wg.Add(1)
			go func(acc map[string]interface{}) {
				defer wg.Done()
				semaphore <- struct{}{}        // Acquire
				defer func() { <-semaphore }() // Release

				accountID := graph.GetString(acc, "id", "")
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
						activities []map[string]interface{}
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

	// Build OpenGraph
	logger.Info("Building OpenGraph...")
	og, err := graph.BuildOpenGraph(
		users,
		groups,
		safes,
		safeMembers,
		accounts,
		*targetDomains,
		accountActivities,
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
