package graph

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// BuildOpenGraph converts CyberArk API data into BloodHound OpenGraph format
func BuildOpenGraph(
	users []map[string]interface{},
	groups []map[string]interface{},
	safes []map[string]interface{},
	safeMembers []map[string]interface{},
	accounts []map[string]interface{},
	targetDomains []string,
	accountActivities map[string][]map[string]interface{},
	logger *logrus.Logger,
	debug bool,
	logLevel string,
) (*OpenGraph, error) {
	og := NewOpenGraph(logger)

	// Determine logging intervals based on log level
	var userInterval, groupInterval, safeInterval, accountInterval, memberInterval int
	if logLevel == "WARNING" || logLevel == "ERROR" {
		userInterval = max(len(users), 1)
		groupInterval = max(len(groups), 1)
		safeInterval = max(len(safes), 1)
		accountInterval = max(len(accounts), 1)
		memberInterval = max(len(safeMembers), 1)
	} else if logLevel == "DEBUG" {
		userInterval = 10
		groupInterval = 10
		safeInterval = 5
		accountInterval = 25
		memberInterval = 25
	} else { // INFO (default)
		userInterval = 50
		groupInterval = 50
		safeInterval = 20
		accountInterval = 100
		memberInterval = 100
	}

	if debug {
		logger.Debugf("Building OpenGraph (users=%d groups=%d safes=%d accounts=%d)",
			len(users), len(groups), len(safes), len(accounts))
	}

	// Track users and groups for lookups
	usersByID := make(map[string]string)
	usersByUsername := make(map[string]string)
	groupsByID := make(map[string]string)
	groupsByName := make(map[string]string)
	safesByName := make(map[string]string)

	// Process Users
	logger.Infof("Processing %d users...", len(users))
	for idx, u := range users {
		if (idx+1)%userInterval == 0 || idx+1 == len(users) {
			logger.Infof("  Processed %d/%d users (%.1f%%)", idx+1, len(users), float64(idx+1)/float64(len(users))*100)
		}

		username := GetString(u, "username", "")
		if username == "" {
			continue
		}

		userDN := GetString(u, "userDN", "")
		source := strings.ToLower(GetString(u, "source", ""))
		isLDAP := strings.Contains(source, "ldap") || userDN != ""

		caNodeID := fmt.Sprintf("causer-%s", username)

		// Extract personal details
		personalDetails := GetMap(u, "personalDetails")

		// Serialize vault authorization if complex
		vaultAuth := GetSlice(u, "vaultAuthorization")
		var vaultAuthSerialized interface{} = vaultAuth
		if len(vaultAuth) > 0 {
			if _, ok := vaultAuth[0].(map[string]interface{}); ok {
				// Complex structure, serialize
				vaultAuthSerialized = SanitizeProperties(map[string]interface{}{"auth": vaultAuth})["auth"]
			}
		}

		// Create user node
		props := map[string]interface{}{
			"id":                           caNodeID,
			"name":                         username,
			"userId":                       GetString(u, "id", ""),
			"isLDAPSynced":                 isLDAP,
			"enabled":                      GetBool(u, "enabled", true),
			"suspended":                    GetBool(u, "suspended", false),
			"distinguishedName":            userDN,
			"authorizedInterfaces":         GetSlice(u, "authorizedInterfaces"),
			"componentUser":                GetBool(u, "componentUser", false),
			"source":                       source,
			"userType":                     GetString(u, "userType", ""),
			"location":                     GetString(u, "location", ""),
			"vaultAuthorization":           vaultAuthSerialized,
			"allowedAuthenticationMethods": GetSlice(u, "allowedAuthenticationMethods"),
			"firstName":                    GetString(personalDetails, "firstName", ""),
			"middleName":                   GetString(personalDetails, "middleName", ""),
			"lastName":                     GetString(personalDetails, "lastName", ""),
			"email":                        GetString(personalDetails, "email", ""),
			"businessEmail":                GetString(personalDetails, "businessEmail", ""),
			"homeEmail":                    GetString(personalDetails, "homeEmail", ""),
			"businessPhone":                GetString(personalDetails, "businessPhone", ""),
			"homePhone":                    GetString(personalDetails, "homePhone", ""),
			"mobilePhone":                  GetString(personalDetails, "mobilePhone", ""),
			"faxNumber":                    GetString(personalDetails, "faxNumber", ""),
			"street":                       GetString(personalDetails, "street", ""),
			"city":                         GetString(personalDetails, "city", ""),
			"state":                        GetString(personalDetails, "state", ""),
			"zip":                          GetString(personalDetails, "zip", ""),
			"country":                      GetString(personalDetails, "country", ""),
			"title":                        GetString(personalDetails, "title", ""),
			"organization":                 GetString(personalDetails, "organization", ""),
			"department":                   GetString(personalDetails, "department", ""),
			"profession":                   GetString(personalDetails, "profession", ""),
			"safePermissions":              []interface{}{}, // Will be populated later
		}

		// Extract group membership
		groupsMembership := GetMapSlice(u, "groupsMembership")
		groupNames := make([]string, 0, len(groupsMembership))
		for _, gm := range groupsMembership {
			groupName := GetString(gm, "groupName", "")
			if groupName == "" {
				groupName = GetString(gm, "name", "")
			}
			if groupName != "" {
				groupNames = append(groupNames, groupName)
			}
		}
		props["groupsMembership"] = groupNames

		og.MergeNode(&Node{
			ID:         caNodeID,
			Kinds:      []string{"CyberArkUser", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		// Track user
		userID := GetString(u, "id", "")
		if userID != "" {
			usersByID[userID] = caNodeID
		}
		usersByUsername[username] = caNodeID

		// Add MemberOf edges
		for _, gm := range groupsMembership {
			groupName := GetString(gm, "groupName", "")
			if groupName == "" {
				groupName = GetString(gm, "name", "")
			}
			if groupName != "" {
				og.AddEdge("CyberArkMemberOf", caNodeID, fmt.Sprintf("cagroup-%s", groupName),
					"id", "id", map[string]interface{}{"source": "userDetails"}, false)
			}
		}

		// Add SyncsToCyberArkUser edge if LDAP synced
		if isLDAP && userDN != "" {
			domain := ParseDomainFromDN(userDN)
			if domain != "" {
				adUserName := fmt.Sprintf("%s@%s", strings.ToUpper(username), strings.ToUpper(domain))
				og.AddEdge("SyncsToCyberArkUser", adUserName, caNodeID,
					"name", "id", map[string]interface{}{
						"inferred": true,
						"source":   "LDAP",
						"domain":   domain,
						"userDN":   userDN,
					}, true)
			}
		}
	}

	// Process Groups
	logger.Infof("Processing %d groups...", len(groups))
	for idx, g := range groups {
		if (idx+1)%groupInterval == 0 || idx+1 == len(groups) {
			logger.Infof("  Processed %d/%d groups (%.1f%%)", idx+1, len(groups), float64(idx+1)/float64(len(groups))*100)
		}

		groupID := GetString(g, "id", "")
		groupName := GetString(g, "groupName", "")
		if groupName == "" {
			groupName = groupID
		}
		if groupName == "" {
			continue
		}

		caGroupID := fmt.Sprintf("cagroup-%s", groupName)

		groupDN := GetString(g, "dn", "")
		directory := GetString(g, "directory", "")
		isDirectorySynced := directory != "" || groupDN != ""

		// Extract members
		members := GetMapSlice(g, "members")
		memberNames := make([]string, 0, len(members))
		for _, m := range members {
			memberName := GetString(m, "memberName", "")
			if memberName == "" {
				memberName = GetString(m, "username", "")
			}
			if memberName != "" {
				memberNames = append(memberNames, memberName)
			}
		}

		props := map[string]interface{}{
			"id":                caGroupID,
			"name":              groupName,
			"groupId":           groupID,
			"groupType":         GetString(g, "groupType", ""),
			"isDirectorySynced": isDirectorySynced,
			"directory":         directory,
			"distinguishedName": groupDN,
			"location":          GetString(g, "location", ""),
			"description":       GetString(g, "description", ""),
			"memberCount":       len(memberNames),
			"members":           memberNames,
			"safePermissions":   []interface{}{}, // Will be populated later
		}

		og.MergeNode(&Node{
			ID:         caGroupID,
			Kinds:      []string{"CyberArkGroup", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		// Track group
		if groupID != "" {
			groupsByID[groupID] = caGroupID
		}
		groupsByName[groupName] = caGroupID

		// Add SyncsToCyberArkGroup edge if directory synced
		if isDirectorySynced && groupDN != "" {
			domain := ParseDomainFromDN(groupDN)
			if domain != "" {
				adGroupName := fmt.Sprintf("%s@%s", strings.ToUpper(groupName), strings.ToUpper(domain))
				og.AddEdge("SyncsToCyberArkGroup", adGroupName, caGroupID,
					"name", "id", map[string]interface{}{
						"inferred": true,
						"source":   "LDAP",
						"domain":   domain,
						"groupDN":  groupDN,
					}, true)
			}
		}
	}

	// Process Safes
	logger.Infof("Processing %d safes...", len(safes))
	for idx, s := range safes {
		if (idx+1)%safeInterval == 0 || idx+1 == len(safes) {
			logger.Infof("  Processed %d/%d safes (%.1f%%)", idx+1, len(safes), float64(idx+1)/float64(len(safes))*100)
		}

		safeName := GetString(s, "safeName", "")
		if safeName == "" {
			continue
		}

		safeNodeID := fmt.Sprintf("casafe-%s", safeName)

		props := map[string]interface{}{
			"id":                        safeNodeID,
			"name":                      safeName,
			"safeName":                  safeName,
			"safeUrlId":                 GetString(s, "safeUrlId", ""),
			"safeNumber":                GetInt(s, "safeNumber", 0),
			"description":               GetString(s, "description", ""),
			"location":                  GetString(s, "location", ""),
			"creator":                   GetString(s, "creator", ""),
			"olacEnabled":               GetBool(s, "olacEnabled", false),
			"managingCPM":               GetString(s, "managingCPM", ""),
			"numberOfVersionsRetention": GetInt(s, "numberOfVersionsRetention", 0),
			"numberOfDaysRetention":     GetInt(s, "numberOfDaysRetention", 0),
			"autoPurgeEnabled":          GetBool(s, "autoPurgeEnabled", false),
			"creationTime":              GetFloat64(s, "creationTime", 0),
			"lastModificationTime":      GetFloat64(s, "lastModificationTime", 0),
			"isExpiredMembershipEnable": GetBool(s, "isExpiredMembershipEnable", false),
		}

		og.MergeNode(&Node{
			ID:         safeNodeID,
			Kinds:      []string{"CyberArkSafe", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		safesByName[safeName] = safeNodeID
	}

	// Process Accounts
	accountsBySafe := make(map[string][]string) // safeName -> []accountNodeIDs
	accountsByID := make(map[string]string)     // accountID -> accountNodeID

	logger.Infof("Processing %d accounts...", len(accounts))
	for idx, a := range accounts {
		if (idx+1)%accountInterval == 0 || idx+1 == len(accounts) {
			logger.Infof("  Processed %d/%d accounts (%.1f%%)", idx+1, len(accounts), float64(idx+1)/float64(len(accounts))*100)
		}

		accountID := GetString(a, "id", "")
		if accountID == "" {
			continue
		}

		safeName := GetString(a, "safeName", "")
		userName := GetString(a, "userName", "")
		address := GetString(a, "address", "")

		accountNodeID := fmt.Sprintf("caaccount-%s", accountID)

		props := map[string]interface{}{
			"id":                         accountNodeID,
			"name":                       fmt.Sprintf("%s@%s", userName, address),
			"accountId":                  accountID,
			"userName":                   userName,
			"address":                    address,
			"platformId":                 GetString(a, "platformId", ""),
			"safeName":                   safeName,
			"safeUrlId":                  GetString(a, "safeUrlId", ""),
			"secretType":                 GetString(a, "secretType", ""),
			"status":                     GetString(a, "status", ""),
			"disabled":                   GetBool(a, "disabled", false),
			"createdTime":                GetFloat64(a, "createdTime", 0),
			"lastModifiedTime":           GetFloat64(a, "lastModifiedTime", 0),
			"lastVerifiedTime":           GetFloat64(a, "lastVerifiedTime", 0),
			"lastReconciledTime":         GetFloat64(a, "lastReconciledTime", 0),
			"categoryModificationTime":   GetFloat64(a, "categoryModificationTime", 0),
			"automaticManagementEnabled": GetBool(a, "automaticManagementEnabled", false),
			"manualManagementReason":     GetString(a, "manualManagementReason", ""),
			"lastModifiedBy":             GetString(a, "lastModifiedBy", ""),
		}

		// Add platform account properties if present
		if platformProps := GetMap(a, "platformAccountProperties"); len(platformProps) > 0 {
			props["platformAccountProperties"] = SanitizeProperties(map[string]interface{}{"props": platformProps})["props"]
		}

		// Add secret management if present
		if secretMgmt := GetMap(a, "secretManagement"); len(secretMgmt) > 0 {
			props["secretManagement"] = SanitizeProperties(map[string]interface{}{"mgmt": secretMgmt})["mgmt"]
		}

		og.MergeNode(&Node{
			ID:         accountNodeID,
			Kinds:      []string{"CyberArkAccount", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		accountsByID[accountID] = accountNodeID

		// Track accounts by safe
		if safeName != "" {
			accountsBySafe[safeName] = append(accountsBySafe[safeName], accountNodeID)

			// Add CyberArkContains edge (Safe -> Account)
			safeNodeID := fmt.Sprintf("casafe-%s", safeName)
			og.AddEdge("CyberArkContains", safeNodeID, accountNodeID,
				"id", "id", nil, false)
		}

		// Add SyncsToADUser edge if applicable
		if userName != "" && address != "" {
			for _, domain := range targetDomains {
				domainLower := strings.ToLower(domain)
				addressLower := strings.ToLower(address)

				// Only create SyncsToADUser if address exactly matches the target domain
				// If address contains subdomain (e.g., computer.domain.com), it's a computer account, not a user
				if addressLower == domainLower {
					adUserName := fmt.Sprintf("%s@%s", strings.ToUpper(userName), strings.ToUpper(domain))
					og.AddEdge("SyncsToADUser", accountNodeID, adUserName,
						"id", "name", map[string]interface{}{
							"inferred": true,
							"source":   "CyberArk",
							"domain":   domain,
						}, true)
					break
				}
			}
		}
	}

	// Process Safe Members and create permission edges
	logger.Infof("Processing %d safe members...", len(safeMembers))

	// Track safe permissions for user/group nodes
	userSafePerms := make(map[string][]map[string]interface{})
	groupSafePerms := make(map[string][]map[string]interface{})

	for idx, sm := range safeMembers {
		if (idx+1)%memberInterval == 0 || idx+1 == len(safeMembers) {
			logger.Infof("  Processed %d/%d safe members (%.1f%%)", idx+1, len(safeMembers), float64(idx+1)/float64(len(safeMembers))*100)
		}

		memberName := GetString(sm, "MemberName", "")
		memberType := GetString(sm, "MemberType", "")
		safeName := GetString(sm, "SafeName", "")

		if memberName == "" || safeName == "" {
			continue
		}

		// Determine if it's a user or group
		var memberNodeID string
		var isMemberGroup bool

		if strings.ToLower(memberType) == "group" {
			memberNodeID = groupsByName[memberName]
			isMemberGroup = true
		} else {
			memberNodeID = usersByUsername[memberName]
			isMemberGroup = false
		}

		if memberNodeID == "" {
			// Member not found, create placeholder
			if isMemberGroup {
				memberNodeID = fmt.Sprintf("cagroup-%s", memberName)
			} else {
				memberNodeID = fmt.Sprintf("causer-%s", memberName)
			}
		}

		safeNodeID := safesByName[safeName]
		if safeNodeID == "" {
			safeNodeID = fmt.Sprintf("casafe-%s", safeName)
		}

		// Extract permissions
		permissions := GetMap(sm, "Permissions")

		// Normalize permission names
		normalizedPerms := make(map[string]bool)
		matchedPermNames := make([]string, 0)
		matchedPermParams := make(map[string]interface{})

		for permKey, permVal := range permissions {
			normKey := NormPermName(permKey)
			if normKey == "" {
				continue
			}

			// Check if permission is granted (value is true)
			isGranted := false
			switch v := permVal.(type) {
			case bool:
				isGranted = v
			case string:
				isGranted = strings.ToLower(v) == "true"
			}

			if isGranted {
				normalizedPerms[normKey] = true
				matchedPermNames = append(matchedPermNames, permKey)
			}

			// Store parameter value
			matchedPermParams[permKey] = permVal
		}

		// Determine edge type based on permissions
		hasDirectAccess := false
		canGrantAccess := false

		for normPerm := range normalizedPerms {
			if AccountAccessPermissions[normPerm] {
				hasDirectAccess = true
			}
			if EscalationPermissions[normPerm] {
				canGrantAccess = true
			}
		}

		// Store safe permission details for node properties
		safePermDetail := map[string]interface{}{
			"safeName":             safeName,
			"permissions":          matchedPermNames,
			"permissionParameters": matchedPermParams,
			"hasDirectAccess":      hasDirectAccess,
			"canGrantAccess":       canGrantAccess,
		}

		if isMemberGroup {
			groupSafePerms[memberNodeID] = append(groupSafePerms[memberNodeID], safePermDetail)
		} else {
			userSafePerms[memberNodeID] = append(userSafePerms[memberNodeID], safePermDetail)
		}

		// Create edges based on permissions
		if hasDirectAccess {
			// Create edges to each account in the safe
			accountsInSafe := accountsBySafe[safeName]
			for _, accountNodeID := range accountsInSafe {
				og.AddEdge("CyberArkHasAccessTo", memberNodeID, accountNodeID,
					"id", "id", map[string]interface{}{
						"safeName":    safeName,
						"permissions": matchedPermNames,
						"inferred":    false,
					}, false)
			}
		}

		if canGrantAccess {
			// Create edge to the safe (privilege escalation path)
			og.AddEdge("CyberArkCanGrantAccessTo", memberNodeID, safeNodeID,
				"id", "id", map[string]interface{}{
					"permissions": matchedPermNames,
					"inferred":    false,
				}, false)
		}
	}

	// Update user and group nodes with safe permissions
	for userNodeID, perms := range userSafePerms {
		if node, exists := og.Nodes[userNodeID]; exists {
			node.Properties["safePermissions"] = SanitizeProperties(map[string]interface{}{"perms": perms})["perms"]
		}
	}

	for groupNodeID, perms := range groupSafePerms {
		if node, exists := og.Nodes[groupNodeID]; exists {
			node.Properties["safePermissions"] = SanitizeProperties(map[string]interface{}{"perms": perms})["perms"]
		}
	}

	// Process Account Activities (if provided)
	if accountActivities != nil && len(accountActivities) > 0 {
		logger.Infof("Processing account activities for %d accounts...", len(accountActivities))
		activityEdgeCount := 0

		if debug {
			logger.Debug("=== CyberArkUsedAccount Edge Creation Debug ===")
			logger.Debugf("Total accounts with activities: %d", len(accountActivities))
		}

		for accountID, activities := range accountActivities {
			accountNodeID := accountsByID[accountID]
			if accountNodeID == "" {
				accountNodeID = fmt.Sprintf("caaccount-%s", accountID)
			}

			if debug {
				logger.Debugf("Processing account: %s (activities: %d)", accountID, len(activities))
			}

			// Track unique users who used this account
			userActivity := make(map[string]map[string]interface{}) // username -> {lastUsedTime, lastAction, usageCount}

			for _, activity := range activities {
				username := GetString(activity, "User", "")
				action := GetString(activity, "Action", "")
				activityDate := GetFloat64(activity, "Date", 0)

				// Convert Unix timestamp to ISO 8601
				var activityTime string
				if activityDate > 0 {
					activityTime = UnixToISO8601(activityDate)
				}

				if debug {
					logger.Debugf("  Activity: User=%s, Action=%s, Date=%.0f (converted to %s)",
						username, action, activityDate, activityTime)
				}

				if username == "" {
					if debug {
						logger.Debug("  Skipping activity - no username")
					}
					continue
				}

				// Track usage per user
				if _, exists := userActivity[username]; !exists {
					userActivity[username] = map[string]interface{}{
						"lastUsedTime": activityTime,
						"lastAction":   action,
						"usageCount":   0,
					}
					if debug {
						logger.Debugf("  New user tracked: %s", username)
					}
				}

				ua := userActivity[username]
				ua["usageCount"] = ua["usageCount"].(int) + 1

				// Update last used time and action if this is more recent
				if activityTime != "" {
					lastTime, _ := ua["lastUsedTime"].(string)
					if lastTime == "" || activityTime > lastTime {
						ua["lastUsedTime"] = activityTime
						ua["lastAction"] = action
						if debug {
							logger.Debugf("  Updated %s: lastTime=%s, lastAction=%s", username, activityTime, action)
						}
					}
				}
			}

			if debug {
				logger.Debugf("Account %s: %d unique users found", accountID, len(userActivity))
			}

			// Create ONE edge per user with their most recent activity
			for username, usageData := range userActivity {
				userNodeID := usersByUsername[username]
				if userNodeID == "" {
					userNodeID = fmt.Sprintf("causer-%s", username)
				}

				if debug {
					userExists := usersByUsername[username] != ""
					logger.Debugf("Creating edge: %s -> %s (user_exists=%v, count=%v, lastTime=%s, lastAction=%s)",
						userNodeID, accountNodeID, userExists, usageData["usageCount"], usageData["lastUsedTime"], usageData["lastAction"])
				}

				og.AddEdge("CyberArkUsedAccount", userNodeID, accountNodeID,
					"id", "id", map[string]interface{}{
						"lastUsedTime": usageData["lastUsedTime"],
						"lastActivity": usageData["lastAction"],
						"usageCount":   usageData["usageCount"],
						"inferred":     false,
					}, false)
				activityEdgeCount++
			}
		}

		logger.Infof("Created %d CyberArkUsedAccount edges from activity data", activityEdgeCount)
		if debug {
			logger.Debug("===========================================")
		}
	}

	if debug {
		logger.Debugf("Graph build complete: nodes=%d internal_edges=%d external_edges=%d",
			len(og.Nodes), len(og.InternalEdges), len(og.ExternalEdges))
	}

	return og, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
