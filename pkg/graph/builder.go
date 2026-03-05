package graph

import (
	"fmt"
	"strings"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

// BuildOpenGraph converts CyberArk API data into BloodHound OpenGraph format
func BuildOpenGraph(
	users []models.User,
	groups []models.Group,
	safes []models.Safe,
	safeMembers []models.SafeMember,
	accounts []models.Account,
	targetDomains []string,
	parseSAMAccountNameFromDN bool,
	pvwaTag string,
	accountActivities map[string][]models.AccountActivity,
	platforms []models.Platform,
	linkedAccounts map[string][]models.LinkedAccount,
	logger *logrus.Logger,
	debug bool,
	logLevel string,
) (*OpenGraph, error) {
	og := NewOpenGraph(logger)
	if pvwaTag == "" {
		pvwaTag = "PVWA"
	}

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
		logger.Debugf("Building OpenGraph (users=%d groups=%d safes=%d accounts=%d platforms=%d)",
			len(users), len(groups), len(safes), len(accounts), len(platforms))
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

		if u.Username == "" {
			continue
		}

		source := strings.ToLower(u.Source)
		isLDAP := strings.Contains(source, "ldap") || u.UserDN != ""

		caNodeID := strings.ToUpper(fmt.Sprintf("causer-%s-%s", u.Username, pvwaTag))

		// Serialize vault authorization if complex
		var vaultAuthSerialized interface{} = u.VaultAuthorization
		if len(u.VaultAuthorization) > 0 {
			if _, ok := u.VaultAuthorization[0].(map[string]interface{}); ok {
				// Complex structure, serialize
				vaultAuthSerialized = SanitizeProperties(map[string]interface{}{"auth": u.VaultAuthorization})["auth"]
			}
		}

		// Create user node
		props := map[string]interface{}{
			"id":                           caNodeID,
			"name":                         u.Username,
			"userId":                       fmt.Sprintf("%v", u.ID),
			"isLDAPSynced":                 isLDAP,
			"enabled":                      u.Enabled,
			"suspended":                    u.Suspended,
			"distinguishedName":            u.UserDN,
			"authorizedInterfaces":         u.AuthorizedInterfaces,
			"componentUser":                u.ComponentUser,
			"source":                       source,
			"userType":                     u.UserType,
			"location":                     u.Location,
			"vaultAuthorization":           vaultAuthSerialized,
			"allowedAuthenticationMethods": u.AllowedAuthenticationMethods,
			"firstName":                    u.PersonalDetails.FirstName,
			"middleName":                   u.PersonalDetails.MiddleName,
			"lastName":                     u.PersonalDetails.LastName,
			"email":                        u.PersonalDetails.Email,
			"businessEmail":                u.PersonalDetails.BusinessEmail,
			"homeEmail":                    u.PersonalDetails.HomeEmail,
			"businessPhone":                u.PersonalDetails.BusinessPhone,
			"homePhone":                    u.PersonalDetails.HomePhone,
			"mobilePhone":                  u.PersonalDetails.MobilePhone,
			"faxNumber":                    u.PersonalDetails.FaxNumber,
			"street":                       u.PersonalDetails.Street,
			"city":                         u.PersonalDetails.City,
			"state":                        u.PersonalDetails.State,
			"zip":                          u.PersonalDetails.Zip,
			"country":                      u.PersonalDetails.Country,
			"title":                        u.PersonalDetails.Title,
			"organization":                 u.PersonalDetails.Organization,
			"department":                   u.PersonalDetails.Department,
			"profession":                   u.PersonalDetails.Profession,
			"safePermissions":              []interface{}{}, // Will be populated later
		}

		// Extract group membership
		groupNames := make([]string, 0, len(u.GroupsMembership))
		for _, gm := range u.GroupsMembership {
			if gm.GroupName != "" {
				groupNames = append(groupNames, gm.GroupName)
			}
		}
		props["groupsMembership"] = groupNames

		og.MergeNode(&Node{
			ID:         caNodeID,
			Kinds:      []string{"CyberArkUser", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		// Track user
		userID := fmt.Sprintf("%v", u.ID)
		if userID != "" {
			usersByID[userID] = caNodeID
		}
		usersByUsername[u.Username] = caNodeID

		// Add MemberOf edges
		for _, gm := range u.GroupsMembership {
			if gm.GroupName != "" {
				og.AddEdge("CyberArkMemberOf", caNodeID, strings.ToUpper(fmt.Sprintf("cagroup-%s-%s", gm.GroupName, pvwaTag)),
					"id", "id", map[string]interface{}{"source": "userDetails"}, false)
			}
		}

		// Add SyncsToCyberArkUser edge if LDAP synced
		if isLDAP && u.UserDN != "" {
			domain := ParseDomainFromDN(u.UserDN)
			if domain != "" {
				adKey := u.Username
				if parseSAMAccountNameFromDN {
					if sam := ParseSAMAccountNameFromDN(u.UserDN); sam != "" {
						adKey = sam
					}
				}

				adUserName := fmt.Sprintf("%s@%s", strings.ToUpper(adKey), strings.ToUpper(domain))
				og.AddEdge("SyncsToCyberArkUser", adUserName, caNodeID,
					"name", "id", map[string]interface{}{
						"inferred": true,
						"source":   "LDAP",
						"domain":   domain,
						"userDN":   u.UserDN,
						"adKey":    adKey,
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

		groupID := fmt.Sprintf("%v", g.ID)
		groupName := g.GroupName
		if groupName == "" {
			groupName = groupID
		}
		if groupName == "" {
			continue
		}

		caGroupID := strings.ToUpper(fmt.Sprintf("cagroup-%s-%s", groupName, pvwaTag))
		isDirectorySynced := g.Directory != "" || g.DN != ""

		// Extract members
		memberNames := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			memberName := m.MemberName
			if memberName == "" {
				memberName = m.Username
			}
			if memberName != "" {
				memberNames = append(memberNames, memberName)
			}
		}

		props := map[string]interface{}{
			"id":                caGroupID,
			"name":              groupName,
			"groupId":           groupID,
			"groupType":         g.GroupType,
			"isDirectorySynced": isDirectorySynced,
			"directory":         g.Directory,
			"distinguishedName": g.DN,
			"location":          g.Location,
			"description":       g.Description,
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
		if isDirectorySynced && g.DN != "" {
			domain := ParseDomainFromDN(g.DN)
			if domain != "" {
				adGroupName := fmt.Sprintf("%s@%s", strings.ToUpper(groupName), strings.ToUpper(domain))
				og.AddEdge("SyncsToCyberArkGroup", adGroupName, caGroupID,
					"name", "id", map[string]interface{}{
						"inferred": true,
						"source":   "LDAP",
						"domain":   domain,
						"groupDN":  g.DN,
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

		if s.SafeName == "" {
			continue
		}

		safeNodeID := strings.ToUpper(fmt.Sprintf("casafe-%s-%s", s.SafeName, pvwaTag))

		props := map[string]interface{}{
			"id":                        safeNodeID,
			"name":                      s.SafeName,
			"safeName":                  s.SafeName,
			"safeUrlId":                 s.SafeUrlId,
			"safeNumber":                s.SafeNumber,
			"description":               s.Description,
			"location":                  s.Location,
			"creator":                   s.Creator.Name,
			"olacEnabled":               s.OlacEnabled,
			"managingCPM":               s.ManagingCPM,
			"numberOfVersionsRetention": s.NumberOfVersionsRetention,
			"numberOfDaysRetention":     s.NumberOfDaysRetention,
			"autoPurgeEnabled":          s.AutoPurgeEnabled,
			"creationTime":              s.CreationTime,
			"lastModificationTime":      s.LastModificationTime,
			"isExpiredMembershipEnable": s.IsExpiredMembershipEnable,
		}

		og.MergeNode(&Node{
			ID:         safeNodeID,
			Kinds:      []string{"CyberArkSafe", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		safesByName[s.SafeName] = safeNodeID

		// CyberArkCreated edge (User → Safe) — safe creator relationship
		if s.Creator.Name != "" {
			creatorNodeID := usersByUsername[s.Creator.Name]
			if creatorNodeID == "" {
				creatorNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", s.Creator.Name, pvwaTag))
			}
			og.AddEdge("CyberArkCreated", creatorNodeID, safeNodeID,
				"id", "id", map[string]interface{}{
					"creatorId": s.Creator.ID,
				}, false)
		}

		// CyberArkManagedBy edge (CPM User → Safe) — CPM management relationship
		if s.ManagingCPM != "" {
			cpmNodeID := usersByUsername[s.ManagingCPM]
			if cpmNodeID == "" {
				cpmNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", s.ManagingCPM, pvwaTag))
			}
			og.AddEdge("CyberArkManagedBy", cpmNodeID, safeNodeID,
				"id", "id", nil, false)
		}
	}

	// Process Platforms (if provided)
	platformsByID := make(map[string]string) // platformID (string) -> platformNodeID
	if len(platforms) > 0 {
		logger.Infof("Processing %d platforms...", len(platforms))
		for _, p := range platforms {
			pid := p.General.PlatformID
			if pid == "" {
				pid = p.General.Name
			}
			if pid == "" {
				continue
			}
			platformNodeID := strings.ToUpper(fmt.Sprintf("caplatform-%s-%s", pid, pvwaTag))

			props := map[string]interface{}{
				"id":          platformNodeID,
				"name":        p.General.Name,
				"platformId":  pid,
				"systemType":  p.General.SystemType,
				"active":      p.General.Active,
				"description": p.General.Description,
			}

			og.MergeNode(&Node{
				ID:         platformNodeID,
				Kinds:      []string{"CyberArkPlatform", "CyberArkBase"},
				Properties: SanitizeProperties(props),
			})

			platformsByID[pid] = platformNodeID
			platformsByID[strings.ToLower(pid)] = platformNodeID
		}
		logger.Infof("Indexed %d platform IDs for matching", len(platformsByID))
	}

	// Process Accounts
	accountsBySafe := make(map[string][]string) // safeName -> []accountNodeIDs
	accountsByID := make(map[string]string)     // accountID -> accountNodeID

	logger.Infof("Processing %d accounts...", len(accounts))
	for idx, a := range accounts {
		if (idx+1)%accountInterval == 0 || idx+1 == len(accounts) {
			logger.Infof("  Processed %d/%d accounts (%.1f%%)", idx+1, len(accounts), float64(idx+1)/float64(len(accounts))*100)
		}

		if a.ID == "" {
			continue
		}

		accountNodeID := strings.ToUpper(fmt.Sprintf("caaccount-%s-%s", a.ID, pvwaTag))

		accountName := a.UserName
		if accountName == "" {
			accountName = a.Name
		}
		if accountName == "" {
			accountName = a.ID
		}
		accountName = StripAfterAt(accountName)

		props := map[string]interface{}{
			"id":                         accountNodeID,
			"name":                       accountName,
			"accountId":                  a.ID,
			"userName":                   a.UserName,
			"address":                    a.Address,
			"platformId":                 a.PlatformID,
			"safeName":                   a.SafeName,
			"safeUrlId":                  a.SafeUrlId,
			"secretType":                 a.SecretType,
			"status":                     a.Status,
			"enabled":                    !a.Disabled,
			"createdTime":                a.CreatedTime,
			"lastModifiedTime":           a.LastModifiedTime,
			"lastVerifiedTime":           a.LastVerifiedTime,
			"lastReconciledTime":         a.LastReconciledTime,
			"categoryModificationTime":   a.CategoryModificationTime,
			"automaticManagementEnabled": a.AutomaticManagementEnabled,
			"manualManagementReason":     a.ManualManagementReason,
			"lastModifiedBy":             a.LastModifiedBy,
		}

		// Add platform account properties if present
		if len(a.PlatformAccountProperties) > 0 {
			props["platformAccountProperties"] = SanitizeProperties(map[string]interface{}{"props": a.PlatformAccountProperties})["props"]
		}

		// Add secret management if present
		if len(a.SecretManagement) > 0 {
			props["secretManagement"] = SanitizeProperties(map[string]interface{}{"mgmt": a.SecretManagement})["mgmt"]
		}

		og.MergeNode(&Node{
			ID:         accountNodeID,
			Kinds:      []string{"CyberArkAccount", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		accountsByID[a.ID] = accountNodeID

		// CyberArkUsesPlatform edge (Account → Platform)
		if a.PlatformID != "" {
			platformNodeID, ok := platformsByID[a.PlatformID]
			if !ok {
				platformNodeID, ok = platformsByID[strings.ToLower(a.PlatformID)]
			}
			if ok {
				og.AddEdge("CyberArkUsesPlatform", accountNodeID, platformNodeID,
					"id", "id", nil, false)
			} else if len(platformsByID) > 0 && debug {
				logger.Debugf("Account %s has platformId '%s' but no matching platform node found", a.ID, a.PlatformID)
			}
		}

		// Track accounts by safe
		if a.SafeName != "" {
			accountsBySafe[a.SafeName] = append(accountsBySafe[a.SafeName], accountNodeID)

			// Add CyberArkContains edge (Safe -> Account)
			safeNodeID := safesByName[a.SafeName]
			if safeNodeID == "" {
				safeNodeID = strings.ToUpper(fmt.Sprintf("casafe-%s-%s", a.SafeName, pvwaTag))
			}
			og.AddEdge("CyberArkContains", safeNodeID, accountNodeID,
				"id", "id", nil, false)
		}

		// Add SyncsToADUser edge if applicable
		if a.UserName != "" && a.Address != "" {
			adKey := StripAfterAt(a.UserName)
			if adKey == "" {
				continue
			}
			for _, domain := range targetDomains {
				domainLower := strings.ToLower(strings.TrimSpace(domain))
				addressLower := strings.TrimRight(strings.ToLower(strings.TrimSpace(a.Address)), ".")

				// Only create SyncsToADUser if address exactly matches the target domain
				// If address contains subdomain (e.g., computer.domain.com), it's a computer account, not a user
				if addressLower == domainLower {
					adUserName := fmt.Sprintf("%s@%s", strings.ToUpper(adKey), strings.ToUpper(domain))
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

		if sm.MemberName == "" || sm.SafeName == "" {
			continue
		}

		// Determine if it's a user or group
		var memberNodeID string
		var isMemberGroup bool

		if strings.ToLower(sm.MemberType) == "group" {
			memberNodeID = groupsByName[sm.MemberName]
			isMemberGroup = true
		} else {
			memberNodeID = usersByUsername[sm.MemberName]
			isMemberGroup = false
		}

		if memberNodeID == "" {
			// Member not found, create placeholder
			if isMemberGroup {
				memberNodeID = strings.ToUpper(fmt.Sprintf("cagroup-%s-%s", sm.MemberName, pvwaTag))
			} else {
				memberNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", sm.MemberName, pvwaTag))
			}
		}

		safeNodeID := safesByName[sm.SafeName]
		if safeNodeID == "" {
			safeNodeID = strings.ToUpper(fmt.Sprintf("casafe-%s-%s", sm.SafeName, pvwaTag))
		}

		// Normalize permission names
		normalizedPerms := make(map[string]bool)
		matchedPermNames := make([]string, 0)
		matchedPermParams := make(map[string]interface{})

		for permKey, permVal := range sm.Permissions {
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
		accessWithoutConfirmation := false
		canApproveL1 := false
		canApproveL2 := false

		for normPerm := range normalizedPerms {
			if AccountAccessPermissions[normPerm] {
				hasDirectAccess = true
			}
			if EscalationPermissions[normPerm] {
				canGrantAccess = true
			}
			switch normPerm {
			case "accesswithoutconfirmation":
				accessWithoutConfirmation = true
			case "requestsauthorizationlevel1":
				canApproveL1 = true
			case "requestsauthorizationlevel2":
				canApproveL2 = true
			}
		}

		// Store safe permission details for node properties
		safePermDetail := map[string]interface{}{
			"safeName":                  sm.SafeName,
			"permissions":               matchedPermNames,
			"permissionParameters":      matchedPermParams,
			"hasDirectAccess":           hasDirectAccess,
			"canGrantAccess":            canGrantAccess,
			"accessWithoutConfirmation": accessWithoutConfirmation,
			"canApproveRequests":        canApproveL1 || canApproveL2,
		}

		if isMemberGroup {
			groupSafePerms[memberNodeID] = append(groupSafePerms[memberNodeID], safePermDetail)
		} else {
			userSafePerms[memberNodeID] = append(userSafePerms[memberNodeID], safePermDetail)
		}

		// Create edges based on permissions
		if hasDirectAccess {
			// Create edges to each account in the safe
			requiresApproval := !accessWithoutConfirmation
			accountsInSafe := accountsBySafe[sm.SafeName]
			for _, accountNodeID := range accountsInSafe {
				og.AddEdge("CyberArkHasAccessTo", memberNodeID, accountNodeID,
					"id", "id", map[string]interface{}{
						"safeName":         sm.SafeName,
						"permissions":      matchedPermNames,
						"inferred":         false,
						"requiresApproval": requiresApproval,
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

		// Create approval edges for dual control
		if canApproveL1 || canApproveL2 {
			approvalLevel := 1
			if canApproveL2 {
				approvalLevel = 2
			}
			og.AddEdge("CyberArkCanApprove", memberNodeID, safeNodeID,
				"id", "id", map[string]interface{}{
					"approvalLevel": approvalLevel,
					"inferred":      false,
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
				accountNodeID = strings.ToUpper(fmt.Sprintf("caaccount-%s-%s", accountID, pvwaTag))
			}

			if debug {
				logger.Debugf("Processing account: %s (activities: %d)", accountID, len(activities))
			}

			// Track unique users who used this account
			userActivity := make(map[string]map[string]interface{}) // username -> {lastUsedTime, lastAction, usageCount}

			for _, activity := range activities {
				username := activity.User
				action := activity.Action

				var activityDate float64
				switch v := activity.Date.(type) {
				case float64:
					activityDate = v
				case int:
					activityDate = float64(v)
				case int64:
					activityDate = float64(v)
				}

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
					userNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", username, pvwaTag))
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

	// Process Linked Accounts (if provided)
	if linkedAccounts != nil && len(linkedAccounts) > 0 {
		logger.Infof("Processing linked accounts for %d accounts...", len(linkedAccounts))
		linkedEdgeCount := 0

		for accountID, links := range linkedAccounts {
			sourceNodeID := accountsByID[accountID]
			if sourceNodeID == "" {
				sourceNodeID = strings.ToUpper(fmt.Sprintf("caaccount-%s-%s", accountID, pvwaTag))
			}

			for _, link := range links {
				targetNodeID := accountsByID[link.AccountID]
				if targetNodeID == "" && link.AccountID != "" {
					targetNodeID = strings.ToUpper(fmt.Sprintf("caaccount-%s-%s", link.AccountID, pvwaTag))
				}
				if targetNodeID == "" {
					continue
				}

				// Map ExtraPassID to human-readable link type
				linkType := "unknown"
				switch link.ExtraPassID {
				case 1:
					linkType = "logon"
				case 2:
					linkType = "enable"
				case 3:
					linkType = "reconcile"
				}

				og.AddEdge("CyberArkLinkedTo", sourceNodeID, targetNodeID,
					"id", "id", map[string]interface{}{
						"linkType": linkType,
						"linkName": link.Name,
						"safeName": link.SafeName,
					}, false)
				linkedEdgeCount++
			}
		}

		logger.Infof("Created %d CyberArkLinkedTo edges from linked account data", linkedEdgeCount)
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
