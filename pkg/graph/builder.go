package graph

import (
	"fmt"
	"net"
	"strings"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

// BuildInput bundles all inputs to BuildOpenGraph. Grouping them into a struct
// keeps call sites self-documenting and lets new data sources be added without
// breaking every caller's positional argument list.
type BuildInput struct {
	Users                     []models.User
	Groups                    []models.Group
	Safes                     []models.Safe
	SafeMembers               []models.SafeMember
	Accounts                  []models.Account
	TargetDomains             []string
	ParseSAMAccountNameFromDN bool
	PVWATag                   string
	AccountActivities         map[string][]models.AccountActivity
	Platforms                 []models.Platform
	PlatformConnectors        map[string][]string
	TargetPlatforms           []models.TargetPlatform
	LinkedAccounts            map[string][]models.LinkedAccount
	PSMServers                []models.PSMServer
	ConnectionComponents      []models.ConnectionComponent
	Applications              []models.Application
	Debug                     bool
	LogLevel                  string
}

// BuildOpenGraph converts CyberArk API data into BloodHound OpenGraph format.
func BuildOpenGraph(in BuildInput, logger *logrus.Logger) (*OpenGraph, error) {
	users := in.Users
	groups := in.Groups
	safes := in.Safes
	safeMembers := in.SafeMembers
	accounts := in.Accounts
	targetDomains := in.TargetDomains
	parseSAMAccountNameFromDN := in.ParseSAMAccountNameFromDN
	pvwaTag := in.PVWATag
	accountActivities := in.AccountActivities
	platforms := in.Platforms
	platformConnectors := in.PlatformConnectors
	targetPlatforms := in.TargetPlatforms
	linkedAccounts := in.LinkedAccounts
	psmServers := in.PSMServers
	connectionComponents := in.ConnectionComponents
	applications := in.Applications
	debug := in.Debug
	logLevel := in.LogLevel

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
			Kinds:      []string{"CyberArk_User", "CyberArkBase"},
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
				og.AddEdge("CyberArk_MemberOf", caNodeID, strings.ToUpper(fmt.Sprintf("cagroup-%s-%s", gm.GroupName, pvwaTag)),
					"id", "id", map[string]interface{}{"source": "userDetails"}, false)
			}
		}

		// Add CyberArk_SyncsToUser edge if LDAP synced
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
				og.AddEdge("CyberArk_SyncsToUser", adUserName, caNodeID,
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
			Kinds:      []string{"CyberArk_Group", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		// Track group
		if groupID != "" {
			groupsByID[groupID] = caGroupID
		}
		groupsByName[groupName] = caGroupID

		// Add CyberArk_SyncsToGroup edge if directory synced
		if isDirectorySynced && g.DN != "" {
			domain := ParseDomainFromDN(g.DN)
			if domain != "" {
				adGroupName := fmt.Sprintf("%s@%s", strings.ToUpper(groupName), strings.ToUpper(domain))
				og.AddEdge("CyberArk_SyncsToGroup", adGroupName, caGroupID,
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
			Kinds:      []string{"CyberArk_Safe", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		safesByName[s.SafeName] = safeNodeID

		// CyberArk_Created edge (User → Safe) — safe creator relationship
		if s.Creator.Name != "" {
			creatorNodeID := usersByUsername[s.Creator.Name]
			if creatorNodeID == "" {
				creatorNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", s.Creator.Name, pvwaTag))
			}
			og.AddEdge("CyberArk_Created", creatorNodeID, safeNodeID,
				"id", "id", map[string]interface{}{
					"creatorId": s.Creator.ID,
				}, false)
		}

		// CyberArk_ManagedBy edge (CPM User → Safe) — CPM management relationship
		if s.ManagingCPM != "" {
			cpmNodeID := usersByUsername[s.ManagingCPM]
			if cpmNodeID == "" {
				cpmNodeID = strings.ToUpper(fmt.Sprintf("causer-%s-%s", s.ManagingCPM, pvwaTag))
			}
			og.AddEdge("CyberArk_ManagedBy", cpmNodeID, safeNodeID,
				"id", "id", nil, false)
		}
	}

	// Process Platforms (if provided)
	platformsByID := make(map[string]string)           // platformID (string) -> platformNodeID
	platformDualControl := make(map[string]bool)       // platformID (lowercase) -> requireDualControlPasswordAccessApproval
	platformSessionMonitoring := make(map[string]bool) // platformID (lowercase) -> requirePrivilegedSessionMonitoringAndIsolation
	platformSessionRecording := make(map[string]bool)  // platformID (lowercase) -> recordAndSaveSessionActivity
	platformPSMServerID := make(map[string]string)     // platformID (lowercase) -> PSMServerID
	if len(platforms) > 0 {
		logger.Infof("Processing %d platforms...", len(platforms))
		for _, p := range platforms {
			pid := p.General.ID
			if pid == "" {
				pid = p.General.Name
			}
			if pid == "" {
				continue
			}
			platformNodeID := strings.ToUpper(fmt.Sprintf("caplatform-%s-%s", pid, pvwaTag))

			// Collect required and optional property names
			requiredProps := make([]string, 0, len(p.Properties.Required))
			for _, rp := range p.Properties.Required {
				requiredProps = append(requiredProps, rp.Name)
			}
			optionalProps := make([]string, 0, len(p.Properties.Optional))
			for _, op := range p.Properties.Optional {
				optionalProps = append(optionalProps, op.Name)
			}

			// Collect linked account type names
			linkedAccountTypes := make([]string, 0, len(p.LinkedAccounts))
			for _, la := range p.LinkedAccounts {
				linkedAccountTypes = append(linkedAccountTypes, la.Name)
			}

			props := map[string]interface{}{
				"id":             platformNodeID,
				"name":           p.General.Name,
				"platformId":     pid,
				"systemType":     p.General.SystemType,
				"active":         p.General.Active,
				"description":    p.General.Description,
				"platformBaseID": p.General.PlatformBaseID,
				"platformType":   p.General.PlatformType,

				// Properties
				"requiredProperties": requiredProps,
				"optionalProperties": optionalProps,

				// Linked account types defined for this platform
				"linkedAccountTypes": linkedAccountTypes,

				// Credentials management
				"allowedSafes":                          p.CredentialsManagement.AllowedSafes,
				"allowedSafesIsWildcard":                isWildcardAllowedSafes(p.CredentialsManagement.AllowedSafes),
				"allowManualChange":                     p.CredentialsManagement.AllowManualChange,
				"performPeriodicChange":                 p.CredentialsManagement.PerformPeriodicChange,
				"requirePasswordChangeEveryXDays":       p.CredentialsManagement.RequirePasswordChangeEveryXDays,
				"allowManualVerification":               p.CredentialsManagement.AllowManualVerification,
				"performPeriodicVerification":           p.CredentialsManagement.PerformPeriodicVerification,
				"requirePasswordVerificationEveryXDays": p.CredentialsManagement.RequirePasswordVerificationEveryXDays,
				"allowManualReconciliation":             p.CredentialsManagement.AllowManualReconciliation,
				"automaticReconcileWhenUnsynched":       p.CredentialsManagement.AutomaticReconcileWhenUnsynched,

				// Session management
				"requirePrivilegedSessionMonitoringAndIsolation": p.SessionManagement.RequirePrivilegedSessionMonitoringAndIsolation,
				"recordAndSaveSessionActivity":                   p.SessionManagement.RecordAndSaveSessionActivity,
				"psmServerID":                                    p.SessionManagement.PSMServerID,

				// Privileged access workflows
				"requireDualControlPasswordAccessApproval": p.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval,
				"enforceCheckinCheckoutExclusiveAccess":    p.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess,
				"enforceOnetimePasswordAccess":             p.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess,
			}

			// Add connection components if available
			if platformConnectors != nil {
				if connectors, ok := platformConnectors[pid]; ok {
					props["connectionComponents"] = connectors
				}
			}

			og.MergeNode(&Node{
				ID:         platformNodeID,
				Kinds:      []string{"CyberArk_Platform", "CyberArkBase"},
				Properties: SanitizeProperties(props),
			})

			platformsByID[pid] = platformNodeID
			platformsByID[strings.ToLower(pid)] = platformNodeID
			platformDualControl[strings.ToLower(pid)] = p.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval
			platformSessionMonitoring[strings.ToLower(pid)] = p.SessionManagement.RequirePrivilegedSessionMonitoringAndIsolation
			platformSessionRecording[strings.ToLower(pid)] = p.SessionManagement.RecordAndSaveSessionActivity
			if p.SessionManagement.PSMServerID != "" {
				platformPSMServerID[strings.ToLower(pid)] = p.SessionManagement.PSMServerID
			}
		}
		logger.Infof("Indexed %d platform IDs for matching", len(platformsByID))
	}

	// Enrich platform nodes with Master Policy exception flags from Targets endpoint.
	// When /API/Platforms/ fails (e.g., HTTP 500), create fallback platform nodes from
	// the Targets data so that account→platform and platform→PSMServer edges still work.
	if len(targetPlatforms) > 0 {
		fallbackCount := 0
		logger.Infof("Processing %d target platform exception flags...", len(targetPlatforms))
		for _, tp := range targetPlatforms {
			tpID := tp.PlatformID
			if tpID == "" {
				tpID = tp.Name
			}
			if tpID == "" {
				continue
			}
			platformNodeID, ok := platformsByID[tpID]
			if !ok {
				platformNodeID, ok = platformsByID[strings.ToLower(tpID)]
			}

			if !ok {
				// Fallback: create a rich platform node from target data when
				// the full /API/Platforms/ endpoint was unavailable.
				platformNodeID = strings.ToUpper(fmt.Sprintf("caplatform-%s-%s", tpID, pvwaTag))
				props := map[string]interface{}{
					"id":          platformNodeID,
					"name":        tp.Name,
					"platformId":  tpID,
					"active":      tp.Active,
					"systemType":  tp.SystemType,
					"psmServerID": tp.SessionManagement.PSMServerID,

					// Session management (from IsActive flags)
					"requirePrivilegedSessionMonitoringAndIsolation": tp.SessionManagement.RequirePrivilegedSessionMonitoringAndIsolation.IsActive,
					"recordAndSaveSessionActivity":                   tp.SessionManagement.RecordAndSaveSessionActivity.IsActive,

					// Privileged access workflows
					"requireDualControlPasswordAccessApproval": tp.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive,
					"enforceCheckinCheckoutExclusiveAccess":    tp.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsActive,
					"enforceOnetimePasswordAccess":             tp.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsActive,
					"requireUsersToSpecifyReasonForAccess":     tp.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsActive,

					// Credentials management
					"allowedSafes":                          tp.AllowedSafes,
					"allowedSafesIsWildcard":                isWildcardAllowedSafes(tp.AllowedSafes),
					"performPeriodicVerification":           tp.CredentialsManagementPolicy.Verification.PerformAutomatic,
					"requirePasswordVerificationEveryXDays": tp.CredentialsManagementPolicy.Verification.RequirePasswordEveryXDays,
					"allowManualVerification":               tp.CredentialsManagementPolicy.Verification.AllowManual,
					"performPeriodicChange":                 tp.CredentialsManagementPolicy.Change.PerformAutomatic,
					"requirePasswordChangeEveryXDays":       tp.CredentialsManagementPolicy.Change.RequirePasswordEveryXDays,
					"allowManualChange":                     tp.CredentialsManagementPolicy.Change.AllowManual,
					"automaticReconcileWhenUnsynched":       tp.CredentialsManagementPolicy.Reconcile.AutomaticReconcileWhenUnsynced,
					"allowManualReconciliation":             tp.CredentialsManagementPolicy.Reconcile.AllowManual,
					"changePasswordInResetMode":             tp.CredentialsManagementPolicy.SecretUpdateConfiguration.ChangePasswordInResetMode,

					// Credential management exception flags
					"verificationFrequencyIsException": tp.CredentialsManagementPolicy.Verification.IsRequirePasswordEveryXDaysAnException,
					"changeFrequencyIsException":       tp.CredentialsManagementPolicy.Change.IsRequirePasswordEveryXDaysAnException,

					"dataSource": "targets-fallback",
				}
				og.MergeNode(&Node{
					ID:         platformNodeID,
					Kinds:      []string{"CyberArk_Platform", "CyberArkBase"},
					Properties: SanitizeProperties(props),
				})
				platformsByID[tpID] = platformNodeID
				platformsByID[strings.ToLower(tpID)] = platformNodeID
				platformDualControl[strings.ToLower(tpID)] = tp.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsActive
				platformSessionMonitoring[strings.ToLower(tpID)] = tp.SessionManagement.RequirePrivilegedSessionMonitoringAndIsolation.IsActive
				platformSessionRecording[strings.ToLower(tpID)] = tp.SessionManagement.RecordAndSaveSessionActivity.IsActive
				if tp.SessionManagement.PSMServerID != "" {
					platformPSMServerID[strings.ToLower(tpID)] = tp.SessionManagement.PSMServerID
				}
				fallbackCount++
			}

			// Merge exception flags into the existing platform node
			node := og.Nodes[platformNodeID]
			if node != nil {
				node.Properties["dualControlIsException"] = tp.PrivilegedAccessWorkflows.RequireDualControlPasswordAccessApproval.IsAnException
				node.Properties["exclusiveAccessIsException"] = tp.PrivilegedAccessWorkflows.EnforceCheckinCheckoutExclusiveAccess.IsAnException
				node.Properties["otpIsException"] = tp.PrivilegedAccessWorkflows.EnforceOnetimePasswordAccess.IsAnException
				node.Properties["reasonForAccessIsException"] = tp.PrivilegedAccessWorkflows.RequireUsersToSpecifyReasonForAccess.IsAnException
				node.Properties["sessionMonitoringIsException"] = tp.SessionManagement.RequirePrivilegedSessionMonitoringAndIsolation.IsAnException
				node.Properties["sessionRecordingIsException"] = tp.SessionManagement.RecordAndSaveSessionActivity.IsAnException
			}
		}
		if fallbackCount > 0 {
			logger.Infof("Created %d fallback platform nodes from Targets endpoint data", fallbackCount)
		}
	}

	// Process Accounts
	accountsBySafe := make(map[string][]string)  // safeName -> []accountNodeIDs
	accountsByID := make(map[string]string)      // accountID -> accountNodeID
	accountPlatformID := make(map[string]string) // accountNodeID -> platformID (lowercase)
	accountIDToSafe := make(map[string]string)   // accountID -> safeName (for reconcile-hijack mapping)

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

		// Annotate the account with the PSM session-monitoring posture inherited
		// from its platform (used by the PSM-breakout-exposure finding). Only set
		// when platform data was available so absence is distinguishable from "off".
		if a.PlatformID != "" {
			platID := strings.ToLower(a.PlatformID)
			if mon, ok := platformSessionMonitoring[platID]; ok {
				props["sessionMonitoringEnabled"] = mon
			}
			if rec, ok := platformSessionRecording[platID]; ok {
				props["sessionRecordingEnabled"] = rec
			}
			if _, ok := platformPSMServerID[platID]; ok {
				props["managedByPSM"] = true
			}
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
			Kinds:      []string{"CyberArk_Account", "CyberArkBase"},
			Properties: SanitizeProperties(props),
		})

		accountsByID[a.ID] = accountNodeID
		if a.SafeName != "" {
			accountIDToSafe[a.ID] = a.SafeName
		}

		// Track account's platform for dual control determination
		if a.PlatformID != "" {
			accountPlatformID[accountNodeID] = strings.ToLower(a.PlatformID)
		}

		// CyberArk_UsesPlatform edge (Account → Platform)
		if a.PlatformID != "" {
			platformNodeID, ok := platformsByID[a.PlatformID]
			if !ok {
				platformNodeID, ok = platformsByID[strings.ToLower(a.PlatformID)]
			}
			if ok {
				og.AddEdge("CyberArk_UsesPlatform", accountNodeID, platformNodeID,
					"id", "id", nil, false)
			} else if len(platformsByID) > 0 && debug {
				logger.Debugf("Account %s has platformId '%s' but no matching platform node found", a.ID, a.PlatformID)
			}
		}

		// Track accounts by safe
		if a.SafeName != "" {
			accountsBySafe[a.SafeName] = append(accountsBySafe[a.SafeName], accountNodeID)

			// Add CyberArk_Contains edge (Safe -> Account)
			safeNodeID := safesByName[a.SafeName]
			if safeNodeID == "" {
				safeNodeID = strings.ToUpper(fmt.Sprintf("casafe-%s-%s", a.SafeName, pvwaTag))
			}
			og.AddEdge("CyberArk_Contains", safeNodeID, accountNodeID,
				"id", "id", nil, false)
		}

		// Add CyberArk_SyncsToADUser and CyberArk_CanConnect edges if applicable
		if a.UserName != "" && a.Address != "" {
			adKey := StripAfterAt(a.UserName)
			if adKey == "" {
				if debug {
					logger.Debugf("CyberArk_SyncsToADUser: skipping account %s — empty username after stripping '@' from '%s'", a.ID, a.UserName)
				}
				continue
			}
			addressLower := strings.TrimRight(strings.ToLower(strings.TrimSpace(a.Address)), ".")
			matched := false
			for _, domain := range targetDomains {
				domainLower := strings.ToLower(strings.TrimSpace(domain))

				if addressLower == domainLower {
					adUserName := fmt.Sprintf("%s@%s", strings.ToUpper(adKey), strings.ToUpper(domain))
					og.AddEdge("CyberArk_SyncsToADUser", accountNodeID, adUserName,
						"id", "name", map[string]interface{}{
							"inferred": true,
							"source":   "CyberArk",
							"domain":   domain,
						}, true)
					matched = true
					if debug {
						logger.Debugf("CyberArk_SyncsToADUser: account %s (user=%s, address=%s) -> %s", a.ID, a.UserName, a.Address, adUserName)
					}
					break
					// Create CyberArk_CanConnect edge from CyberArk_User to AD Computer if address is a subdomain of the target domain
				} else if strings.HasSuffix(addressLower, "."+domainLower) {
					adHostname := StripAfterDot(a.Address)
					adComputerName := fmt.Sprintf("%s.%s", strings.ToUpper(adHostname), strings.ToUpper(domain))

					// Check if computer name matches the address (prevents the computer.sub.domain.com case)
					if strings.ToLower(adComputerName) == addressLower {
						og.AddEdge("CyberArk_CanConnect", accountNodeID, adComputerName,
							"id", "name", map[string]interface{}{
								"inferred":  true,
								"source":    "CyberArk",
								"domain":    domain,
								"localUser": adKey,
							}, true)
						break
					}
				}
			}
			if !matched && debug {
				logger.Debugf("CyberArk_SyncsToADUser: account %s (user=%s, address=%q [%x]) — no target domain match (domains: %q [%x])", a.ID, a.UserName, a.Address, []byte(a.Address), targetDomains, func() [][]byte {
					var bs [][]byte
					for _, d := range targetDomains {
						bs = append(bs, []byte(d))
					}
					return bs
				}())
			}
		} else if debug && (a.UserName == "" || a.Address == "") {
			logger.Debugf("CyberArk_SyncsToADUser: skipping account %s — missing userName=%q or address=%q", a.ID, a.UserName, a.Address)
		}
	}

	// Process Applications (CCP / AIMWebService AppIDs), if provided.
	//
	// Tradecraft reference: Marat Nigmatullin (@_mnigma_, FalconForce),
	// "4 GET requests = 3 Domain admins: CyberArk magic you didn't know about"
	// (SO-CON 2026). CyberArk Applications are the identities the Central
	// Credential Provider (CCP/AIMWebService) authenticates before serving
	// credentials. An AppID whose authentication is weak or absent (no Allowed
	// Machines and no OS user / path / hash / certificate binding) can be abused
	// from anywhere that can reach the CCP endpoint to retrieve every credential
	// the application is permitted to read — frequently in a single GET request.
	applicationsByName := make(map[string]string)   // lowercase AppID -> appNodeID
	appIsUnrestricted := make(map[string]bool)      // lowercase AppID -> no auth restrictions at all
	appAllowedMachines := make(map[string][]string) // lowercase AppID -> allowed machines/IPs
	appIsDefaultCCP := make(map[string]bool)        // lowercase AppID -> is the default AIMWebService app
	if len(applications) > 0 {
		logger.Infof("Processing %d applications (CCP/AIMWebService AppIDs)...", len(applications))
		unrestrictedCount := 0
		for _, app := range applications {
			if app.AppID == "" {
				continue
			}
			appNodeID := strings.ToUpper(fmt.Sprintf("caapp-%s-%s", app.AppID, pvwaTag))
			appKey := strings.ToLower(app.AppID)

			// Summarise the authentication restrictions configured on the AppID.
			allowedMachines := make([]string, 0)
			authMethods := make([]string, 0)
			seenAuthType := make(map[string]bool)
			hasMachine := false
			hasOSUser := false
			hasPath := false
			hasHash := false
			hasCertificate := false
			for _, a := range app.Authentications {
				at := strings.ToLower(strings.TrimSpace(a.AuthType))
				if at == "" {
					continue
				}
				if !seenAuthType[at] {
					seenAuthType[at] = true
					authMethods = append(authMethods, a.AuthType)
				}
				switch at {
				case "machineaddress":
					hasMachine = true
					if a.AuthValue != "" {
						allowedMachines = append(allowedMachines, a.AuthValue)
					}
				case "osuser":
					hasOSUser = true
				case "path":
					hasPath = true
				case "hash":
					hasHash = true
				case "certificateserialnumber", "certificateattributes", "certificate":
					hasCertificate = true
				}
			}

			// "Unrestricted" = nothing binds the AppID to a caller. Knowing the
			// AppID is sufficient to retrieve credentials via the CCP endpoint.
			isUnrestricted := !hasMachine && !hasOSUser && !hasPath && !hasHash && !hasCertificate
			if isUnrestricted {
				unrestrictedCount++
			}
			// The out-of-the-box CCP application ("AIMWebService") most likely has
			// access to all safes and is a prime target (Nigmatullin, SO-CON 2026).
			isDefaultCCP := appKey == "aimwebservice"

			businessOwnerName := strings.TrimSpace(fmt.Sprintf("%s %s", app.BusinessOwnerFName, app.BusinessOwnerLName))

			props := map[string]interface{}{
				"id":                        appNodeID,
				"name":                      app.AppID,
				"appId":                     app.AppID,
				"description":               app.Description,
				"location":                  app.Location,
				"disabled":                  asBool(app.Disabled),
				"businessOwnerName":         businessOwnerName,
				"businessOwnerEmail":        app.BusinessOwnerEmail,
				"businessOwnerPhone":        app.BusinessOwnerPhone,
				"allowedMachines":           allowedMachines,
				"authMethods":               authMethods,
				"hasMachineRestriction":     hasMachine,
				"hasOSUserRestriction":      hasOSUser,
				"hasPathRestriction":        hasPath,
				"hasHashRestriction":        hasHash,
				"hasCertificateRestriction": hasCertificate,
				"isUnrestricted":            isUnrestricted,
				"isDefaultCCPApp":           isDefaultCCP,
			}

			og.MergeNode(&Node{
				ID:         appNodeID,
				Kinds:      []string{"CyberArk_Application", "CyberArkBase"},
				Properties: SanitizeProperties(props),
			})

			applicationsByName[appKey] = appNodeID
			appIsUnrestricted[appKey] = isUnrestricted
			appAllowedMachines[appKey] = allowedMachines
			appIsDefaultCCP[appKey] = isDefaultCCP

			// CyberArk_CCPAllowedFrom external edges (Application → AD Computer).
			// The Allowed Machines list is the set of hosts permitted to present
			// this AppID to the CCP endpoint. When machineIsOnlyRestriction is true,
			// landing on one of these hosts is sufficient to wield the AppID — there
			// is no OS user / path / hash / certificate factor to also satisfy.
			machineIsOnlyRestriction := hasMachine && !hasOSUser && !hasPath && !hasHash && !hasCertificate
			for _, machine := range allowedMachines {
				m := strings.TrimSpace(machine)
				if m == "" {
					continue
				}
				og.AddEdge("CyberArk_CCPAllowedFrom", appNodeID, strings.ToUpper(m),
					"id", "name", map[string]interface{}{
						"machine":                  m,
						"machineIsOnlyRestriction": machineIsOnlyRestriction,
						"targetIsIP":               looksLikeIP(m),
						"inferred":                 true,
						"source":                   "CyberArk",
					}, true)
			}
		}
		logger.Infof("Created %d CyberArk_Application nodes (%d with no authentication restrictions)", len(applicationsByName), unrestrictedCount)
	}

	// Process Safe Members and create permission edges
	logger.Infof("Processing %d safe members...", len(safeMembers))

	// Pre-compute which safes have approvers (members with L1/L2 authorization).
	// This is used together with the platform's requireDualControlPasswordAccessApproval
	// setting to determine whether dual control is practically enforceable for each account.
	safesWithApprovers := make(map[string]bool)
	for _, sm := range safeMembers {
		for permKey, permVal := range sm.Permissions {
			normKey := NormPermName(permKey)
			isGranted := false
			switch v := permVal.(type) {
			case bool:
				isGranted = v
			case string:
				isGranted = strings.ToLower(v) == "true"
			}
			if isGranted && (normKey == "requestsauthorizationlevel1" || normKey == "requestsauthorizationlevel2") {
				safesWithApprovers[sm.SafeName] = true
				break
			}
		}
	}

	// Track safe permissions for user/group nodes
	userSafePerms := make(map[string][]map[string]interface{})
	groupSafePerms := make(map[string][]map[string]interface{})

	// Track principals who can introduce or control accounts in each safe. These
	// are the candidates for reconcile-account hijack: with addAccounts/manageSafe
	// on a safe whose platform has a reconcile account, a principal can create or
	// redirect an account so the CPM uses the (privileged) reconcile account
	// against a target of their choosing (Nigmatullin, SO-CON 2026).
	type reconcileManager struct {
		nodeID string
		perms  []string
	}
	safeManagers := make(map[string][]reconcileManager) // safeName -> principals with account-management rights

	for idx, sm := range safeMembers {
		if (idx+1)%memberInterval == 0 || idx+1 == len(safeMembers) {
			logger.Infof("  Processed %d/%d safe members (%.1f%%)", idx+1, len(safeMembers), float64(idx+1)/float64(len(safeMembers))*100)
		}

		if sm.MemberName == "" || sm.SafeName == "" {
			continue
		}

		// Application (CCP/AIMWebService AppID) safe members are routed to
		// CyberArk_CanRetrieveViaCCP edges instead of user/group access edges.
		// An application is recognised either by its CyberArk member type or by
		// matching the name of an AppID we collected from the Applications API.
		appKey := strings.ToLower(sm.MemberName)
		appNodeID, isApplication := applicationsByName[appKey]
		if !isApplication && strings.ToLower(sm.MemberType) == "application" {
			// Member is an application but was not in (or we did not collect) the
			// Applications list — create a minimal node so the edge has an anchor.
			appNodeID = strings.ToUpper(fmt.Sprintf("caapp-%s-%s", sm.MemberName, pvwaTag))
			og.MergeNode(&Node{
				ID:    appNodeID,
				Kinds: []string{"CyberArk_Application", "CyberArkBase"},
				Properties: SanitizeProperties(map[string]interface{}{
					"id":              appNodeID,
					"name":            sm.MemberName,
					"appId":           sm.MemberName,
					"isDefaultCCPApp": appKey == "aimwebservice",
				}),
			})
			applicationsByName[appKey] = appNodeID
			isApplication = true
		}

		if isApplication {
			// Determine whether the application can retrieve/use credentials in this safe.
			canRetrieve := false
			canUse := false
			grantedPerms := make([]string, 0)
			for permKey, permVal := range sm.Permissions {
				normKey := NormPermName(permKey)
				granted := false
				switch v := permVal.(type) {
				case bool:
					granted = v
				case string:
					granted = strings.ToLower(v) == "true"
				}
				if !granted {
					continue
				}
				grantedPerms = append(grantedPerms, permKey)
				switch normKey {
				case "retrieveaccounts":
					canRetrieve = true
				case "useaccounts":
					canUse = true
				}
			}

			if canRetrieve || canUse {
				for _, accountNodeID := range accountsBySafe[sm.SafeName] {
					og.AddEdge("CyberArk_CanRetrieveViaCCP", appNodeID, accountNodeID,
						"id", "id", map[string]interface{}{
							"safeName":            sm.SafeName,
							"permissions":         grantedPerms,
							"canRetrievePassword": canRetrieve,
							"appIsUnrestricted":   appIsUnrestricted[appKey],
							"allowedMachines":     appAllowedMachines[appKey],
							"isDefaultCCPApp":     appIsDefaultCCP[appKey],
							"inferred":            false,
						}, false)
				}
			}
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
		canManageAccounts := false
		mgmtPermNames := make([]string, 0)

		for normPerm := range normalizedPerms {
			if AccountAccessPermissions[normPerm] {
				hasDirectAccess = true
			}
			if EscalationPermissions[normPerm] {
				canGrantAccess = true
			}
			if ReconcileHijackPermissions[normPerm] {
				canManageAccounts = true
			}
			if AccountManagementPermissions[normPerm] {
				mgmtPermNames = append(mgmtPermNames, normPerm)
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

		// Record principals able to introduce/control accounts in this safe so
		// reconcile-hijack edges can be built once linked-account data is processed.
		if canManageAccounts {
			safeManagers[sm.SafeName] = append(safeManagers[sm.SafeName], reconcileManager{
				nodeID: memberNodeID,
				perms:  mgmtPermNames,
			})
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
			// Create edges to each account in the safe.
			// Dual control determination is per-account based on its platform's effective policy:
			//
			// 1. Primary: The platform's requireDualControlPasswordAccessApproval field
			//    reflects the effective Master Policy (including platform-level exceptions).
			//    This is the authoritative source for whether dual control is enabled.
			//
			// 2. Secondary: The safe must have at least one member with L1/L2 approval
			//    permissions for dual control to be practically enforceable — without
			//    approvers, no one can approve requests regardless of policy.
			//
			// 3. Bypass: A member with accessWithoutConfirmation=true can skip approval
			//    even when dual control is active.
			//
			// When platform data is not available (--include-platforms not used), we fall
			// back to the approver-presence heuristic: if the safe has members with L1/L2
			// permissions, we assume dual control is likely intended.
			accountsInSafe := accountsBySafe[sm.SafeName]
			for _, accountNodeID := range accountsInSafe {
				platID := accountPlatformID[accountNodeID]
				requiresApproval := false
				if !accessWithoutConfirmation {
					_, platformLoaded := platformDualControl[platID]
					if platID != "" && platformLoaded {
						// Platform data available: use the authoritative policy setting,
						// but only if the safe actually has approvers to enforce it
						requiresApproval = platformDualControl[platID] && safesWithApprovers[sm.SafeName]
					} else {
						// No platform data for this account: fall back to approver-presence
						// heuristic. This occurs when --include-platforms is not used, or when
						// the account's platformId doesn't match any loaded platform.
						requiresApproval = safesWithApprovers[sm.SafeName]
					}
				}
				// Look up session management properties from the account's platform
				requiresSessionMonitoring := false
				recordsSessionActivity := false
				if platID != "" {
					requiresSessionMonitoring = platformSessionMonitoring[platID]
					recordsSessionActivity = platformSessionRecording[platID]
				}

				og.AddEdge("CyberArk_HasAccessTo", memberNodeID, accountNodeID,
					"id", "id", map[string]interface{}{
						"safeName":                  sm.SafeName,
						"permissions":               matchedPermNames,
						"inferred":                  false,
						"requiresApproval":          requiresApproval,
						"requiresSessionMonitoring": requiresSessionMonitoring,
						"recordsSessionActivity":    recordsSessionActivity,
					}, false)
			}
		}

		if canGrantAccess {
			// Create edge to the safe (privilege escalation path)
			og.AddEdge("CyberArk_CanGrantAccessTo", memberNodeID, safeNodeID,
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
			og.AddEdge("CyberArk_CanApprove", memberNodeID, safeNodeID,
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
			logger.Debug("=== CyberArk_UsedAccount Edge Creation Debug ===")
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

				og.AddEdge("CyberArk_UsedAccount", userNodeID, accountNodeID,
					"id", "id", map[string]interface{}{
						"lastUsedTime": usageData["lastUsedTime"],
						"lastActivity": usageData["lastAction"],
						"usageCount":   usageData["usageCount"],
						"inferred":     false,
					}, false)
				activityEdgeCount++
			}
		}

		logger.Infof("Created %d CyberArk_UsedAccount edges from activity data", activityEdgeCount)
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

				og.AddEdge("CyberArk_LinkedTo", sourceNodeID, targetNodeID,
					"id", "id", map[string]interface{}{
						"linkType": linkType,
						"linkName": link.Name,
						"safeName": link.SafeName,
					}, false)
				linkedEdgeCount++
			}
		}

		logger.Infof("Created %d CyberArk_LinkedTo edges from linked account data", linkedEdgeCount)

		// Build CyberArk_CanHijackViaReconcile edges (Principal → reconcile account).
		//
		// Tradecraft reference: Marat Nigmatullin (FalconForce), SO-CON 2026 —
		// "Hijacking accounts under a platform with a Reconcile Account". When a
		// principal can introduce or control accounts in a safe (addAccounts /
		// manageSafe), and that safe holds accounts whose platform defines a
		// privileged reconcile account, the principal can create or redirect an
		// account so the CPM uses that reconcile account to reset a target of
		// their choosing. The reconcile account is the privileged credential being
		// wielded, so the edge points to it; its own downstream edges
		// (CyberArk_SyncsToADUser, etc.) bound the blast radius.
		reconcileHijackEdges := 0
		for accountID, links := range linkedAccounts {
			sourceSafe := accountIDToSafe[accountID]
			if sourceSafe == "" {
				continue
			}
			managers := safeManagers[sourceSafe]
			if len(managers) == 0 {
				continue
			}
			for _, link := range links {
				if link.ExtraPassID != 3 { // only reconcile accounts
					continue
				}
				reconcileNodeID := accountsByID[link.AccountID]
				if reconcileNodeID == "" && link.AccountID != "" {
					reconcileNodeID = strings.ToUpper(fmt.Sprintf("caaccount-%s-%s", link.AccountID, pvwaTag))
				}
				if reconcileNodeID == "" {
					continue
				}
				for _, mgr := range managers {
					og.AddEdge("CyberArk_CanHijackViaReconcile", mgr.nodeID, reconcileNodeID,
						"id", "id", map[string]interface{}{
							"viaSafe":     sourceSafe,
							"permissions": mgr.perms,
							"linkType":    "reconcile",
							"linkName":    link.Name,
							"inferred":    true,
						}, false)
					reconcileHijackEdges++
				}
			}
		}
		if reconcileHijackEdges > 0 {
			logger.Infof("Created %d CyberArk_CanHijackViaReconcile edges", reconcileHijackEdges)
		}
	}

	// Process PSM Servers (if provided)
	psmServersByID := make(map[string]string) // PSMServerID -> psmServerNodeID
	if len(psmServers) > 0 {
		logger.Infof("Processing %d PSM servers...", len(psmServers))
		for _, ps := range psmServers {
			if ps.ID == "" {
				continue
			}
			psmNodeID := strings.ToUpper(fmt.Sprintf("capsmserver-%s-%s", ps.ID, pvwaTag))

			og.MergeNode(&Node{
				ID:    psmNodeID,
				Kinds: []string{"CyberArk_PSMServer", "CyberArkBase"},
				Properties: SanitizeProperties(map[string]interface{}{
					"id":          psmNodeID,
					"psmServerId": ps.ID,
					"name":        ps.Name,
					"address":     ps.Address,
				}),
			})

			psmServersByID[ps.ID] = psmNodeID
		}
		logger.Infof("Created %d CyberArk_PSMServer nodes", len(psmServersByID))

		// Create CyberArk_UsesPSMServer edges (Platform → PSM Server)
		psmEdgeCount := 0
		for platID, psmSrvID := range platformPSMServerID {
			platNodeID, ok := platformsByID[platID]
			if !ok {
				continue
			}
			psmNodeID, ok := psmServersByID[psmSrvID]
			if !ok {
				if debug {
					logger.Debugf("Platform %s references PSMServerID '%s' but no matching PSM server node found", platID, psmSrvID)
				}
				continue
			}
			og.AddEdge("CyberArk_UsesPSMServer", platNodeID, psmNodeID,
				"id", "id", nil, false)
			psmEdgeCount++
		}
		logger.Infof("Created %d CyberArk_UsesPSMServer edges", psmEdgeCount)

		// Create CyberArk_ManagedByPSM edges (Account → PSM Server)
		accountPSMEdgeCount := 0
		for accountNodeID, platID := range accountPlatformID {
			psmSrvID, ok := platformPSMServerID[platID]
			if !ok {
				continue
			}
			psmNodeID, ok := psmServersByID[psmSrvID]
			if !ok {
				continue
			}
			og.AddEdge("CyberArk_ManagedByPSM", accountNodeID, psmNodeID,
				"id", "id", nil, false)
			accountPSMEdgeCount++
		}
		logger.Infof("Created %d CyberArk_ManagedByPSM edges", accountPSMEdgeCount)

		// Create CyberArk_PSMServerHostedOn external edges (PSM Server → AD Computer)
		psmHostedOnCount := 0
		for _, ps := range psmServers {
			addr := strings.TrimSpace(ps.Address)
			if addr == "" {
				continue
			}
			psmNodeID, ok := psmServersByID[ps.ID]
			if !ok {
				continue
			}
			og.AddEdge("CyberArk_PSMServerHostedOn", psmNodeID, strings.ToUpper(addr),
				"id", "name", nil, true)
			psmHostedOnCount++
		}
		logger.Infof("Created %d CyberArk_PSMServerHostedOn edges", psmHostedOnCount)
	}

	// Process Connection Components (if provided)
	if len(connectionComponents) > 0 {
		logger.Infof("Processing %d connection components...", len(connectionComponents))
		connCompNodeCount := 0
		connCompsByID := make(map[string]string) // connectorID (lowercase) -> connCompNodeID

		for _, cc := range connectionComponents {
			if cc.ID == "" {
				continue
			}
			connCompNodeID := strings.ToUpper(fmt.Sprintf("caconncomp-%s-%s", cc.ID, pvwaTag))

			og.MergeNode(&Node{
				ID:    connCompNodeID,
				Kinds: []string{"CyberArk_ConnectionComponent", "CyberArkBase"},
				Properties: SanitizeProperties(map[string]interface{}{
					"id":          connCompNodeID,
					"connectorId": cc.ID,
					"displayName": cc.DisplayName,
				}),
			})

			connCompsByID[strings.ToLower(cc.ID)] = connCompNodeID
			connCompNodeCount++
		}
		logger.Infof("Created %d CyberArk_ConnectionComponent nodes", connCompNodeCount)

		// Create CyberArk_HasConnectionComponent edges (Platform → Connection Component)
		if platformConnectors != nil {
			connCompEdgeCount := 0
			for platID, connectorIDs := range platformConnectors {
				platNodeID, ok := platformsByID[platID]
				if !ok {
					platNodeID, ok = platformsByID[strings.ToLower(platID)]
				}
				if !ok {
					if debug {
						logger.Debugf("Platform '%s' from platformConnectors not found in platformsByID", platID)
					}
					continue
				}
				for _, connID := range connectorIDs {
					connCompNodeID, ok := connCompsByID[strings.ToLower(connID)]
					if !ok {
						if debug {
							logger.Debugf("Platform %s references connector '%s' but no matching connection component node found", platID, connID)
						}
						continue
					}
					og.AddEdge("CyberArk_HasConnectionComponent", platNodeID, connCompNodeID,
						"id", "id", map[string]interface{}{"enabled": true}, false)
					connCompEdgeCount++
				}
			}
			logger.Infof("Created %d CyberArk_HasConnectionComponent edges", connCompEdgeCount)
		} else {
			logger.Infof("No platform-to-connector mapping available; skipping CyberArk_HasConnectionComponent edges")
		}
	}

	// Create the CyberArk_Instance environment root node and connect it to the
	// bounded set of top-level configuration objects via CyberArk_InstanceContains.
	//
	// Users and Groups are intentionally NOT linked here. In LDAP/AD-integrated
	// vaults they can number in the millions (every directory-synced principal
	// becomes a node), so fanning out an InstanceContains edge to each one blows
	// up the export (observed 3.3M+ edges) without adding navigational value —
	// users and groups already attach to the graph through their membership and
	// safe-permission edges (CyberArk_MemberOf, CyberArk_HasAccessTo,
	// CyberArk_CanGrantAccessTo, CyberArk_CanApprove, CyberArk_Created, etc.).
	//
	// Accounts are likewise not linked here — they remain nested under their safe
	// via CyberArk_Contains (Instance → Safe → Account), mirroring hierarchical
	// containment.
	instanceNodeID := strings.ToUpper(fmt.Sprintf("cainstance-%s", pvwaTag))
	og.MergeNode(&Node{
		ID:    instanceNodeID,
		Kinds: []string{"CyberArk_Instance", "CyberArkBase"},
		Properties: SanitizeProperties(map[string]interface{}{
			"id":      instanceNodeID,
			"name":    pvwaTag,
			"pvwaTag": pvwaTag,
		}),
	})

	instanceChildKinds := map[string]bool{
		"CyberArk_Safe":                true,
		"CyberArk_Platform":            true,
		"CyberArk_PSMServer":           true,
		"CyberArk_ConnectionComponent": true,
		"CyberArk_Application":         true,
	}
	instanceEdgeCount := 0
	for nodeID, node := range og.Nodes {
		if nodeID == instanceNodeID {
			continue
		}
		for _, k := range node.Kinds {
			if instanceChildKinds[k] {
				og.AddEdge("CyberArk_InstanceContains", instanceNodeID, nodeID,
					"id", "id", nil, false)
				instanceEdgeCount++
				break
			}
		}
	}
	logger.Infof("Created CyberArk_Instance node (%s) and %d CyberArk_InstanceContains edges", instanceNodeID, instanceEdgeCount)

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

// isWildcardAllowedSafes reports whether a platform's AllowedSafes restriction is
// effectively unrestricted (matches any safe). The talk by Marat Nigmatullin
// (SO-CON 2026) highlights AllowedSafes=.* as an over-permissive setting that
// lets a platform's reconcile/logon accounts be attached to unexpected safes.
// An empty value or one of the common "match everything" regular expressions is
// treated as a wildcard.
func isWildcardAllowedSafes(allowedSafes string) bool {
	s := strings.TrimSpace(allowedSafes)
	switch s {
	case "", ".*", ".*.", "^.*$", "(.*)", ".+":
		return true
	}
	return false
}

// looksLikeIP reports whether s is an IPv4/IPv6 literal (as opposed to a
// hostname/FQDN). Allowed Machines may be expressed as either; IP literals will
// not match a BloodHound Computer node by name, so callers can flag them.
func looksLikeIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

// asBool best-effort coerces a value that CyberArk may return as a bool, a
// string ("true"/"false", "yes"/"no", "1"/"0"), or a number into a boolean.
func asBool(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "yes", "1":
			return true
		}
		return false
	case float64:
		return t != 0
	case int:
		return t != 0
	default:
		return false
	}
}
