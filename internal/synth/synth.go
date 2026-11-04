// Package synth generates synthetic CyberArk collections for benchmarks.
package synth

import (
	"fmt"
	"math/rand"

	"github.com/siemens-healthineers/cyberarkhound/pkg/graph"
	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
)

// Vault returns graph-builder input for a vault with the given number of
// safes, each holding accountsPerSafe accounts and eight members, and with
// users and groups scaled to match. The same arguments always produce the
// same data.
func Vault(safes, accountsPerSafe int) graph.BuildInput {
	r := rand.New(rand.NewSource(1))
	users, groups := safes*4, safes/5+1

	in := graph.BuildInput{
		PVWATag:           "SYNT",
		TargetDomains:     []string{"corp.local"},
		Platforms:         []models.Platform{{General: models.PlatformGeneral{ID: "WinServer", Name: "WinServer"}}},
		LinkedAccounts:    map[string][]models.LinkedAccount{},
		AccountActivities: map[string][]models.AccountActivity{},
	}
	for g := 0; g < groups; g++ {
		var members []models.GroupMember
		for m := 0; m < 30; m++ {
			members = append(members, models.GroupMember{Username: fmt.Sprintf("user%d", r.Intn(users))})
		}
		in.Groups = append(in.Groups, models.Group{ID: float64(g), GroupName: fmt.Sprintf("Group%d", g),
			DN: fmt.Sprintf("CN=Group%d,OU=Groups,DC=corp,DC=local", g), Directory: "corp.local", Members: members})
	}
	for u := 0; u < users; u++ {
		in.Users = append(in.Users, models.User{ID: float64(u), Username: fmt.Sprintf("user%d", u), Source: "LDAP", Enabled: true,
			UserDN:           fmt.Sprintf("CN=User %d,OU=Users,DC=corp,DC=local", u),
			GroupsMembership: []models.UserGroupMembership{{GroupName: fmt.Sprintf("Group%d", r.Intn(groups))}}})
	}
	for i := 0; i < safes; i++ {
		safe := fmt.Sprintf("Safe%d", i)
		in.Safes = append(in.Safes, models.Safe{SafeName: safe, SafeUrlId: safe, ManagingCPM: "PasswordManager"})
		for m := 0; m < 8; m++ {
			perms := map[string]interface{}{"listAccounts": true, "useAccounts": m%2 == 0, "retrieveAccounts": m%3 == 0,
				"manageSafeMembers": m == 7, "requestsAuthorizationLevel1": m == 6}
			member := models.SafeMember{MemberName: fmt.Sprintf("user%d", r.Intn(users)), MemberType: "User", SafeName: safe, Permissions: perms}
			if m < 4 {
				member.MemberName, member.MemberType = fmt.Sprintf("Group%d", r.Intn(groups)), "Group"
			}
			in.SafeMembers = append(in.SafeMembers, member)
		}
		for a := 0; a < accountsPerSafe; a++ {
			id := fmt.Sprintf("%d_%d", i, a)
			in.Accounts = append(in.Accounts, models.Account{ID: id, UserName: fmt.Sprintf("svc%d", a), SafeName: safe, PlatformID: "WinServer",
				Address: fmt.Sprintf("srv%d.corp.local", r.Intn(safes*4))})
			if a%3 == 0 {
				in.LinkedAccounts[id] = []models.LinkedAccount{{AccountID: fmt.Sprintf("%d_%d", r.Intn(safes), r.Intn(accountsPerSafe)), ExtraPassID: 3, Name: "reconcile"}}
			}
			if a%5 == 0 {
				in.AccountActivities[id] = []models.AccountActivity{{User: fmt.Sprintf("user%d", r.Intn(users)), Action: "Retrieve password", Date: float64(1700000000)}}
			}
		}
	}
	return in
}
