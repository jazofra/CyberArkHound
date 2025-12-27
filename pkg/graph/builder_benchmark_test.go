package graph

import (
	"fmt"
	"io"
	"testing"

	"github.com/siemens-healthineers/cyberarkhound/pkg/models"
	"github.com/sirupsen/logrus"
)

func BenchmarkBuildOpenGraph(b *testing.B) {
	// Disable logging for benchmark
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	// Setup mock data
	users := make([]models.User, 1000)
	for i := 0; i < 1000; i++ {
		users[i] = models.User{
			ID:       i,
			Username: fmt.Sprintf("User%d", i),
			Source:   "LDAP",
			UserDN:   fmt.Sprintf("CN=User%d,OU=Users,DC=example,DC=com", i),
			GroupsMembership: []models.UserGroupMembership{
				{GroupName: fmt.Sprintf("Group%d", i%100)},
			},
		}
	}

	groups := make([]models.Group, 100)
	for i := 0; i < 100; i++ {
		groups[i] = models.Group{
			ID:        i,
			GroupName: fmt.Sprintf("Group%d", i),
			DN:        fmt.Sprintf("CN=Group%d,OU=Groups,DC=example,DC=com", i),
		}
	}

	safes := make([]models.Safe, 100)
	for i := 0; i < 100; i++ {
		safes[i] = models.Safe{
			SafeName: fmt.Sprintf("Safe%d", i),
			Creator:  models.SafeCreator{Name: "Admin"},
		}
	}

	accounts := make([]models.Account, 2000)
	for i := 0; i < 2000; i++ {
		accounts[i] = models.Account{
			ID:       fmt.Sprintf("Acc%d", i),
			UserName: fmt.Sprintf("User%d", i),
			Address:  "example.com",
			SafeName: fmt.Sprintf("Safe%d", i%100),
		}
	}

	safeMembers := make([]models.SafeMember, 500)
	for i := 0; i < 500; i++ {
		safeMembers[i] = models.SafeMember{
			SafeName:   fmt.Sprintf("Safe%d", i%100),
			MemberName: fmt.Sprintf("User%d", i),
			MemberType: "User",
			Permissions: map[string]interface{}{
				"UseAccounts":      true,
				"RetrieveAccounts": true,
			},
		}
	}

	targetDomains := []string{"example.com"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := BuildOpenGraph(users, groups, safes, safeMembers, accounts, targetDomains, nil, logger, false, "INFO")
		if err != nil {
			b.Fatal(err)
		}
	}
}
