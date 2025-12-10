package models

// User represents a CyberArk user
type User struct {
	ID                           interface{}              `json:"id"`
	Username                     string                   `json:"username"`
	Source                       string                   `json:"source"`
	UserType                     string                   `json:"userType"`
	ComponentUser                bool                     `json:"componentUser"`
	Enabled                      bool                     `json:"enabled"`
	Suspended                    bool                     `json:"suspended"`
	VaultAuthorization           []interface{}            `json:"vaultAuthorization"`
	AuthorizedInterfaces         []string                 `json:"authorizedInterfaces"`
	Location                     string                   `json:"location"`
	UserDN                       string                   `json:"userDN"`
	AllowedAuthenticationMethods []string                 `json:"allowedAuthenticationMethods"`
	GroupsMembership             []UserGroupMembership    `json:"groupsMembership"`
	PersonalDetails              PersonalDetails          `json:"personalDetails"`
}

// UserGroupMembership represents a group membership entry for a user
type UserGroupMembership struct {
	GroupID   interface{} `json:"groupID"`
	GroupName string      `json:"groupName"`
	GroupType string      `json:"groupType"`
}

// PersonalDetails represents the personal details of a user
type PersonalDetails struct {
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	MiddleName     string `json:"middleName"`
	Email          string `json:"email"`
	BusinessEmail  string `json:"businessEmail"`
	HomeEmail      string `json:"homeEmail"`
	BusinessPhone  string `json:"businessPhone"`
	HomePhone      string `json:"homePhone"`
	MobilePhone    string `json:"mobilePhone"`
	FaxNumber      string `json:"faxNumber"`
	Title          string `json:"title"`
	Organization   string `json:"organization"`
	Department     string `json:"department"`
	Profession     string `json:"profession"`
	Street         string `json:"street"`
	City           string `json:"city"`
	State          string `json:"state"`
	Zip            string `json:"zip"`
	Country        string `json:"country"`
}

// Group represents a CyberArk user group
type Group struct {
	ID            interface{}   `json:"id"`
	GroupName     string        `json:"groupName"` // Sometimes just "name" in some contexts, but API usually returns groupName or name
	Description   string        `json:"description"`
	GroupType     string        `json:"groupType"`
	Location      string        `json:"location"`
	Directory     string        `json:"directory"`
	DN            string        `json:"dn"`
	Members       []GroupMember `json:"members"`
}

// GroupMember represents a member of a group
type GroupMember struct {
	MemberName string `json:"memberName"`
	MemberType string `json:"memberType"`
	// Handle variance where sometimes it might be "username"
	Username   string `json:"username,omitempty"`
}

// SafeCreator represents the creator of a safe
type SafeCreator struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Safe represents a CyberArk safe
type Safe struct {
	SafeUrlId                 string      `json:"safeUrlId"`
	SafeName                  string      `json:"safeName"`
	SafeNumber                int         `json:"safeNumber"`
	Description               string      `json:"description"`
	Location                  string      `json:"location"`
	Creator                   SafeCreator `json:"creator"`
	OlacEnabled               bool        `json:"olacEnabled"`
	ManagingCPM               string      `json:"managingCPM"`
	NumberOfVersionsRetention int     `json:"numberOfVersionsRetention"`
	NumberOfDaysRetention     int     `json:"numberOfDaysRetention"`
	AutoPurgeEnabled          bool    `json:"autoPurgeEnabled"`
	CreationTime              float64 `json:"creationTime"`
	LastModificationTime      float64 `json:"lastModificationTime"`
	IsExpiredMembershipEnable bool    `json:"isExpiredMembershipEnable"`
}

// SafeMember represents a member of a safe with permissions
type SafeMember struct {
	MemberName   string                 `json:"memberName"`
	MemberType   string                 `json:"memberType"`
	SafeName     string                 `json:"safeName"`
	SafeUrlId    string                 `json:"safeUrlId"`
	Permissions  map[string]interface{} `json:"permissions"`
	MembershipExpirationDate float64    `json:"membershipExpirationDate,omitempty"`
}

// Account represents a CyberArk account
type Account struct {
	ID                         string                 `json:"id"`
	Name                       string                 `json:"name"`
	Address                    string                 `json:"address"`
	UserName                   string                 `json:"userName"`
	PlatformID                 string                 `json:"platformId"`
	SafeName                   string                 `json:"safeName"`
	SafeUrlId                  string                 `json:"safeUrlId"`
	SecretType                 string                 `json:"secretType"`
	PlatformAccountProperties  map[string]interface{} `json:"platformAccountProperties"`
	SecretManagement           map[string]interface{} `json:"secretManagement"`
	CreatedTime                float64                `json:"createdTime"`
	LastModifiedTime           float64                `json:"lastModifiedTime"`
	LastVerifiedTime           float64                `json:"lastVerifiedTime"`
	LastReconciledTime         float64                `json:"lastReconciledTime"`
	CategoryModificationTime   float64                `json:"categoryModificationTime"`
	Status                     string                 `json:"status"` // Active, Archived, etc.
	Disabled                   bool                   `json:"disabled"`
	AutomaticManagementEnabled bool                   `json:"automaticManagementEnabled"`
	ManualManagementReason     string                 `json:"manualManagementReason"`
	LastModifiedBy             string                 `json:"lastModifiedBy"`
}

// AccountActivity represents an activity log for an account
type AccountActivity struct {
	ID             string  `json:"id"` // usually numeric string
	Date           interface{} `json:"Date"` // can be float64 timestamp or other format
	Action         string  `json:"Action"`
	User           string  `json:"User"`
	Activity       string  `json:"Activity"`
	Reason         string  `json:"Reason"`
	MoreInfo       string  `json:"MoreInfo"`
	IPAddress      string  `json:"IPAddress"`
}
