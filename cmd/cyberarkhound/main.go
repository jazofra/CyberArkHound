package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/siemens-healthineers/cyberarkhound/pkg/client"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// passwordEnvVar is read when --password is not given, so the secret does not
// have to appear on the command line (where any local user can see it in the
// process list).
const passwordEnvVar = "CYBERARK_PASSWORD"

// Exit codes.
const (
	exitOK          = 0
	exitError       = 1
	exitInterrupted = 130 // conventional for SIGINT
)

// config holds the parsed command line.
type config struct {
	pvwaURL       string
	username      string
	password      string
	passwordFlag  bool // password came from --password
	authMethod    string
	identityURL   string
	outputFile    string
	targetDomains []string
	parseSAM      bool

	workers                    int
	insecure                   bool
	caBundle                   string
	logLevel                   logrus.Level
	requestTimeout             time.Duration
	authTimeout                time.Duration
	userExtendedDetailsTimeout time.Duration
	safePageLimit              int
	maxReauthAttempts          int
	maxRateLimitRetries        int
	continueOnError            bool

	includeActivity          bool
	activityDays             int
	activityLimit            int
	includeLinkedAccounts    bool
	includePlatforms         bool
	includePSM               bool
	includeApplications      bool
	includePredefinedMembers bool

	limitUsers  int
	limitGroups int
	limitSafes  int
	testSafe    string

	findingsOutput string
	saveRaw        string
	fromRaw        string
	resume         string

	// checkpointInterval is how often a collection saves its progress
	// (zero means defaultCheckpointInterval). Not a flag; tests shorten it.
	checkpointInterval time.Duration
	// explicit records which collection-option flags were set on the
	// command line, so a resumed collection can say which ones it ignores.
	explicit map[string]bool
}

// resumeOptionFlags are the flags whose values a resumed collection takes
// from the original run instead of the command line.
var resumeOptionFlags = []string{"limit-users", "limit-groups", "limit-safes", "test-safe", "activity-days", "activity-limit", "include-predefined-members"}

// usageError is a command-line mistake; the caller prints usage after it.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func newFlagSet(cfg *config) (*pflag.FlagSet, *string, *bool, *bool) {
	fs := pflag.NewFlagSet("cyberarkhound", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.pvwaURL, "pvwa", "", "PVWA / Privilege Cloud base URL (required)")
	fs.StringVar(&cfg.username, "username", "", "API username (or OAuth client_id for --auth-method identity) (required)")
	fs.StringVar(&cfg.password, "password", "", "API password (or OAuth client_secret for --auth-method identity). Prefer the "+passwordEnvVar+" environment variable or the interactive prompt: a value given here is visible in the process list")
	fs.StringVar(&cfg.authMethod, "auth-method", "cyberark", "Authentication method: cyberark, ldap, radius, windows (self-hosted PVWA), or identity (Privilege Cloud / ISPSS SaaS)")
	fs.StringVar(&cfg.identityURL, "identity-url", "", "CyberArk Identity tenant URL for --auth-method identity (e.g. https://<tenant>.id.cyberark.cloud)")
	fs.StringVar(&cfg.outputFile, "output", "", "Output file (required). A .zip extension writes the JSON inside a zip archive")
	fs.StringSliceVar(&cfg.targetDomains, "target-domains", []string{}, "Target AD domain(s) for CyberArk_SyncsToADUser edges (required)")
	fs.BoolVar(&cfg.parseSAM, "parse-samaccountname", false, "Parse sAMAccountName/GID from LDAP distinguishedName CN for CyberArk_SyncsToUser edges (optional)")

	fs.IntVar(&cfg.workers, "workers", 50, "Concurrent workers for account detail retrieval")

	quiet := fs.Bool("quiet", false, "Suppress verbose logs")
	fs.BoolVar(&cfg.insecure, "insecure", false, "Disable SSL verification (insecure)")
	fs.StringVar(&cfg.caBundle, "ca-bundle", "", "Path to CA bundle file")
	debug := fs.Bool("debug", false, "Enable debug logging")
	logLevel := fs.String("log-level", "INFO", "Set logging level: DEBUG, INFO, WARNING, ERROR (case-insensitive)")
	fs.DurationVar(&cfg.requestTimeout, "request-timeout", 360*time.Second, "HTTP request timeout (e.g. 10m, 600s)")
	fs.DurationVar(&cfg.authTimeout, "auth-timeout", 360*time.Second, "Authentication timeout (e.g. 2m, 120s)")
	fs.DurationVar(&cfg.userExtendedDetailsTimeout, "user-extended-details-timeout", client.UserExtendedDetailsTimeout, "Timeout for optional Users?ExtendedDetails=true before falling back to basic users")
	fs.IntVar(&cfg.safePageLimit, "safe-page-limit", client.SafePageLimit, "Safes page size for /API/safes pagination (lower can help slow or error-prone PVWA)")
	fs.IntVar(&cfg.maxReauthAttempts, "max-reauth-attempts", 5, "Max re-authentication attempts on HTTP 401 before giving up")
	fs.IntVar(&cfg.maxRateLimitRetries, "max-rate-limit-retries", client.MaxRateLimitRetries, "Max HTTP 429 (rate limited) retries per request before giving up; 0 retries indefinitely")
	fs.BoolVar(&cfg.continueOnError, "continue-on-error", true, "Export the data collected so far when safe enumeration fails partway through (the export will be incomplete); set false to abort instead")

	// Activity tracking flags
	fs.BoolVar(&cfg.includeActivity, "include-activity", true, "Include account activity data (creates CyberArk_UsedAccount edges)")
	fs.IntVar(&cfg.activityDays, "activity-days", 3, "Number of days to look back for activity")
	fs.IntVar(&cfg.activityLimit, "activity-limit", 100, "Max activities per account")

	// Linked accounts and platforms flags
	fs.BoolVar(&cfg.includeLinkedAccounts, "include-linked-accounts", true, "Include linked account data (creates CyberArk_LinkedTo edges for logon/reconcile/additional account chains)")
	fs.BoolVar(&cfg.includePlatforms, "include-platforms", true, "Include platform data (creates CyberArk_Platform nodes and CyberArk_UsesPlatform edges)")
	fs.BoolVar(&cfg.includePSM, "include-psm", true, "Include PSM server and connection component data (creates CyberArk_PSMServer and CyberArk_ConnectionComponent nodes)")
	fs.BoolVar(&cfg.includeApplications, "include-applications", true, "Include CCP/AIMWebService Application (AppID) data (creates CyberArk_Application nodes and CyberArk_CanRetrieveViaCCP edges)")
	fs.BoolVar(&cfg.includePredefinedMembers, "include-predefined-members", true, "Include built-in safe members such as Master, Vault Admins and Auditors, which the Safe members API omits by default")

	// Testing limits
	fs.IntVar(&cfg.limitUsers, "limit-users", 0, "Limit number of users (0 = no limit)")
	fs.IntVar(&cfg.limitGroups, "limit-groups", 0, "Limit number of groups (0 = no limit)")
	fs.IntVar(&cfg.limitSafes, "limit-safes", 0, "Limit number of safes (0 = no limit)")
	fs.StringVar(&cfg.testSafe, "test-safe", "", "Fetch single safe by search term")

	// Additional outputs and offline rebuilds
	fs.StringVar(&cfg.findingsOutput, "findings-output", "", "Also write the security findings, with the objects behind each one, to this JSON file")
	fs.StringVar(&cfg.saveRaw, "save-raw", "", "Also save the raw collected data to this JSON file, so the graph can be rebuilt later with --from-raw. Progress is saved periodically while collecting, so an interrupted or failed collection can be continued with --resume")
	fs.StringVar(&cfg.fromRaw, "from-raw", "", "Build the graph from a file written by --save-raw instead of contacting PVWA")
	fs.StringVar(&cfg.resume, "resume", "", "Continue an interrupted or failed collection from its --save-raw file: finished work is not fetched again, failed work is retried, and progress keeps being saved to that file (or to --save-raw)")

	return fs, logLevel, debug, quiet
}

// parseFlags parses and validates the command line. The password is not
// required here; resolvePassword fills it in afterwards.
func parseFlags(args []string) (*config, error) {
	cfg := &config{}
	fs, logLevel, debug, quiet := newFlagSet(cfg)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil, err
		}
		return nil, &usageError{err.Error()}
	}
	cfg.passwordFlag = fs.Changed("password")
	cfg.explicit = make(map[string]bool)
	for _, name := range resumeOptionFlags {
		cfg.explicit[name] = fs.Changed(name)
	}

	// Leftover positional arguments are additional target domains.
	cfg.targetDomains = normalizeDomains(append(cfg.targetDomains, fs.Args()...))

	level, err := logrus.ParseLevel(strings.TrimSpace(*logLevel))
	if err != nil {
		return nil, &usageError{fmt.Sprintf("invalid --log-level %q (valid: DEBUG, INFO, WARNING, ERROR)", *logLevel)}
	}
	switch {
	case *debug:
		level = logrus.DebugLevel
	case *quiet && level > logrus.WarnLevel:
		level = logrus.WarnLevel
	}
	cfg.logLevel = level

	var missing []string
	if cfg.outputFile == "" {
		missing = append(missing, "--output")
	}
	if len(cfg.targetDomains) == 0 {
		missing = append(missing, "--target-domains")
	}
	if cfg.fromRaw == "" {
		// A resumed collection takes the PVWA URL from its file by default.
		if cfg.pvwaURL == "" && cfg.resume == "" {
			missing = append(missing, "--pvwa")
		}
		if cfg.username == "" {
			missing = append(missing, "--username")
		}
	}
	if len(missing) > 0 {
		return nil, &usageError{"missing required flags: " + strings.Join(missing, ", ")}
	}

	if cfg.fromRaw != "" && cfg.saveRaw != "" {
		return nil, &usageError{"--save-raw cannot be combined with --from-raw"}
	}
	if cfg.fromRaw != "" && cfg.resume != "" {
		return nil, &usageError{"--resume cannot be combined with --from-raw"}
	}

	method, ok := client.NormalizeAuthMethod(cfg.authMethod)
	if !ok {
		return nil, &usageError{fmt.Sprintf("unsupported --auth-method %q (valid: cyberark, ldap, radius, windows, identity)", cfg.authMethod)}
	}
	cfg.authMethod = method
	if cfg.fromRaw == "" && method == client.AuthMethodIdentity && cfg.identityURL == "" {
		return nil, &usageError{"--identity-url is required when --auth-method is identity (e.g. https://<tenant>.id.cyberark.cloud)"}
	}
	return cfg, nil
}

// normalizeDomains trims whitespace and trailing dots and drops empty entries,
// so "--target-domains 'a.com, b.com'" behaves like "a.com,b.com".
func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d = strings.TrimRight(strings.TrimSpace(d), "."); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// resolvePassword fills in cfg.password from, in order: --password, the
// CYBERARK_PASSWORD environment variable, or an interactive prompt.
func resolvePassword(cfg *config, getenv func(string) string, prompt func() (string, error)) error {
	if cfg.passwordFlag {
		return nil
	}
	if p := getenv(passwordEnvVar); p != "" {
		cfg.password = p
		return nil
	}
	if prompt == nil {
		return fmt.Errorf("no password given: set %s, pass --password, or run interactively to be prompted", passwordEnvVar)
	}
	p, err := prompt()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	if p == "" {
		return errors.New("empty password")
	}
	cfg.password = p
	return nil
}

// terminalPrompt reads a password from the terminal without echoing it, or
// returns nil when stdin is not a terminal.
func terminalPrompt() func() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	return func() (string, error) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: cyberarkhound --pvwa URL --username USER --output FILE --target-domains DOMAINS [OPTIONS]\n")
	fmt.Fprintf(w, "       cyberarkhound --resume FILE --username USER --output FILE --target-domains DOMAINS [OPTIONS]\n")
	fmt.Fprintf(w, "       cyberarkhound --from-raw FILE --output FILE --target-domains DOMAINS [OPTIONS]\n\n")
	fmt.Fprintf(w, "The password is read from --password, the %s environment variable, or an interactive prompt.\n\n", passwordEnvVar)
	fs, _, _, _ := newFlagSet(&config{})
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func realMain(args []string) int {
	cfg, err := parseFlags(args)
	if errors.Is(err, pflag.ErrHelp) {
		printUsage(os.Stdout)
		return exitOK
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage(os.Stderr)
		return exitError
	}

	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	logger.SetLevel(cfg.logLevel)

	if cfg.fromRaw == "" {
		if err := resolvePassword(cfg, os.Getenv, terminalPrompt()); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return exitError
		}
		if cfg.passwordFlag {
			logger.Warnf("--password is visible to other local users in the process list; prefer the %s environment variable or the interactive prompt", passwordEnvVar)
		}
	}

	// The first SIGINT/SIGTERM stops the collection gracefully: requests are
	// abandoned, and what was gathered so far is still built and exported. The
	// handler is then removed, so a second signal terminates immediately.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		signal.Stop(sigCh)
		logger.Warnf("Received %s: stopping the collection and exporting what was gathered so far (repeat to abort immediately)", sig)
		cancel()
	}()

	return run(ctx, cfg, logger)
}
