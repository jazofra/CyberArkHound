package graph

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"text/template"
	"text/template/parse"
)

// These tests stand in for BloodHound's upload-time template validation and
// its Entity Panel rendering: they parse every link-based section with only the
// functions BloodHound allows, render it for a sample node, and decode every
// Explore link back to its Cypher.

// bloodhoundTemplateFuncs is BloodHound's documented Entity Panel function
// allowlist (Sprig-based), from
// https://bloodhound.specterops.io/opengraph/developer/entity-panel-content.
var bloodhoundTemplateFuncs = []string{
	// Conditional checks and null handling
	"default", "coalesce", "empty", "ternary", "contains", "hasPrefix", "hasSuffix", "eq", "ne", "lt", "gt", "and", "or", "not",
	// Text formatting
	"printf", "trim", "trimPrefix", "trimSuffix", "upper", "lower", "title", "replace", "trunc", "substr", "repeat", "indent", "nindent",
	// Lists and iteration helpers
	"list", "join", "first", "last", "rest", "initial", "reverse", "uniq", "compact", "has", "sortAlpha", "len",
	// Dictionary lookup and manipulation
	"dict", "get", "hasKey", "keys", "values", "pick", "omit",
	// Numbers and conversion
	"add", "sub", "mul", "div", "mod", "max", "min", "ceil", "floor", "round", "int", "int64", "float64", "atoi",
	// JSON and encoding
	"toJson", "toPrettyJson", "fromJson", "b64enc", "b64dec", "urlquery",
	// Quoting
	"quote", "squote",
}

// goTemplateBuiltins are provided by text/template itself and must not be
// redefined in a FuncMap.
var goTemplateBuiltins = map[string]bool{
	"and": true, "call": true, "html": true, "index": true, "slice": true, "js": true, "len": true, "not": true,
	"or": true, "print": true, "printf": true, "println": true, "urlquery": true,
	"eq": true, "ge": true, "gt": true, "le": true, "lt": true, "ne": true,
}

// entityPanelFuncMap implements the Sprig functions the sections use, with
// Sprig's semantics, and stubs the rest of the allowlist so parsing accepts
// exactly BloodHound's function names.
func entityPanelFuncMap() template.FuncMap {
	fm := template.FuncMap{}
	for _, name := range bloodhoundTemplateFuncs {
		if goTemplateBuiltins[name] {
			continue
		}
		name := name
		fm[name] = func(...interface{}) (interface{}, error) {
			return nil, fmt.Errorf("test stub for %q called; implement it in entityPanelFuncMap", name)
		}
	}
	fm["default"] = func(d interface{}, given ...interface{}) interface{} {
		if len(given) == 0 || given[0] == nil || given[0] == "" {
			return d
		}
		return given[0]
	}
	fm["replace"] = func(old, new, src string) string { return strings.ReplaceAll(src, old, new) }
	fm["b64enc"] = func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	return fm
}

// templateIdentifiers collects every function name a parsed template calls.
func templateIdentifiers(node parse.Node, out map[string]bool) {
	switch n := node.(type) {
	case nil:
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, c := range n.Nodes {
			templateIdentifiers(c, out)
		}
	case *parse.ActionNode:
		templateIdentifiers(n.Pipe, out)
	case *parse.IfNode:
		templateIdentifiers(n.Pipe, out)
		templateIdentifiers(n.List, out)
		templateIdentifiers(n.ElseList, out)
	case *parse.WithNode:
		templateIdentifiers(n.Pipe, out)
		templateIdentifiers(n.List, out)
		templateIdentifiers(n.ElseList, out)
	case *parse.RangeNode:
		templateIdentifiers(n.Pipe, out)
		templateIdentifiers(n.List, out)
		templateIdentifiers(n.ElseList, out)
	case *parse.PipeNode:
		if n == nil {
			return
		}
		for _, c := range n.Cmds {
			templateIdentifiers(c, out)
		}
	case *parse.CommandNode:
		for _, a := range n.Args {
			templateIdentifiers(a, out)
		}
	case *parse.IdentifierNode:
		out[n.Ident] = true
	case *parse.TemplateNode:
		out["template"] = true
	}
}

// nodeContext mirrors BloodHound's node template context.
type nodeContext struct {
	NodeID     int64
	Kinds      []struct{ Name string }
	Properties map[string]interface{}
}

func renderSection(t *testing.T, s ExploreSection, props map[string]interface{}) string {
	t.Helper()
	tmpl, err := template.New(s.ID).Funcs(entityPanelFuncMap()).Parse(s.Markdown())
	if err != nil {
		t.Fatalf("section %q does not parse as a template: %v", s.ID, err)
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, nodeContext{NodeID: 42, Properties: props}); err != nil {
		t.Fatalf("section %q failed to render: %v", s.ID, err)
	}
	return b.String()
}

var exploreLinkPattern = regexp.MustCompile(`\]\(` + regexp.QuoteMeta(exploreURL) + `([^)\s]+)\)`)

// decodeExploreLinks returns the Cypher behind every Explore link in rendered
// markdown, reversing the template's b64enc | urlquery.
func decodeExploreLinks(t *testing.T, rendered string) []string {
	t.Helper()
	var queries []string
	for _, m := range exploreLinkPattern.FindAllStringSubmatch(rendered, -1) {
		unescaped, err := url.QueryUnescape(m[1])
		if err != nil {
			t.Fatalf("link parameter %q is not URL-encoded: %v", m[1], err)
		}
		raw, err := base64.StdEncoding.DecodeString(unescaped)
		if err != nil {
			t.Fatalf("link parameter %q is not base64: %v", unescaped, err)
		}
		queries = append(queries, string(raw))
	}
	return queries
}

func TestExploreSectionKindsAreCanonical(t *testing.T) {
	want := toSet(NodeKinds)
	for kind := range NodeExploreSections {
		if !want[kind] {
			t.Errorf("NodeExploreSections has %q which is not in graph.NodeKinds", kind)
		}
		if _, ok := NodeInfoMap[kind]; !ok {
			t.Errorf("NodeExploreSections has %q but NodeInfoMap does not, so the sections would never be published", kind)
		}
	}
}

func TestExploreSectionIDsDoNotCollide(t *testing.T) {
	fixed := map[string]bool{infoOverview: true, infoAbuse: true, infoOpsec: true, infoReferences: true}
	for kind, sections := range NodeExploreSections {
		seen := map[string]bool{}
		for _, s := range sections {
			if fixed[s.ID] || seen[s.ID] {
				t.Errorf("%s: explore section id %q collides with another section", kind, s.ID)
			}
			seen[s.ID] = true
			if len(s.Queries) == 0 {
				t.Errorf("%s: explore section %q has no queries", kind, s.ID)
			}
		}
	}
}

// TestExploreSectionsPlacedAfterOverview checks that link sections follow
// Overview directly, ahead of the abuse/OPSEC/reference text.
func TestExploreSectionsPlacedAfterOverview(t *testing.T) {
	for kind, explore := range NodeExploreSections {
		sections := NodeInfoSections(kind)
		for i, s := range explore {
			if got := sections[s.ID].Position; got != i+2 {
				t.Errorf("%s: section %q has position %d, want %d", kind, s.ID, got, i+2)
			}
		}
		if got, want := sections[infoAbuse].Position, len(explore)+2; got != want {
			t.Errorf("%s: abuse section has position %d, want %d", kind, got, want)
		}
	}
}

// TestExploreSectionsUseOnlyAllowedTemplateFunctions mirrors BloodHound's
// upload check: a template calling anything outside the allowlist is rejected.
func TestExploreSectionsUseOnlyAllowedTemplateFunctions(t *testing.T) {
	allowed := toSet(bloodhoundTemplateFuncs)
	for kind, sections := range NodeExploreSections {
		for _, s := range sections {
			trees, err := parse.Parse(s.ID, s.Markdown(), "", "", entityPanelFuncMap(), goTemplateBuiltinFuncs())
			if err != nil {
				t.Fatalf("%s.%s: parse: %v", kind, s.ID, err)
			}
			used := map[string]bool{}
			for _, tree := range trees {
				templateIdentifiers(tree.Root, used)
			}
			for ident := range used {
				if !allowed[ident] {
					t.Errorf("%s.%s: uses %q, which BloodHound's Entity Panel templates do not allow", kind, s.ID, ident)
				}
			}
		}
	}
}

// goTemplateBuiltinFuncs gives parse.Parse the builtin names so it accepts them.
func goTemplateBuiltinFuncs() map[string]interface{} {
	m := map[string]interface{}{}
	for name := range goTemplateBuiltins {
		m[name] = func() {}
	}
	return m
}

// TestExploreLinksRoundTrip renders every section for a sample node and checks
// that each link decodes to exactly its query with the node's objectid.
func TestExploreLinksRoundTrip(t *testing.T) {
	const objectID = "CAUSER-JDOE-APVA"
	for kind, sections := range NodeExploreSections {
		for _, s := range sections {
			rendered := renderSection(t, s, map[string]interface{}{"objectid": objectID, "name": "jdoe"})
			if strings.Contains(rendered, "{{") || strings.Contains(rendered, "}}") {
				t.Errorf("%s.%s: rendered markdown still contains template delimiters:\n%s", kind, s.ID, rendered)
			}
			if strings.Contains(rendered, missingObjectIDNote) {
				t.Errorf("%s.%s: rendered the missing-objectid note for a node that has one", kind, s.ID)
			}
			if !strings.HasPrefix(rendered, s.Intro+"\n\n- [") {
				t.Errorf("%s.%s: rendered markdown should be the intro then the link list, got:\n%s", kind, s.ID, rendered)
			}
			got := decodeExploreLinks(t, rendered)
			if len(got) != len(s.Queries) {
				t.Fatalf("%s.%s: rendered %d links, want %d:\n%s", kind, s.ID, len(got), len(s.Queries), rendered)
			}
			for i, q := range s.Queries {
				if want := fmt.Sprintf(q.Cypher, objectID); got[i] != want {
					t.Errorf("%s.%s link %q decodes to\n%s\nwant\n%s", kind, s.ID, q.Label, got[i], want)
				}
			}
		}
	}
}

// TestExploreLinksWithoutObjectID checks the guard: no links, just the note.
func TestExploreLinksWithoutObjectID(t *testing.T) {
	for kind, sections := range NodeExploreSections {
		for _, s := range sections {
			rendered := renderSection(t, s, map[string]interface{}{"name": "jdoe"})
			if strings.Contains(rendered, "/ui/explore") {
				t.Errorf("%s.%s: rendered Explore links for a node with no objectid", kind, s.ID)
			}
			if want := s.Intro + "\n\n" + missingObjectIDNote + "\n"; rendered != want {
				t.Errorf("%s.%s: rendered\n%q\nwant\n%q", kind, s.ID, rendered, want)
			}
		}
	}
}

// TestExploreLinksStripQueryBreakingCharacters checks that an objectid with a
// double quote or backslash cannot end the Cypher string literal early.
func TestExploreLinksStripQueryBreakingCharacters(t *testing.T) {
	const hostile = `CAUSER-X"}) DETACH DELETE n //\-APVA`
	const stripped = `CAUSER-X}) DETACH DELETE n //-APVA`
	for kind, sections := range NodeExploreSections {
		for _, s := range sections {
			got := decodeExploreLinks(t, renderSection(t, s, map[string]interface{}{"objectid": hostile}))
			for i, q := range s.Queries {
				if want := fmt.Sprintf(q.Cypher, stripped); got[i] != want {
					t.Errorf("%s.%s link %q: decoded\n%s\nwant\n%s", kind, s.ID, q.Label, got[i], want)
				}
			}
		}
	}
}

// edgeEndpoints records the node kinds builder.go emits at each end of every
// CyberArk edge kind. External edges end at the AD kinds User, Group, and
// Computer.
var edgeEndpoints = map[string][2][]string{
	"CyberArk_HasAccessTo":            {{"CyberArk_User", "CyberArk_Group"}, {"CyberArk_Account"}},
	"CyberArk_CanGrantAccessTo":       {{"CyberArk_User", "CyberArk_Group"}, {"CyberArk_Safe"}},
	"CyberArk_CanRetrieveViaCCP":      {{"CyberArk_Application"}, {"CyberArk_Account"}},
	"CyberArk_CCPAllowedFrom":         {{"CyberArk_Application"}, {"Computer"}},
	"CyberArk_CanHijackViaReconcile":  {{"CyberArk_User", "CyberArk_Group"}, {"CyberArk_Account"}},
	"CyberArk_CanApprove":             {{"CyberArk_User", "CyberArk_Group"}, {"CyberArk_Safe"}},
	"CyberArk_MemberOf":               {{"CyberArk_User"}, {"CyberArk_Group"}},
	"CyberArk_InstanceContains":       {{"CyberArk_Instance"}, {"CyberArk_Safe", "CyberArk_Platform", "CyberArk_PSMServer", "CyberArk_ConnectionComponent", "CyberArk_Application"}},
	"CyberArk_Contains":               {{"CyberArk_Safe"}, {"CyberArk_Account"}},
	"CyberArk_Created":                {{"CyberArk_User"}, {"CyberArk_Safe"}},
	"CyberArk_ManagedBy":              {{"CyberArk_User"}, {"CyberArk_Safe"}},
	"CyberArk_UsesPlatform":           {{"CyberArk_Account"}, {"CyberArk_Platform"}},
	"CyberArk_UsedAccount":            {{"CyberArk_User"}, {"CyberArk_Account"}},
	"CyberArk_LinkedTo":               {{"CyberArk_Account"}, {"CyberArk_Account"}},
	"CyberArk_UsesPSMServer":          {{"CyberArk_Platform"}, {"CyberArk_PSMServer"}},
	"CyberArk_ManagedByPSM":           {{"CyberArk_Account"}, {"CyberArk_PSMServer"}},
	"CyberArk_HasConnectionComponent": {{"CyberArk_Platform"}, {"CyberArk_ConnectionComponent"}},
	"CyberArk_PSMServerHostedOn":      {{"CyberArk_PSMServer"}, {"Computer"}},
	"CyberArk_SyncsToUser":            {{"User"}, {"CyberArk_User"}},
	"CyberArk_SyncsToGroup":           {{"Group"}, {"CyberArk_Group"}},
	"CyberArk_SyncsToADUser":          {{"CyberArk_Account"}, {"User"}},
	"CyberArk_CanConnect":             {{"CyberArk_Account"}, {"Computer"}},
}

// adKindsUsed is every built-in AD kind the queries may reference. Each was
// checked against BloodHound's packages/go/graphschema/ad/ad.go.
var adKindsUsed = map[string]bool{
	"User": true, "Group": true, "Computer": true,
	"MemberOf": true, "AdminTo": true, "AddMember": true, "AddSelf": true,
	"AllExtendedRights": true, "ForceChangePassword": true, "GenericAll": true, "GenericWrite": true,
	"Owns": true, "OwnsLimitedRights": true, "WriteDacl": true, "WriteOwner": true, "WriteOwnerLimitedRights": true,
	"AddKeyCredentialLink": true, "WriteSPN": true, "WriteAltSecurityIdentities": true,
}

func TestEdgeEndpointsCoverCanonicalKinds(t *testing.T) {
	for _, kind := range EdgeKinds {
		if _, ok := edgeEndpoints[kind]; !ok {
			t.Errorf("edgeEndpoints has no entry for %q", kind)
		}
	}
}

var (
	cypherNodePattern = regexp.MustCompile(`^\((\w*)(?::(\w+))?(?: \{[^}]*\})?\)`)
	cypherRelPattern  = regexp.MustCompile(`^(<?)-\[:([\w|]+)(\*[\d.]*)?\]-(>?)`)
)

// TestExploreQueriesMatchTheModel parses each query's path and checks that it
// is well formed, names only known kinds, and that every fixed single-edge hop
// between labeled nodes runs in the direction builder.go emits it.
func TestExploreQueriesMatchTheModel(t *testing.T) {
	nodeKinds := toSet(NodeKinds)
	edgeKinds := toSet(EdgeKinds)
	contains := func(list []string, s string) bool {
		for _, v := range list {
			if v == s {
				return true
			}
		}
		return false
	}

	for kind, sections := range NodeExploreSections {
		for _, s := range sections {
			for _, q := range s.Queries {
				where := fmt.Sprintf("%s.%s %q", kind, s.ID, q.Label)
				if strings.Count(q.Cypher, "%") != strings.Count(q.Cypher, "%[1]s") {
					t.Errorf("%s: only the %%[1]s placeholder may appear in a query", where)
				}
				if !strings.Contains(q.Cypher, self(kind)) {
					t.Errorf("%s: query does not match the selected node as %s", where, self(kind))
				}
				if !strings.HasPrefix(q.Cypher, "MATCH p=") || !strings.HasSuffix(q.Cypher, "\nRETURN p") {
					t.Errorf("%s: query must be MATCH p=…\\nRETURN p, got %q", where, q.Cypher)
					continue
				}

				rest := strings.TrimSuffix(strings.TrimPrefix(q.Cypher, "MATCH p="), "\nRETURN p")
				var labels []string
				var rels []struct {
					kinds    []string
					varLen   bool
					leftward bool
				}
				for i := 0; rest != ""; i++ {
					if i%2 == 0 {
						m := cypherNodePattern.FindStringSubmatch(rest)
						if m == nil {
							t.Fatalf("%s: cannot parse a node pattern at %q", where, rest)
						}
						if m[2] != "" && !nodeKinds[m[2]] && !adKindsUsed[m[2]] {
							t.Errorf("%s: unknown node label %q", where, m[2])
						}
						labels = append(labels, m[2])
						rest = rest[len(m[0]):]
						continue
					}
					m := cypherRelPattern.FindStringSubmatch(rest)
					if m == nil {
						t.Fatalf("%s: cannot parse a relationship pattern at %q", where, rest)
					}
					if (m[1] == "<") == (m[4] == ">") {
						t.Fatalf("%s: relationship %q must point exactly one way", where, m[0])
					}
					kinds := strings.Split(m[2], "|")
					for _, k := range kinds {
						if !edgeKinds[k] && !adKindsUsed[k] {
							t.Errorf("%s: unknown relationship kind %q", where, k)
						}
					}
					rels = append(rels, struct {
						kinds    []string
						varLen   bool
						leftward bool
					}{kinds, m[3] != "", m[1] == "<"})
					rest = rest[len(m[0]):]
				}
				if len(labels) != len(rels)+1 {
					t.Fatalf("%s: path must start and end with a node", where)
				}

				for i, r := range rels {
					ends, ok := edgeEndpoints[r.kinds[0]]
					if len(r.kinds) != 1 || r.varLen || !ok {
						continue
					}
					src, dst := labels[i], labels[i+1]
					if r.leftward {
						src, dst = dst, src
					}
					if src != "" && !contains(ends[0], src) {
						t.Errorf("%s: %s never starts at %s (builder emits it from %v)", where, r.kinds[0], src, ends[0])
					}
					if dst != "" && !contains(ends[1], dst) {
						t.Errorf("%s: %s never ends at %s (builder emits it to %v)", where, r.kinds[0], dst, ends[1])
					}
				}
			}
		}
	}
}
