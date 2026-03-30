package diff

import (
	"database/sql"
	"fmt"
	"path"
	"sort"

	"github.com/agentic-research/mache/graph"
	_ "modernc.org/sqlite"
)

// ProviderDiff holds the comparison for a single provider.
type ProviderDiff struct {
	Provider string `json:"provider"`
	CountA   int    `json:"count_a"`
	CountB   int    `json:"count_b"`
	Delta    int    `json:"delta"` // CountB - CountA
}

// StateComparison holds the result of comparing two state graphs.
type StateComparison struct {
	NewCVEs      int `json:"new_cves"`
	RemovedCVEs  int `json:"removed_cves"`
	StateChanges int `json:"state_changes"`
	ConflictsA   int `json:"conflicts_a"`
	ConflictsB   int `json:"conflicts_b"`
}

// Result holds the full comparison between two vulnerability databases.
type Result struct {
	Common          []ProviderDiff   `json:"common"`
	OnlyInA         []ProviderDiff   `json:"only_in_a"`
	OnlyInB         []ProviderDiff   `json:"only_in_b"`
	TotalA          int              `json:"total_a"`
	TotalB          int              `json:"total_b"`
	StateComparison *StateComparison `json:"state_comparison,omitempty"`
}

// Option configures the comparison.
type Option func(*options)

type options struct {
	statePathA string
	statePathB string
	matchable  bool
}

// WithMatchable filters to only count entries that have at least one
// affected_package_handle or affected_cpe_handle (i.e., entries grype can actually match).
func WithMatchable(v bool) Option {
	return func(o *options) {
		o.matchable = v
	}
}

// WithStatePaths provides explicit state.db paths for graph comparison.
func WithStatePaths(a, b string) Option {
	return func(o *options) {
		o.statePathA = a
		o.statePathB = b
	}
}

// CompareDBs compares two vulnerability databases by provider and row count.
// Paths can be .db files or archives (.tar.gz, .tar.zst, .tar.xz).
func CompareDBs(pathA, pathB string, opts ...Option) (*Result, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	dbA, cleanA, err := resolveDBPath(pathA)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", pathA, err)
	}
	defer cleanA()

	dbB, cleanB, err := resolveDBPath(pathB)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", pathB, err)
	}
	defer cleanB()

	countsA, err := providerCounts(dbA, cfg.matchable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pathA, err)
	}
	countsB, err := providerCounts(dbB, cfg.matchable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pathB, err)
	}

	result := &Result{}

	allProviders := map[string]bool{}
	for p := range countsA {
		allProviders[p] = true
	}
	for p := range countsB {
		allProviders[p] = true
	}

	sorted := make([]string, 0, len(allProviders))
	for p := range allProviders {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)

	for _, p := range sorted {
		a, inA := countsA[p]
		b, inB := countsB[p]

		switch {
		case inA && inB:
			result.Common = append(result.Common, ProviderDiff{
				Provider: p, CountA: a, CountB: b, Delta: b - a,
			})
		case inA:
			result.OnlyInA = append(result.OnlyInA, ProviderDiff{
				Provider: p, CountA: a,
			})
		default:
			result.OnlyInB = append(result.OnlyInB, ProviderDiff{
				Provider: p, CountB: b,
			})
		}

		result.TotalA += a
		result.TotalB += b
	}

	if cfg.statePathA != "" && cfg.statePathB != "" {
		sc, err := compareStateGraphs(cfg.statePathA, cfg.statePathB)
		if err == nil {
			result.StateComparison = sc
		}
	}

	return result, nil
}

// ProviderDrillResult holds the CVE-level diff for a single provider.
type ProviderDrillResult struct {
	Provider string   `json:"provider"`
	Common   []string `json:"common"`
	OnlyInA  []string `json:"only_in_a"`
	OnlyInB  []string `json:"only_in_b"`
}

// DrillProvider compares the vulnerability names for a specific provider across two DBs.
// Paths can be .db files or archives (.tar.gz, .tar.zst, .tar.xz).
func DrillProvider(pathA, pathB, provider string, opts ...Option) (*ProviderDrillResult, error) {
	var cfg options
	for _, o := range opts {
		o(&cfg)
	}

	dbA, cleanA, err := resolveDBPath(pathA)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", pathA, err)
	}
	defer cleanA()

	dbB, cleanB, err := resolveDBPath(pathB)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", pathB, err)
	}
	defer cleanB()

	namesA, err := providerVulnNames(dbA, provider, cfg.matchable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pathA, err)
	}
	namesB, err := providerVulnNames(dbB, provider, cfg.matchable)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", pathB, err)
	}

	if len(namesA) == 0 && len(namesB) == 0 {
		return nil, fmt.Errorf("provider %q not found in either database", provider)
	}

	setA := make(map[string]bool, len(namesA))
	for _, n := range namesA {
		setA[n] = true
	}
	setB := make(map[string]bool, len(namesB))
	for _, n := range namesB {
		setB[n] = true
	}

	result := &ProviderDrillResult{Provider: provider}

	for _, n := range namesA {
		if setB[n] {
			result.Common = append(result.Common, n)
		} else {
			result.OnlyInA = append(result.OnlyInA, n)
		}
	}
	for _, n := range namesB {
		if !setA[n] {
			result.OnlyInB = append(result.OnlyInB, n)
		}
	}

	sort.Strings(result.Common)
	sort.Strings(result.OnlyInA)
	sort.Strings(result.OnlyInB)

	return result, nil
}

func providerVulnNames(dbPath, provider string, matchable bool) ([]string, error) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	names, err := queryV6VulnNames(db, provider, matchable)
	if err != nil {
		names, err = queryV5VulnNames(db, provider)
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}

func queryV6VulnNames(db *sql.DB, provider string, matchable bool) ([]string, error) {
	q := `SELECT name FROM vulnerability_handles WHERE provider_id = ? ORDER BY name`
	if matchable {
		q = `WITH matchable_ids AS (
			SELECT DISTINCT vulnerability_id AS id FROM affected_package_handles
			UNION
			SELECT DISTINCT vulnerability_id AS id FROM affected_cpe_handles
		)
		SELECT vh.name FROM vulnerability_handles vh
		WHERE vh.provider_id = ?
		AND vh.id IN (SELECT id FROM matchable_ids)
		ORDER BY vh.name`
	}
	rows, err := db.Query(q, provider)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func queryV5VulnNames(db *sql.DB, provider string) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM vulnerability WHERE namespace LIKE ? ORDER BY id`, provider+"%")
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func providerCounts(dbPath string, matchable bool) (map[string]int, error) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	counts, err := queryV6Counts(db, matchable)
	if err != nil {
		counts, err = queryV5Counts(db)
		if err != nil {
			return nil, fmt.Errorf("querying provider counts: %w", err)
		}
	}
	return counts, nil
}

func queryV6Counts(db *sql.DB, matchable bool) (map[string]int, error) {
	q := `
		SELECT p.id, COUNT(vh.id)
		FROM providers p
		LEFT JOIN vulnerability_handles vh ON vh.provider_id = p.id
		GROUP BY p.id
		ORDER BY p.id
	`
	if matchable {
		q = `
		WITH matchable_ids AS (
			SELECT DISTINCT vulnerability_id AS id FROM affected_package_handles
			UNION
			SELECT DISTINCT vulnerability_id AS id FROM affected_cpe_handles
		)
		SELECT p.id, COUNT(vh.id)
		FROM providers p
		LEFT JOIN vulnerability_handles vh ON vh.provider_id = p.id
			AND vh.id IN (SELECT id FROM matchable_ids)
		GROUP BY p.id
		ORDER BY p.id
		`
	}
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts := map[string]int{}
	for rows.Next() {
		var id string
		var count int
		if err := rows.Scan(&id, &count); err != nil {
			return nil, err
		}
		counts[id] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Enrichment providers store data in their own tables, not vulnerability_handles.
	enrichmentTables := map[string]string{
		"epss": "epss_handles",
		"kev":  "known_exploited_vulnerability_handles",
	}
	for provider, table := range enrichmentTables {
		if _, exists := counts[provider]; !exists {
			continue
		}
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count) //nolint:gosec // table name is hardcoded above
		if err == nil && count > 0 {
			counts[provider] = count
		}
	}

	return counts, nil
}

func queryV5Counts(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query(`
		SELECT namespace, COUNT(*)
		FROM vulnerability
		GROUP BY namespace
		ORDER BY namespace
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	counts := map[string]int{}
	for rows.Next() {
		var ns string
		var count int
		if err := rows.Scan(&ns, &count); err != nil {
			return nil, err
		}
		counts[ns] = count
	}
	return counts, rows.Err()
}

// compareStateGraphs diffs two mache state graphs.
func compareStateGraphs(pathA, pathB string) (*StateComparison, error) {
	gA, err := graph.ImportSQLite(pathA)
	if err != nil {
		return nil, fmt.Errorf("importing graph A: %w", err)
	}
	gB, err := graph.ImportSQLite(pathB)
	if err != nil {
		return nil, fmt.Errorf("importing graph B: %w", err)
	}

	transitions := diffGraphStates(gA, gB)

	sc := &StateComparison{
		ConflictsA: countConflicts(gA),
		ConflictsB: countConflicts(gB),
	}
	for _, t := range transitions {
		switch {
		case t.fromState == "":
			sc.NewCVEs++
		case t.toState == "":
			sc.RemovedCVEs++
		default:
			sc.StateChanges++
		}
	}
	return sc, nil
}

type stateTransition struct {
	fromState string
	toState   string
}

// diffGraphStates compares the by-state/ trees of two mache graphs.
func diffGraphStates(prev, curr *graph.MemoryStore) []stateTransition {
	prevStates := cveStateMap(prev)
	currStates := cveStateMap(curr)

	var transitions []stateTransition

	for cve, currState := range currStates {
		prevState, existed := prevStates[cve]
		if !existed {
			transitions = append(transitions, stateTransition{fromState: "", toState: currState})
		} else if prevState != currState {
			transitions = append(transitions, stateTransition{fromState: prevState, toState: currState})
		}
	}

	for cve, prevState := range prevStates {
		if _, exists := currStates[cve]; !exists {
			transitions = append(transitions, stateTransition{fromState: prevState, toState: ""})
		}
	}

	return transitions
}

func cveStateMap(g *graph.MemoryStore) map[string]string {
	byState, err := findByStateNode(g)
	if err != nil {
		return map[string]string{}
	}

	m := map[string]string{}
	for _, stateDir := range byState.Children {
		stateName := path.Base(stateDir)
		stateNode, err := g.GetNode(stateDir)
		if err != nil {
			continue
		}
		for _, child := range stateNode.Children {
			cveID := path.Base(child)
			m[cveID] = stateName
		}
	}
	return m
}

// findByStateNode searches all root nodes for a by-state child.
func findByStateNode(g *graph.MemoryStore) (*graph.Node, error) {
	for _, root := range g.RootIDs() {
		node, err := g.GetNode(root + "/by-state")
		if err == nil {
			return node, nil
		}
	}
	return nil, fmt.Errorf("no by-state node found")
}

func countConflicts(g *graph.MemoryStore) int {
	byState, err := findByStateNode(g)
	if err != nil {
		return 0
	}

	count := 0
	for _, stateDir := range byState.Children {
		stateNode, err := g.GetNode(stateDir)
		if err != nil {
			continue
		}
		for _, child := range stateNode.Children {
			node, err := g.GetNode(child)
			if err != nil {
				continue
			}
			if string(node.Properties["conflict"]) == "true" {
				count++
			}
		}
	}
	return count
}
