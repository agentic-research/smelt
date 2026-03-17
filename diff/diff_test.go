package diff

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// createTestDB creates a minimal v6-style vulnerability.db with providers and vulnerability_handles.
func createTestDB(t *testing.T, dir, name string, providers map[string]int) string {
	t.Helper()
	// Convert counts to named CVEs for the richer helper
	named := map[string][]string{}
	for provider, count := range providers {
		var cves []string
		for i := range count {
			cves = append(cves, fmt.Sprintf("CVE-2024-%s-%04d", provider, i))
		}
		named[provider] = cves
	}
	return createTestDBNamed(t, dir, name, named)
}

// createTestDBNamed creates a test DB with specific CVE names per provider.
func createTestDBNamed(t *testing.T, dir, name string, providers map[string][]string) string {
	t.Helper()
	dbPath := filepath.Join(dir, name)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`
		CREATE TABLE providers (
			id TEXT PRIMARY KEY,
			version TEXT,
			processor TEXT,
			date_captured TEXT,
			input_digest TEXT
		);
		CREATE TABLE blob_digests (
			id INTEGER PRIMARY KEY,
			digest TEXT
		);
		CREATE TABLE vulnerability_handles (
			id INTEGER PRIMARY KEY,
			name TEXT,
			provider_id TEXT REFERENCES providers(id),
			blob_id INTEGER REFERENCES blob_digests(id)
		);
		CREATE TABLE affected_package_handles (
			id INTEGER PRIMARY KEY,
			vulnerability_id INTEGER REFERENCES vulnerability_handles(id),
			operating_system_id INTEGER,
			package_id INTEGER,
			blob_id INTEGER
		);
		CREATE TABLE affected_cpe_handles (
			id INTEGER PRIMARY KEY,
			vulnerability_id INTEGER REFERENCES vulnerability_handles(id),
			cpe_id INTEGER,
			blob_id INTEGER
		);
	`)
	if err != nil {
		t.Fatalf("create schema: %v", err)
	}

	blobID := 1
	vulnID := 1
	for provider, cves := range providers {
		_, err = db.Exec("INSERT INTO providers (id) VALUES (?)", provider)
		if err != nil {
			t.Fatalf("insert provider %s: %v", provider, err)
		}
		for _, cveName := range cves {
			_, err = db.Exec("INSERT INTO blob_digests (id, digest) VALUES (?, ?)", blobID, "sha256:fake")
			if err != nil {
				t.Fatalf("insert blob: %v", err)
			}
			_, err = db.Exec("INSERT INTO vulnerability_handles (id, name, provider_id, blob_id) VALUES (?, ?, ?, ?)",
				vulnID, cveName, provider, blobID)
			if err != nil {
				t.Fatalf("insert vuln: %v", err)
			}
			blobID++
			vulnID++
		}
	}

	return dbPath
}

func TestCompareDBs_IdenticalProviders(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 100, "alpine": 50})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 100, "alpine": 50})

	result, err := CompareDBs(dbA, dbB)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.OnlyInA) != 0 {
		t.Errorf("expected no providers only in A, got %v", result.OnlyInA)
	}
	if len(result.OnlyInB) != 0 {
		t.Errorf("expected no providers only in B, got %v", result.OnlyInB)
	}
	if len(result.Common) != 2 {
		t.Errorf("expected 2 common providers, got %d", len(result.Common))
	}
	for _, p := range result.Common {
		if p.CountA != p.CountB {
			t.Errorf("provider %s: expected equal counts, got A=%d B=%d", p.Provider, p.CountA, p.CountB)
		}
	}
}

func TestCompareDBs_DifferentProviders(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 100, "alpine": 50})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 80, "ubuntu": 30})

	result, err := CompareDBs(dbA, dbB)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.OnlyInA) != 1 || result.OnlyInA[0].Provider != "alpine" {
		t.Errorf("expected alpine only in A, got %v", result.OnlyInA)
	}
	if len(result.OnlyInB) != 1 || result.OnlyInB[0].Provider != "ubuntu" {
		t.Errorf("expected ubuntu only in B, got %v", result.OnlyInB)
	}
	if len(result.Common) != 1 || result.Common[0].Provider != "nvd" {
		t.Errorf("expected nvd in common, got %v", result.Common)
	}
	nvd := result.Common[0]
	if nvd.CountA != 100 || nvd.CountB != 80 {
		t.Errorf("nvd counts: expected A=100 B=80, got A=%d B=%d", nvd.CountA, nvd.CountB)
	}
	if nvd.Delta != -20 {
		t.Errorf("nvd delta: expected -20, got %d", nvd.Delta)
	}
}

func TestCompareDBs_EmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 10})
	dbB := createTestDB(t, dir, "b.db", map[string]int{})

	result, err := CompareDBs(dbA, dbB)
	if err != nil {
		t.Fatal(err)
	}

	if len(result.OnlyInA) != 1 {
		t.Errorf("expected 1 provider only in A, got %d", len(result.OnlyInA))
	}
	if result.TotalA != 10 || result.TotalB != 0 {
		t.Errorf("totals: expected A=10 B=0, got A=%d B=%d", result.TotalA, result.TotalB)
	}
}

func TestCompareDBs_NonexistentFile(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 10})

	_, err := CompareDBs(dbA, filepath.Join(dir, "nope.db"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestCompareDBs_Summary(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 100, "alpine": 50, "debian": 30})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 120, "alpine": 45, "ubuntu": 25})

	result, err := CompareDBs(dbA, dbB)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalA != 180 {
		t.Errorf("TotalA: expected 180, got %d", result.TotalA)
	}
	if result.TotalB != 190 {
		t.Errorf("TotalB: expected 190, got %d", result.TotalB)
	}

	// Find state.db alongside the DBs — shouldn't exist
	if result.StateComparison != nil {
		t.Error("expected no state comparison for DBs without state.db")
	}
}

func TestCompareDBs_WithStateDBs(t *testing.T) {
	// Skip if mache graph isn't easily constructable in test
	// The state diff is tested thoroughly in validate/statediff_test and store/diff_test
	// Here we just verify the wiring: if state.db exists alongside, it gets picked up
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 10})

	// Create a fake state.db that isn't a real graph — should produce an error
	// but not fail the whole comparison
	fakeState := filepath.Join(dir, "a_state.db")
	if err := os.WriteFile(fakeState, []byte("not a db"), 0o644); err != nil {
		t.Fatal(err)
	}

	// CompareDBs with explicit state paths
	result, err := CompareDBs(dbA, dbA, WithStatePaths(fakeState, fakeState))
	if err != nil {
		t.Fatal(err)
	}

	// Should still have the provider comparison even if state diff fails
	if len(result.Common) != 1 {
		t.Errorf("expected 1 common provider, got %d", len(result.Common))
	}
	// State comparison should be nil (failed gracefully)
	if result.StateComparison != nil {
		t.Error("expected nil state comparison for invalid state.db")
	}
}

// addMatchableEntries adds affected_package or affected_cpe rows for specific vulns in a test DB.
func addMatchableEntries(t *testing.T, dbPath string, pkgVulnIDs, cpeVulnIDs []int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, vid := range pkgVulnIDs {
		_, err = db.Exec("INSERT INTO affected_package_handles (vulnerability_id, package_id) VALUES (?, 1)", vid)
		if err != nil {
			t.Fatalf("insert affected_package: %v", err)
		}
	}
	for _, vid := range cpeVulnIDs {
		_, err = db.Exec("INSERT INTO affected_cpe_handles (vulnerability_id, cpe_id) VALUES (?, 1)", vid)
		if err != nil {
			t.Fatalf("insert affected_cpe: %v", err)
		}
	}
}

// getVulnID returns the vulnerability_handles.id for a given name.
func getVulnID(t *testing.T, dbPath, name string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()

	var id int
	err = db.QueryRow("SELECT id FROM vulnerability_handles WHERE name = ?", name).Scan(&id)
	if err != nil {
		t.Fatalf("get vuln id for %s: %v", name, err)
	}
	return id
}

func TestCompareDBs_Matchable(t *testing.T) {
	dir := t.TempDir()

	// DB-A: nvd has 3 CVEs, only 1 has a CPE match (matchable)
	dbA := createTestDBNamed(t, dir, "a.db", map[string][]string{
		"nvd": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
	})
	id1A := getVulnID(t, dbA, "CVE-2024-0001")
	addMatchableEntries(t, dbA, nil, []int{id1A}) // only CVE-0001 has a CPE

	// DB-B: nvd has 3 CVEs, 2 have package matches (matchable)
	dbB := createTestDBNamed(t, dir, "b.db", map[string][]string{
		"nvd": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
	})
	id1B := getVulnID(t, dbB, "CVE-2024-0001")
	id2B := getVulnID(t, dbB, "CVE-2024-0002")
	addMatchableEntries(t, dbB, []int{id1B, id2B}, nil)

	// Without matchable: both show 3
	result, err := CompareDBs(dbA, dbB)
	if err != nil {
		t.Fatal(err)
	}
	if result.Common[0].CountA != 3 || result.Common[0].CountB != 3 {
		t.Errorf("without matchable: expected 3/3, got %d/%d", result.Common[0].CountA, result.Common[0].CountB)
	}

	// With matchable: A=1, B=2
	result, err = CompareDBs(dbA, dbB, WithMatchable(true))
	if err != nil {
		t.Fatal(err)
	}
	if result.Common[0].CountA != 1 {
		t.Errorf("matchable A: expected 1, got %d", result.Common[0].CountA)
	}
	if result.Common[0].CountB != 2 {
		t.Errorf("matchable B: expected 2, got %d", result.Common[0].CountB)
	}
	if result.TotalA != 1 || result.TotalB != 2 {
		t.Errorf("matchable totals: expected 1/2, got %d/%d", result.TotalA, result.TotalB)
	}
}

func TestCompareDBs_MatchableFiltersStubs(t *testing.T) {
	dir := t.TempDir()

	// A has nvd with 5 CVEs, none matchable (all stubs)
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 5})
	// B has nvd with 5 CVEs, all matchable
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 5})
	// Make all of B's vulns matchable
	db, err := sql.Open("sqlite", dbB+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT id FROM vulnerability_handles")
	if err != nil {
		t.Fatal(err)
	}
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	_ = rows.Close()
	_ = db.Close()
	addMatchableEntries(t, dbB, ids, nil)

	result, err := CompareDBs(dbA, dbB, WithMatchable(true))
	if err != nil {
		t.Fatal(err)
	}

	// A should show 0 (all stubs), B should show 5
	if result.Common[0].CountA != 0 {
		t.Errorf("expected 0 matchable in A, got %d", result.Common[0].CountA)
	}
	if result.Common[0].CountB != 5 {
		t.Errorf("expected 5 matchable in B, got %d", result.Common[0].CountB)
	}
}

func TestDrillProvider_Matchable(t *testing.T) {
	dir := t.TempDir()

	// A: 3 CVEs, only CVE-0001 is matchable
	dbA := createTestDBNamed(t, dir, "a.db", map[string][]string{
		"nvd": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
	})
	addMatchableEntries(t, dbA, nil, []int{getVulnID(t, dbA, "CVE-2024-0001")})

	// B: 3 CVEs, CVE-0001 and CVE-0002 are matchable
	dbB := createTestDBNamed(t, dir, "b.db", map[string][]string{
		"nvd": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
	})
	addMatchableEntries(t, dbB, []int{getVulnID(t, dbB, "CVE-2024-0001"), getVulnID(t, dbB, "CVE-2024-0002")}, nil)

	// Without matchable: all 3 common, no diffs
	result, err := DrillProvider(dbA, dbB, "nvd")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Common) != 3 {
		t.Errorf("without matchable: expected 3 common, got %d", len(result.Common))
	}

	// With matchable: only CVE-0001 is common, CVE-0002 only in B
	result, err = DrillProvider(dbA, dbB, "nvd", WithMatchable(true))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Common) != 1 || result.Common[0] != "CVE-2024-0001" {
		t.Errorf("matchable common: expected [CVE-2024-0001], got %v", result.Common)
	}
	if len(result.OnlyInB) != 1 || result.OnlyInB[0] != "CVE-2024-0002" {
		t.Errorf("matchable onlyB: expected [CVE-2024-0002], got %v", result.OnlyInB)
	}
	if len(result.OnlyInA) != 0 {
		t.Errorf("matchable onlyA: expected empty, got %v", result.OnlyInA)
	}
}

func TestDrillProvider_ShowsDiffs(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDBNamed(t, dir, "a.db", map[string][]string{
		"github": {"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"},
	})
	dbB := createTestDBNamed(t, dir, "b.db", map[string][]string{
		"github": {"CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"},
	})

	result, err := DrillProvider(dbA, dbB, "github")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.OnlyInA) != 1 || result.OnlyInA[0] != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001 only in A, got %v", result.OnlyInA)
	}
	if len(result.OnlyInB) != 1 || result.OnlyInB[0] != "CVE-2024-0004" {
		t.Errorf("expected CVE-2024-0004 only in B, got %v", result.OnlyInB)
	}
	if len(result.Common) != 2 {
		t.Errorf("expected 2 common, got %d", len(result.Common))
	}
}

func TestDrillProvider_ProviderNotInEither(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDB(t, dir, "a.db", map[string]int{"nvd": 5})
	dbB := createTestDB(t, dir, "b.db", map[string]int{"nvd": 5})

	_, err := DrillProvider(dbA, dbB, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent provider")
	}
}

func TestDrillProvider_ProviderOnlyInOneDB(t *testing.T) {
	dir := t.TempDir()
	dbA := createTestDBNamed(t, dir, "a.db", map[string][]string{
		"nvd": {"CVE-2024-0001", "CVE-2024-0002"},
	})
	dbB := createTestDBNamed(t, dir, "b.db", map[string][]string{
		"ubuntu": {"CVE-2024-0003"},
	})

	// Provider only in A
	result, err := DrillProvider(dbA, dbB, "nvd")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OnlyInA) != 2 {
		t.Errorf("expected 2 only in A, got %d", len(result.OnlyInA))
	}
	if len(result.OnlyInB) != 0 {
		t.Errorf("expected 0 only in B, got %d", len(result.OnlyInB))
	}

	// Provider only in B
	result, err = DrillProvider(dbA, dbB, "ubuntu")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OnlyInA) != 0 {
		t.Errorf("expected 0 only in A, got %d", len(result.OnlyInA))
	}
	if len(result.OnlyInB) != 1 {
		t.Errorf("expected 1 only in B, got %d", len(result.OnlyInB))
	}
}

func TestDrillProvider_Identical(t *testing.T) {
	dir := t.TempDir()
	cves := []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}
	dbA := createTestDBNamed(t, dir, "a.db", map[string][]string{"nvd": cves})
	dbB := createTestDBNamed(t, dir, "b.db", map[string][]string{"nvd": cves})

	result, err := DrillProvider(dbA, dbB, "nvd")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.OnlyInA) != 0 || len(result.OnlyInB) != 0 {
		t.Errorf("expected no diffs, got onlyA=%v onlyB=%v", result.OnlyInA, result.OnlyInB)
	}
	if len(result.Common) != 3 {
		t.Errorf("expected 3 common, got %d", len(result.Common))
	}
}
