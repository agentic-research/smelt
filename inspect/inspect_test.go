package inspect

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func createTestDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	_, err = db.Exec(`
		CREATE TABLE db_metadata (
			build_timestamp datetime NOT NULL,
			model INTEGER NOT NULL,
			revision INTEGER NOT NULL,
			addition INTEGER NOT NULL
		);
		INSERT INTO db_metadata VALUES ('2026-03-18 19:06:09+00:00', 6, 1, 4);

		CREATE TABLE providers (
			id TEXT PRIMARY KEY
		);
		CREATE TABLE blobs (
			id INTEGER PRIMARY KEY,
			value TEXT
		);
		CREATE TABLE vulnerability_handles (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			provider_id TEXT NOT NULL,
			status TEXT,
			published_date datetime,
			modified_date datetime,
			blob_id INTEGER
		);
		CREATE TABLE vulnerability_aliases (
			name TEXT,
			alias TEXT,
			PRIMARY KEY (name, alias)
		);
		CREATE TABLE packages (
			id INTEGER PRIMARY KEY,
			ecosystem TEXT,
			name TEXT
		);
		CREATE TABLE operating_systems (
			id INTEGER PRIMARY KEY,
			name TEXT,
			major_version TEXT,
			minor_version TEXT
		);
		CREATE TABLE cpes (
			id INTEGER PRIMARY KEY,
			part TEXT,
			vendor TEXT,
			product TEXT,
			target_software TEXT
		);
		CREATE TABLE affected_package_handles (
			id INTEGER PRIMARY KEY,
			vulnerability_id INTEGER,
			operating_system_id INTEGER,
			package_id INTEGER,
			blob_id INTEGER
		);
		CREATE TABLE affected_cpe_handles (
			id INTEGER PRIMARY KEY,
			vulnerability_id INTEGER,
			cpe_id INTEGER,
			blob_id INTEGER
		);
	`)
	if err != nil {
		t.Fatal(err)
	}

	// Providers
	for _, p := range []string{"nvd", "debian", "github"} {
		_, _ = db.Exec("INSERT INTO providers (id) VALUES (?)", p)
	}

	// Blobs
	_, _ = db.Exec(`INSERT INTO blobs VALUES (1, '{"id":"CVE-2024-1234","description":"Test vuln"}')`)
	_, _ = db.Exec(`INSERT INTO blobs VALUES (2, '{"ranges":[{"version":{"type":"dpkg"},"fix":{"version":"1.2.3-1","state":"fixed"}}]}')`)
	_, _ = db.Exec(`INSERT INTO blobs VALUES (3, '{"ranges":[{"version":{"constraint":">= 1.0, < 1.2.3"},"fix":{"version":"1.2.3","state":"fixed"}}]}')`)

	// NVD entry (no packages, 1 CPE)
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status, published_date, modified_date, blob_id)
		VALUES (1, 'CVE-2024-1234', 'nvd', 'analyzed', '2024-01-15', '2024-02-01', 1)`)
	_, _ = db.Exec(`INSERT INTO cpes VALUES (1, 'a', 'example', 'libfoo', '')`)
	_, _ = db.Exec(`INSERT INTO affected_cpe_handles (vulnerability_id, cpe_id, blob_id) VALUES (1, 1, 3)`)

	// Debian entry (1 package, no CPEs)
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (2, 'CVE-2024-1234', 'debian', 'active')`)
	_, _ = db.Exec(`INSERT INTO packages VALUES (1, 'deb', 'libfoo')`)
	_, _ = db.Exec(`INSERT INTO operating_systems VALUES (1, 'debian', '12', '')`)
	_, _ = db.Exec(`INSERT INTO affected_package_handles (vulnerability_id, operating_system_id, package_id, blob_id) VALUES (2, 1, 1, 2)`)

	// Alias
	_, _ = db.Exec(`INSERT INTO vulnerability_aliases VALUES ('GHSA-xxxx-yyyy-zzzz', 'CVE-2024-1234')`)

	// GitHub entry for the GHSA
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (3, 'GHSA-xxxx-yyyy-zzzz', 'github', 'active')`)
	_, _ = db.Exec(`INSERT INTO packages VALUES (2, 'npm', 'libfoo-js')`)
	_, _ = db.Exec(`INSERT INTO affected_package_handles (vulnerability_id, package_id, blob_id) VALUES (3, 2, 3)`)

	return dbPath
}

func TestInspect_FindsCVE(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	if result.CVE != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", result.CVE)
	}
	if result.DBBuildTime == "" {
		t.Error("expected non-empty build time")
	}
	if result.SchemaVersion != "6.1.4" {
		t.Errorf("expected schema 6.1.4, got %s", result.SchemaVersion)
	}
}

func TestInspect_Providers(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	// Should find nvd + debian directly, plus github via alias
	if len(result.Providers) != 3 {
		t.Errorf("expected 3 providers, got %d: %v", len(result.Providers), providerNames(result))
	}

	nvd := findProvider(result, "nvd")
	if nvd == nil {
		t.Fatal("missing nvd provider")
	}
	if nvd.Status != "analyzed" {
		t.Errorf("nvd status: expected analyzed, got %s", nvd.Status)
	}
	if nvd.CPEMatches != 1 {
		t.Errorf("nvd cpe matches: expected 1, got %d", nvd.CPEMatches)
	}
	if nvd.PackageMatches != 0 {
		t.Errorf("nvd pkg matches: expected 0, got %d", nvd.PackageMatches)
	}

	deb := findProvider(result, "debian")
	if deb == nil {
		t.Fatal("missing debian provider")
	}
	if deb.PackageMatches != 1 {
		t.Errorf("debian pkg matches: expected 1, got %d", deb.PackageMatches)
	}
}

func TestInspect_Aliases(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Aliases) != 1 || result.Aliases[0] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("expected alias GHSA-xxxx-yyyy-zzzz, got %v", result.Aliases)
	}
}

func TestInspect_SearchByAlias(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	// Should resolve GHSA to CVE
	result, err := CVE(dbPath, "GHSA-xxxx-yyyy-zzzz")
	if err != nil {
		t.Fatal(err)
	}

	if result.CVE != "CVE-2024-1234" {
		t.Errorf("expected CVE-2024-1234, got %s", result.CVE)
	}
	// Should still find all 3 providers
	if len(result.Providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(result.Providers))
	}
}

func TestInspect_Packages(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	deb := findProvider(result, "debian")
	if len(deb.Packages) != 1 {
		t.Fatalf("expected 1 debian package, got %d", len(deb.Packages))
	}
	if deb.Packages[0].Name != "libfoo" {
		t.Errorf("expected libfoo, got %s", deb.Packages[0].Name)
	}
	if deb.Packages[0].Distro != "debian:12" {
		t.Errorf("expected debian:12, got %s", deb.Packages[0].Distro)
	}
}

func TestInspect_CPEs(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	nvd := findProvider(result, "nvd")
	if len(nvd.CPEs) != 1 {
		t.Fatalf("expected 1 CPE, got %d", len(nvd.CPEs))
	}
	if nvd.CPEs[0].Vendor != "example" || nvd.CPEs[0].Product != "libfoo" {
		t.Errorf("expected example:libfoo, got %s:%s", nvd.CPEs[0].Vendor, nvd.CPEs[0].Product)
	}
}

func TestInspect_NotFound(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	_, err := CVE(dbPath, "CVE-9999-0000")
	if err == nil {
		t.Fatal("expected error for missing CVE")
	}
}

func TestInspect_Matchable(t *testing.T) {
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	result, err := CVE(dbPath, "CVE-2024-1234")
	if err != nil {
		t.Fatal(err)
	}

	// nvd has 1 CPE, debian has 1 pkg, github has 1 pkg = all matchable
	for _, p := range result.Providers {
		if !p.Matchable {
			t.Errorf("provider %s should be matchable", p.Provider)
		}
	}
}

func TestInspect_StubNotMatchable(t *testing.T) {
	// A CVE that exists but has no packages or CPEs — pure NVD stub
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	// Add a stub CVE with no affected entries
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (100, 'CVE-2024-9999', 'nvd', 'received')`)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	result, err := CVE(dbPath, "CVE-2024-9999")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(result.Providers))
	}
	if result.Providers[0].Matchable {
		t.Error("stub should not be matchable")
	}
	if result.Providers[0].PackageMatches != 0 || result.Providers[0].CPEMatches != 0 {
		t.Error("stub should have 0 matches")
	}
}

func TestInspect_MultipleDistroEntries(t *testing.T) {
	// A CVE in multiple distro providers — like CVE-2026-2673 in debian + rhel + ubuntu
	dir := t.TempDir()
	dbPath := createTestDB(t, dir)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec("INSERT INTO providers (id) VALUES ('rhel')")
	_, _ = db.Exec("INSERT INTO packages VALUES (10, 'rpm', 'openssl')")
	_, _ = db.Exec("INSERT INTO operating_systems VALUES (10, 'redhat', '9', '')")

	// NVD stub
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (50, 'CVE-2024-5678', 'nvd', 'analyzing')`)
	// Debian with package
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (51, 'CVE-2024-5678', 'debian', 'active')`)
	_, _ = db.Exec(`INSERT INTO affected_package_handles (vulnerability_id, operating_system_id, package_id) VALUES (51, 1, 1)`)
	// RHEL with package
	_, _ = db.Exec(`INSERT INTO vulnerability_handles (id, name, provider_id, status) VALUES (52, 'CVE-2024-5678', 'rhel', 'active')`)
	_, _ = db.Exec(`INSERT INTO affected_package_handles (vulnerability_id, operating_system_id, package_id) VALUES (52, 10, 10)`)
	_ = db.Close()

	result, err := CVE(dbPath, "CVE-2024-5678")
	if err != nil {
		t.Fatal(err)
	}

	if len(result.Providers) != 3 {
		t.Fatalf("expected 3 providers, got %d: %v", len(result.Providers), providerNames(result))
	}

	nvd := findProvider(result, "nvd")
	if nvd.Matchable {
		t.Error("nvd stub should not be matchable")
	}

	deb := findProvider(result, "debian")
	if !deb.Matchable || deb.PackageMatches != 1 {
		t.Errorf("debian: matchable=%v pkg=%d", deb.Matchable, deb.PackageMatches)
	}

	rhel := findProvider(result, "rhel")
	if !rhel.Matchable || rhel.PackageMatches != 1 {
		t.Errorf("rhel: matchable=%v pkg=%d", rhel.Matchable, rhel.PackageMatches)
	}
	if rhel.Packages[0].Distro != "redhat:9" {
		t.Errorf("expected redhat:9, got %s", rhel.Packages[0].Distro)
	}
}

func providerNames(r *Result) []string {
	var names []string
	for _, p := range r.Providers {
		names = append(names, fmt.Sprintf("%s(pkg=%d,cpe=%d)", p.Provider, p.PackageMatches, p.CPEMatches))
	}
	return names
}

func findProvider(r *Result, name string) *ProviderEntry {
	for i := range r.Providers {
		if r.Providers[i].Provider == name {
			return &r.Providers[i]
		}
	}
	return nil
}
