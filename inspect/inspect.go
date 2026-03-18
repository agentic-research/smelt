package inspect

import (
	"database/sql"
	"fmt"
	"sort"

	_ "modernc.org/sqlite"
)

// Result holds everything the DB knows about a CVE.
type Result struct {
	CVE           string
	DBBuildTime   string
	SchemaVersion string
	Aliases       []string
	Providers     []ProviderEntry
}

// ProviderEntry holds one provider's data for this CVE.
type ProviderEntry struct {
	Provider       string
	VulnName       string // may differ from CVE (e.g. GHSA-xxx)
	Status         string
	PublishedDate  string
	ModifiedDate   string
	PackageMatches int
	CPEMatches     int
	Matchable      bool
	Packages       []PackageMatch
	CPEs           []CPEMatch
}

// PackageMatch is a single affected package entry.
type PackageMatch struct {
	Name      string
	Ecosystem string
	Distro    string
	FixState  string
}

// CPEMatch is a single affected CPE entry.
type CPEMatch struct {
	Vendor         string
	Product        string
	TargetSoftware string
}

// CVE inspects a vulnerability database for everything it knows about a CVE.
// Accepts CVE IDs or GHSA IDs (resolves via alias table).
func CVE(dbPath, id string) (*Result, error) {
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()

	result := &Result{}

	// DB metadata
	if err := db.QueryRow(`SELECT build_timestamp, model, revision, addition FROM db_metadata`).
		Scan(&result.DBBuildTime, new(int), new(int), new(int)); err == nil {
		var model, rev, add int
		_ = db.QueryRow(`SELECT model, revision, addition FROM db_metadata`).Scan(&model, &rev, &add)
		result.SchemaVersion = fmt.Sprintf("%d.%d.%d", model, rev, add)
	}

	// Resolve aliases: find the canonical CVE and all related names
	names := resolveNames(db, id)
	if len(names) == 0 {
		return nil, fmt.Errorf("CVE %q not found in database", id)
	}

	// Pick the CVE-* as canonical, or first name
	result.CVE = names[0]
	for _, n := range names {
		if len(n) > 4 && n[:4] == "CVE-" {
			result.CVE = n
			break
		}
	}

	// Aliases are all names except the canonical
	for _, n := range names {
		if n != result.CVE {
			result.Aliases = append(result.Aliases, n)
		}
	}
	sort.Strings(result.Aliases)

	// Query each name's vulnerability handles
	for _, name := range names {
		entries, err := queryProviderEntries(db, name)
		if err != nil {
			return nil, err
		}
		result.Providers = append(result.Providers, entries...)
	}

	sort.Slice(result.Providers, func(i, j int) bool {
		return result.Providers[i].Provider < result.Providers[j].Provider
	})

	if len(result.Providers) == 0 {
		return nil, fmt.Errorf("CVE %q not found in database", id)
	}

	return result, nil
}

// resolveNames finds all names associated with an ID via the alias table.
func resolveNames(db *sql.DB, id string) []string {
	seen := map[string]bool{id: true}
	queue := []string{id}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		rows, err := db.Query(`SELECT name, alias FROM vulnerability_aliases WHERE name = ? OR alias = ?`, current, current)
		if err != nil {
			continue
		}
		for rows.Next() {
			var name, alias string
			if err := rows.Scan(&name, &alias); err != nil {
				continue
			}
			for _, n := range []string{name, alias} {
				if !seen[n] {
					seen[n] = true
					queue = append(queue, n)
				}
			}
		}
		_ = rows.Close()
	}

	// Only keep names that actually have vulnerability_handles
	var names []string
	for name := range seen {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM vulnerability_handles WHERE name = ?`, name).Scan(&count); err == nil && count > 0 {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func queryProviderEntries(db *sql.DB, name string) ([]ProviderEntry, error) {
	rows, err := db.Query(`
		SELECT id, name, provider_id,
			COALESCE(status, ''),
			COALESCE(published_date, ''),
			COALESCE(modified_date, '')
		FROM vulnerability_handles WHERE name = ?`, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []ProviderEntry
	for rows.Next() {
		var vulnID int
		var e ProviderEntry
		if err := rows.Scan(&vulnID, &e.VulnName, &e.Provider, &e.Status, &e.PublishedDate, &e.ModifiedDate); err != nil {
			return nil, err
		}

		// Packages
		pkgRows, err := db.Query(`
			SELECT p.name, p.ecosystem,
				COALESCE(os.name || ':' || os.major_version, '')
			FROM affected_package_handles ap
			JOIN packages p ON ap.package_id = p.id
			LEFT JOIN operating_systems os ON ap.operating_system_id = os.id
			WHERE ap.vulnerability_id = ?`, vulnID)
		if err == nil {
			for pkgRows.Next() {
				var pm PackageMatch
				if err := pkgRows.Scan(&pm.Name, &pm.Ecosystem, &pm.Distro); err == nil {
					e.Packages = append(e.Packages, pm)
				}
			}
			_ = pkgRows.Close()
		}
		e.PackageMatches = len(e.Packages)

		// CPEs
		cpeRows, err := db.Query(`
			SELECT c.vendor, c.product, COALESCE(c.target_software, '')
			FROM affected_cpe_handles ac
			JOIN cpes c ON ac.cpe_id = c.id
			WHERE ac.vulnerability_id = ?`, vulnID)
		if err == nil {
			for cpeRows.Next() {
				var cm CPEMatch
				if err := cpeRows.Scan(&cm.Vendor, &cm.Product, &cm.TargetSoftware); err == nil {
					e.CPEs = append(e.CPEs, cm)
				}
			}
			_ = cpeRows.Close()
		}
		e.CPEMatches = len(e.CPEs)

		e.Matchable = e.PackageMatches > 0 || e.CPEMatches > 0
		entries = append(entries, e)
	}

	return entries, rows.Err()
}
