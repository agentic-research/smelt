package inspect

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"

	_ "modernc.org/sqlite"
)

// Result holds everything the DB knows about a CVE.
type Result struct {
	CVE           string          `json:"cve"`
	DBBuildTime   string          `json:"db_build_time"`
	SchemaVersion string          `json:"schema_version"`
	Aliases       []string        `json:"aliases,omitempty"`
	Providers     []ProviderEntry `json:"providers"`
}

// ProviderEntry holds one provider's data for this CVE.
type ProviderEntry struct {
	Provider       string         `json:"provider"`
	VulnName       string         `json:"vuln_name"`       // may differ from CVE (e.g. GHSA-xxx)
	Status         string         `json:"status"`
	PublishedDate  string         `json:"published_date"`
	ModifiedDate   string         `json:"modified_date"`
	PackageMatches int            `json:"package_matches"`
	CPEMatches     int            `json:"cpe_matches"`
	Matchable      bool           `json:"matchable"`
	Packages       []PackageMatch `json:"packages,omitempty"`
	CPEs           []CPEMatch     `json:"cpes,omitempty"`
}

// PackageMatch is a single affected package entry.
type PackageMatch struct {
	Name       string `json:"name"`
	Ecosystem  string `json:"ecosystem"`
	Distro     string `json:"distro,omitempty"`
	FixState   string `json:"fix_state,omitempty"`
	FixVersion string `json:"fix_version,omitempty"`
	Constraint string `json:"constraint,omitempty"`
}

// CPEMatch is a single affected CPE entry.
type CPEMatch struct {
	Vendor         string `json:"vendor"`
	Product        string `json:"product"`
	TargetSoftware string `json:"target_software,omitempty"`
	FixState       string `json:"fix_state,omitempty"`
	FixVersion     string `json:"fix_version,omitempty"`
	Constraint     string `json:"constraint,omitempty"`
}

// blobData is the minimal structure we parse from affected_*_handle blobs.
type blobData struct {
	Ranges []struct {
		Version struct {
			Constraint string `json:"constraint"`
		} `json:"version"`
		Fix struct {
			State   string `json:"state"`
			Version string `json:"version"`
		} `json:"fix"`
	} `json:"ranges"`
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
				COALESCE(os.name || ':' || os.major_version, ''),
				COALESCE(b.value, '')
			FROM affected_package_handles ap
			JOIN packages p ON ap.package_id = p.id
			LEFT JOIN operating_systems os ON ap.operating_system_id = os.id
			LEFT JOIN blobs b ON ap.blob_id = b.id
			WHERE ap.vulnerability_id = ?`, vulnID)
		if err == nil {
			for pkgRows.Next() {
				var pm PackageMatch
				var blob string
				if err := pkgRows.Scan(&pm.Name, &pm.Ecosystem, &pm.Distro, &blob); err == nil {
					parseFixInfo(blob, &pm.FixState, &pm.FixVersion, &pm.Constraint)
					e.Packages = append(e.Packages, pm)
				}
			}
			_ = pkgRows.Close()
		}
		e.PackageMatches = len(e.Packages)

		// CPEs
		cpeRows, err := db.Query(`
			SELECT c.vendor, c.product, COALESCE(c.target_software, ''), COALESCE(b.value, '')
			FROM affected_cpe_handles ac
			JOIN cpes c ON ac.cpe_id = c.id
			LEFT JOIN blobs b ON ac.blob_id = b.id
			WHERE ac.vulnerability_id = ?`, vulnID)
		if err == nil {
			for cpeRows.Next() {
				var cm CPEMatch
				var blob string
				if err := cpeRows.Scan(&cm.Vendor, &cm.Product, &cm.TargetSoftware, &blob); err == nil {
					parseFixInfo(blob, &cm.FixState, &cm.FixVersion, &cm.Constraint)
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

func parseFixInfo(blob string, state, version, constraint *string) {
	if blob == "" {
		return
	}
	var bd blobData
	if err := json.Unmarshal([]byte(blob), &bd); err != nil || len(bd.Ranges) == 0 {
		return
	}
	r := bd.Ranges[0]
	*state = r.Fix.State
	*version = r.Fix.Version
	*constraint = r.Version.Constraint
}
