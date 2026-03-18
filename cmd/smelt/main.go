package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/agentic-research/smelt/diff"
	"github.com/agentic-research/smelt/inspect"
)

var (
	diffStateA    string
	diffStateB    string
	diffProvider  string
	diffMatchable bool
	outputJSON    bool

	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "smelt",
	Short: "Compare and validate grype vulnerability databases",
}

var diffCmd = &cobra.Command{
	Use:   "diff <db-a> <db-b>",
	Short: "Compare two vulnerability databases",
	Long: `Diff compares two grype vulnerability databases side by side.

Shows per-provider row counts, added/removed providers, and count deltas.
Use --provider to drill into CVE-level differences for a specific provider.
Use --matchable to only count entries grype can actually match against
(those with affected_package or affected_cpe entries — filters out stubs).

Examples:
  smelt diff upstream-v6.db candidate-v6.db
  smelt diff a.db b.db --matchable
  smelt diff a.db b.db --provider nvd --matchable
  smelt diff a.db b.db --state-a a-state.db --state-b b-state.db`,
	Args: cobra.ExactArgs(2),
	RunE: runDiff,
}

var inspectCmd = &cobra.Command{
	Use:   "inspect <db> [db-b] <cve>",
	Short: "Show everything a database knows about a CVE",
	Long: `Inspect shows all providers, packages, CPEs, and aliases for a CVE.

Resolves GHSA IDs to CVEs via the alias table. Reports DB build time
and whether each provider entry is matchable by grype.

Pass two databases to compare the same CVE side by side.

Examples:
  smelt inspect vulnerability.db CVE-2026-2673
  smelt inspect vulnerability.db GHSA-xxxx-yyyy-zzzz
  smelt inspect db-a.db db-b.db CVE-2026-2673`,
	Args: cobra.RangeArgs(2, 3),
	RunE: runInspect,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("smelt %s (commit: %s, built: %s)\n", version, commit, date)
	},
}

func init() {
	diffCmd.Flags().StringVar(&diffStateA, "state-a", "", "Path to state.db for first database")
	diffCmd.Flags().StringVar(&diffStateB, "state-b", "", "Path to state.db for second database")
	diffCmd.Flags().StringVar(&diffProvider, "provider", "", "Drill into CVE-level diff for a specific provider")
	diffCmd.Flags().BoolVar(&diffMatchable, "matchable", false, "Only count entries with affected packages or CPEs (effective coverage)")
	diffCmd.Flags().BoolVar(&outputJSON, "json", false, "Output result as JSON")
	inspectCmd.Flags().BoolVar(&outputJSON, "json", false, "Output result as JSON")

	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(versionCmd)
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runDiff(cmd *cobra.Command, args []string) error {
	if diffProvider != "" {
		return runDiffProvider(args[0], args[1], diffProvider)
	}

	var opts []diff.Option
	if diffStateA != "" && diffStateB != "" {
		opts = append(opts, diff.WithStatePaths(diffStateA, diffStateB))
	}
	if diffMatchable {
		opts = append(opts, diff.WithMatchable(true))
	}

	result, err := diff.CompareDBs(args[0], args[1], opts...)
	if err != nil {
		return err
	}

	if outputJSON {
		return printJSON(result)
	}

	fmt.Printf("%-30s %10s %10s %10s\n", "PROVIDER", "DB-A", "DB-B", "DELTA")
	fmt.Println(strings.Repeat("-", 62))

	for _, p := range result.Common {
		if p.CountA == 0 && p.CountB == 0 {
			continue
		}
		fmt.Printf("%-30s %10d %10d %10s\n", p.Provider, p.CountA, p.CountB, formatDelta(p.Delta))
	}

	for _, p := range result.OnlyInA {
		if p.CountA == 0 {
			continue
		}
		fmt.Printf("%-30s %10d %10s %10s\n", p.Provider+" (A only)", p.CountA, "-", formatDelta(-p.CountA))
	}

	for _, p := range result.OnlyInB {
		if p.CountB == 0 {
			continue
		}
		fmt.Printf("%-30s %10s %10d %10s\n", p.Provider+" (B only)", "-", p.CountB, formatDelta(p.CountB))
	}

	fmt.Println(strings.Repeat("-", 62))
	fmt.Printf("%-30s %10d %10d %10s\n", "TOTAL", result.TotalA, result.TotalB, formatDelta(result.TotalB-result.TotalA))

	if result.StateComparison != nil {
		sc := result.StateComparison
		fmt.Printf("\nState graph diff:\n")
		fmt.Printf("  New CVEs:       %d\n", sc.NewCVEs)
		fmt.Printf("  Removed CVEs:   %d\n", sc.RemovedCVEs)
		fmt.Printf("  State changes:  %d\n", sc.StateChanges)
		fmt.Printf("  Conflicts A:    %d\n", sc.ConflictsA)
		fmt.Printf("  Conflicts B:    %d\n", sc.ConflictsB)
		fmt.Printf("  Conflict delta: %s\n", formatDelta(sc.ConflictsB-sc.ConflictsA))
	}

	return nil
}

func formatFix(state, version, constraint string) string {
	if state == "" {
		return ""
	}
	s := "  " + state
	if version != "" {
		s += " @ " + version
	}
	if constraint != "" {
		s += " (" + constraint + ")"
	}
	return s
}

func formatDelta(d int) string {
	switch {
	case d > 0:
		return fmt.Sprintf("+%d", d)
	case d < 0:
		return fmt.Sprintf("%d", d)
	default:
		return "0"
	}
}

func runDiffProvider(pathA, pathB, provider string) error {
	var opts []diff.Option
	if diffMatchable {
		opts = append(opts, diff.WithMatchable(true))
	}
	result, err := diff.DrillProvider(pathA, pathB, provider, opts...)
	if err != nil {
		return err
	}

	if outputJSON {
		return printJSON(result)
	}

	fmt.Printf("Provider: %s\n", result.Provider)
	fmt.Printf("Common: %d  |  Only in A: %d  |  Only in B: %d\n\n",
		len(result.Common), len(result.OnlyInA), len(result.OnlyInB))

	if len(result.OnlyInA) > 0 {
		fmt.Println("Only in DB-A:")
		for _, name := range result.OnlyInA {
			fmt.Printf("  - %s\n", name)
		}
		fmt.Println()
	}

	if len(result.OnlyInB) > 0 {
		fmt.Println("Only in DB-B:")
		for _, name := range result.OnlyInB {
			fmt.Printf("  + %s\n", name)
		}
		fmt.Println()
	}

	return nil
}

func runInspect(cmd *cobra.Command, args []string) error {
	if len(args) == 3 {
		return runInspectCompare(args[0], args[1], args[2])
	}

	result, err := inspect.CVE(args[0], args[1])
	if err != nil {
		return err
	}

	if outputJSON {
		return printJSON(result)
	}

	fmt.Printf("CVE:       %s\n", result.CVE)
	fmt.Printf("DB Built:  %s\n", result.DBBuildTime)
	fmt.Printf("Schema:    %s\n", result.SchemaVersion)

	if len(result.Aliases) > 0 {
		fmt.Printf("Aliases:   %s\n", strings.Join(result.Aliases, ", "))
	}

	fmt.Printf("Providers: %d\n\n", len(result.Providers))

	for _, p := range result.Providers {
		matchIcon := "x"
		if p.Matchable {
			matchIcon = "~"
		}

		name := p.VulnName
		if name != result.CVE {
			name = fmt.Sprintf("%s (via %s)", p.Provider, p.VulnName)
		} else {
			name = p.Provider
		}

		fmt.Printf("[%s] %s  status=%s  pkg=%d  cpe=%d\n", matchIcon, name, p.Status, p.PackageMatches, p.CPEMatches)

		for _, pkg := range p.Packages {
			distro := ""
			if pkg.Distro != "" {
				distro = " (" + pkg.Distro + ")"
			}
			fix := formatFix(pkg.FixState, pkg.FixVersion, pkg.Constraint)
			fmt.Printf("      pkg: %s [%s]%s%s\n", pkg.Name, pkg.Ecosystem, distro, fix)
		}
		for _, cpe := range p.CPEs {
			ts := ""
			if cpe.TargetSoftware != "" {
				ts = " target=" + cpe.TargetSoftware
			}
			fix := formatFix(cpe.FixState, cpe.FixVersion, cpe.Constraint)
			fmt.Printf("      cpe: %s:%s%s%s\n", cpe.Vendor, cpe.Product, ts, fix)
		}
	}

	return nil
}

func runInspectCompare(pathA, pathB, cve string) error {
	resultA, errA := inspect.CVE(pathA, cve)
	resultB, errB := inspect.CVE(pathB, cve)

	if errA != nil && errB != nil {
		return fmt.Errorf("%s not found in either database", cve)
	}

	printInspectSide := func(label string, r *inspect.Result, err error) {
		fmt.Printf("=== %s ===\n", label)
		if err != nil {
			fmt.Printf("  (not found)\n\n")
			return
		}
		fmt.Printf("  DB Built:  %s\n", r.DBBuildTime)
		fmt.Printf("  Providers: %d\n", len(r.Providers))
		matchable := 0
		totalPkg := 0
		totalCPE := 0
		for _, p := range r.Providers {
			if p.Matchable {
				matchable++
			}
			totalPkg += p.PackageMatches
			totalCPE += p.CPEMatches
		}
		fmt.Printf("  Matchable: %d/%d\n", matchable, len(r.Providers))
		fmt.Printf("  Packages:  %d\n", totalPkg)
		fmt.Printf("  CPEs:      %d\n\n", totalCPE)

		for _, p := range r.Providers {
			icon := "x"
			if p.Matchable {
				icon = "~"
			}
			name := p.Provider
			if p.VulnName != r.CVE {
				name = fmt.Sprintf("%s (via %s)", p.Provider, p.VulnName)
			}
			fmt.Printf("  [%s] %s  status=%s  pkg=%d  cpe=%d\n", icon, name, p.Status, p.PackageMatches, p.CPEMatches)
		}
		fmt.Println()
	}

	fmt.Printf("CVE: %s\n\n", cve)
	printInspectSide("DB-A", resultA, errA)
	printInspectSide("DB-B", resultB, errB)

	return nil
}
