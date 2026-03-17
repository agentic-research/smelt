package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/agentic-research/smelt/diff"
)

var (
	diffStateA    string
	diffStateB    string
	diffProvider  string
	diffMatchable bool

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

	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(versionCmd)
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
