# smelt

**Know exactly what's different between two grype vulnerability databases.**

## Table of Contents

- [Install](#install)
- [Commands](#commands)
  - [diff — Compare two databases](#diff--compare-two-databases)
  - [inspect — Debug a single CVE](#inspect--debug-a-single-cve)
- [How it works](#how-it-works)
- [Reference](#reference)
- [License](#license)

## Install

```bash
go install github.com/agentic-research/smelt/cmd/smelt@latest
```

## Commands

### diff — Compare two databases

Compare provider coverage and row counts between any two grype vulnerability databases:

```bash
smelt diff db-a.db db-b.db
```

```
PROVIDER                             DB-A       DB-B      DELTA
--------------------------------------------------------------
epss                               320636     320636          0
github                              48851      48844         -7
kev                                  1542       1542          0
nvd                                337953     337953          0
alpine (B only)                         -       8572      +8572
debian (B only)                         -     106554    +106554
rhel (B only)                           -      24762     +24762
ubuntu (B only)                         -      56146     +56146
--------------------------------------------------------------
TOTAL                              724773    1079089    +354316
```

#### Drill into a provider

See exactly which CVEs differ for a specific provider:

```bash
smelt diff db-a.db db-b.db --provider github
```

```
Provider: github
Common: 48844  |  Only in A: 7  |  Only in B: 0

Only in DB-A:
  - GHSA-3q53-ww3h-grwr
  - GHSA-5g36-7rfc-494g
  - GHSA-5mcx-ff2q-gjjf
```

#### Filter to effective coverage

Many NVD entries are stubs — no CPE or package match data, so grype can't match against them. Use `--matchable` to see only entries grype can actually use:

```bash
smelt diff db-a.db db-b.db --matchable
```

```
PROVIDER                             DB-A       DB-B      DELTA
--------------------------------------------------------------
nvd                                295426     295426          0
...
--------------------------------------------------------------
TOTAL                              360028     687556    +327528
```

42,527 NVD entries filtered out (stubs with no CPE data).

### inspect — Debug a single CVE

Show everything a database knows about a specific CVE — which providers have it, whether it's matchable, what packages and CPEs are covered:

```bash
smelt inspect vulnerability.db CVE-2024-3094
```

```
CVE:       CVE-2024-3094
DB Built:  2026-03-18T19:06:09Z
Schema:    6.1.4
Aliases:   GHSA-rxc8-2hfw-w2f5
Providers: 4

[~] debian  status=active  pkg=6  cpe=0
      pkg: xz-utils [deb] (debian:12)
      pkg: xz-utils [deb] (debian:13)
      ...
[~] github (via GHSA-rxc8-2hfw-w2f5)  status=active  pkg=1  cpe=0
      pkg: tukaani-project/xz [go]
[~] nvd  status=analyzed  pkg=0  cpe=2
      cpe: tukaani:xz
      cpe: tukaani:xz target=linux_kernel
[~] ubuntu  status=active  pkg=3  cpe=0
      pkg: xz-utils [deb] (ubuntu:22)
      pkg: xz-utils [deb] (ubuntu:24)
      pkg: xz-utils [deb] (ubuntu:25)
```

`[~]` = matchable (grype can detect it), `[x]` = stub (entry exists but no match data).

Also resolves GHSA IDs:

```bash
smelt inspect vulnerability.db GHSA-rxc8-2hfw-w2f5
```

Returns the same result, resolving the alias to `CVE-2024-3094`.

## How it works

```mermaid
flowchart TD
    DB[vulnerability.db] --> Q[SQLite queries]

    Q --> Diff[smelt diff\nPer-provider counts + deltas]
    Q --> Inspect[smelt inspect\nSingle CVE deep dive]

    Diff -->|--provider X| CVE[CVE-level diff]
    Diff -->|--matchable| F[Filter to matchable entries]
    Inspect --> P[Providers + packages + CPEs]
    Inspect --> A[Alias resolution]
```

smelt reads the grype-db v6 schema directly (`providers`, `vulnerability_handles`, `affected_package_handles`, `affected_cpe_handles`, `vulnerability_aliases`). Falls back to v5 namespace queries for older databases. Enrichment providers (EPSS, KEV) are counted from their own tables.

## Reference

| Command | Description |
|---------|-------------|
| `smelt diff <a> <b>` | Compare two databases |
| `smelt diff --provider X` | CVE-level diff for one provider |
| `smelt diff --matchable` | Only count entries with package/CPE data |
| `smelt diff --state-a --state-b` | Compare mache state graphs |
| `smelt inspect <db> <cve>` | Show all data for a CVE or GHSA |
| `smelt version` | Print version |

## License

[Apache-2.0](LICENSE)
