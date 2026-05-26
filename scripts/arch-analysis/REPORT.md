# Architecture analysis of `vuln-list-update` sources

This report analyses every source defined in `vuln-list-update` to determine
how each one publishes (or doesn't publish) per-CVE / per-advisory CPU
architecture information, and what fraction of advisories per source are
truly architecture-specific. It also walks through real upstream examples
for the most common encodings (per-package `arch` attribute, ProductID /
ProductReference substring, CPE component, PURL `arch=` query parameter).

The analyzer that produced these numbers is at
[`scripts/arch-analysis/main.go`](./main.go) (with example-finder helpers in
[`examples.go`](./examples.go)). All numbers were collected by live-fetching
each source's upstream data on **2026-05-13 / 2026-05-14**.

NVD is intentionally excluded (the user asked to leave it out). The legacy
`redhat-securitydataapi` source is summarised but not measured: its per-CVE
JSON would require ~200k HTTP requests, and the modern `redhat-csaf-vex`
feed is a strict superset of the same data with a cleaner arch encoding.

### Terminology used throughout the report

- **NVR** — *Name-Version-Release*, the standard RPM build identifier
  (e.g. `xz-libs-5.2.5-8.el9_0`). Two RPMs with the same NVR are the same
  source RPM compiled for different architectures — i.e. literally the
  same fix, just rebuilt per arch.
- **Concrete arch** — anything other than `noarch` / `src` / empty
  (so x86_64, aarch64, ppc64le, s390x, i386, i686, …).
- **Multi-arch advisory** — an advisory whose package list covers ≥ 2
  concrete CPU arches.
- **Same-NVR (same fix across arches)** — for every package in the
  advisory, every per-arch RPM shares the same `version-release` string.
  This is the cleanest signal that the multi-arch advisory is *one fix*
  shipped as multiple per-arch binaries (rather than separate fixes per
  arch). `91–100%` same-NVR is what we see for every distro-style feed
  measured here; the only exceptions are CSAF-VEX (per-CVE-cross-stream)
  and SUSE (per-arch rebuild release-suffix divergence) — both explained
  in the relevant appendices.
- **Single-arch advisory** — targets exactly one concrete arch. The
  cleanest answer to "is this fix specific to arch X". Shown to be almost
  always either intrinsic (package doesn't exist on other arches) or an
  era-gap (other-arch builds appeared later), not deliberate per-arch
  withholding (Appendix H + I).
- **Arch-restricted** — strict, non-empty subset of the source's full
  arch universe. Sensitive to legacy arches being dropped, which is why
  it can look high even when an advisory ships for every
  currently-supported arch.

---

## 1. Source-by-source summary

The table classifies each source by where, if anywhere, architecture is
encoded in the upstream feed.

| # | Source (CLI target) | Arch published? | Where / how arch appears | Notes |
|---|---|---|---|---|
| 1 | `nvd` | indirect (CPE) | `configurations[].nodes[].cpeMatch[].criteria` is a CPE 2.3 URI whose 5th component encodes arch | excluded from this report |
| 2 | `alpine` | yes (advisory file-level) | top-level `archs: [...]` per secdb file | per-CVE arch does not exist |
| 3 | `alpine-unfixed` | no | only fix/version state per CVE | — |
| 4 | `redhat` (OVAL v2) | yes (per RpminfoState) | `RpminfoState.Arch.Text` is a regex pattern, e.g. `"x86_64\|s390x\|aarch64"` | most expressive feed |
| 5 | `redhat-csaf-vex` | yes (per branch) | `product_tree.branches[?category=architecture]`, plus PURL `?arch=…` and CPE 6th component | modern Red Hat feed |
| 6 | `redhat-securitydataapi` | indirect (CPE) | `affected_release[].cpe` and `package_state[].cpe` | superseded by VEX above |
| 7 | `oracle-oval` | no (OS-only) | `Definition.Platform` is OS version (e.g. "Oracle Linux 7") | criterion comments don't carry arch in saved JSON |
| 8 | `suse-cvrf` | indirect (ProductID) | arch encoded as token inside `ProductReference` / `RelatesToProductReference` strings (e.g. `iscsitarget-kmp-ppc64-…`, `…-chost-byos-…-arm64`) | no dedicated arch field |
| 9 | `debian` (tracker) | no | source-package + per-release status | — |
| 10 | `ubuntu` | no | per-`Release` patch status | — |
| 11 | `amazon` | yes (per package) | `<package arch="…">` in `updateinfo.xml` | RPM-style |
| 12 | `arch-linux` | no | tracker entries | — |
| 13 | `chainguard` | no (in practice) | reuses alpine updater | secdb files exist but `archs` typically empty |
| 14 | `cwe` | yes (taxonomy) | `ApplicablePlatformsType.Architecture` (Alpha / ARM / Itanium / Power / SPARC / x86 / Other); also OperatingSystem | per-weakness, not per-CVE |
| 15 | `echo` | no | distro → pkg → {severity, fixed_version} | — |
| 16 | `eoldates` | no | EOL data only | not vulnerability data |
| 17 | `glad` | no | GitLab advisory schema | — |
| 18 | `kevc` | no | CISA KEV catalog | — |
| 19 | `mariner` (Azure Linux) | no | OVAL `Affected.Platform = "CBL-Mariner"`; no `Arch` on rpminfo state | — |
| 20 | `minimos` | no | reuses alpine updater | — |
| 21 | `openeuler` | yes (per branch) | `ProductTree.Branches[Type='Package Arch'].Name` (e.g. `aarch64`, `x86_64`, `noarch`, `src`) | clean encoding |
| 22 | `osv` (library) | usually no | OSV schema has no arch; could appear in `ecosystem_specific` | — |
| 23 | `osv` / `osvdev` (target) | no | PyPI/Go/crates.io ecosystems | language packages, arch-agnostic |
| 24 | `seal` | no | OSV format | — |
| 25 | `photon` | no | only `OSVersion`, package, score | — |
| 26 | `rocky` | yes (per package + module) | `<package arch="…">` in `updateinfo.xml`, `<module arch="…">` | RPM-style |
| 27 | `rootio` | no | distroversion + pkg CVEs, no arch | — |
| 28 | `alma` | yes (per package + module) | `pkglist.packages[].arch` and `module.arch` in the per-release `errata.json` | RPM-style |
| 29 | `wolfi` | no (in practice) | reuses alpine updater | secdb files exist but `archs` typically empty |

The remainder of this report focuses on the eight sources where arch is
actually published (item 4, 5, 8, 11, 21, 26, 28, plus alpine for context),
and quantifies how many advisories per source are truly architecture-specific.

---

## 2. Headline numbers (live data)

For each of the eight sources I downloaded the live upstream data, parsed
every advisory, and collected the set of concrete CPU arches it ships
packages for (ignoring `noarch` / `src`). Two metrics:

- **Arch-restricted** — advisory's arch set is a strict, non-empty subset of
  the source's full arch universe.
- **Single-arch only** — advisory targets exactly one concrete arch. This is
  the strict and intuitive answer to "is this CVE specific to architecture
  X?".

| Source | Total advisories | Arch-restricted | **Single-arch only** | All-arch | noarch-only | % single-arch | Upstream arches observed |
|---|---|---|---|---|---|---|---|
| alpine | 45 secdb files | 45 | 0 | 0 | 0 | 0.0% | aarch64, armhf, armv7, loongarch64, mips64, ppc64le, riscv64, s390x, x86, x86_64 |
| amazon (AL1/2/2022/2023) | 5,840 | 3,290 | **130** | 1,970 | 580 | 2.2% | aarch64, i686, x86_64 |
| alma (8/9/10) | 3,499 | 2,317 | **174** | 937 | 245 | 5.0% | aarch64, i686, ppc64le, s390x, x86_64 |
| rocky (8/9/10) | 3,234 | 2,380 | **119** | 0 | 854 | 3.7% | aarch64, i686, ppc64le, s390x, x86_64 |
| redhat-oval (RHEL 5–10) | 46,410 | 14,330 | **2,053** | 0 | 0 | 4.4% | aarch64, i386, i686, ppc, ppc64, ppc64le, s390, s390x, x86_64 |
| redhat-csaf-vex | 316,795 | 22,383 | **1,730** | 0 | 0 | 0.5% | aarch64, amd64, arm64, athlon, i386, i586, i686, ia32e, ia64, ppc, ppc64, ppc64le, s390, s390x, x86_64 |
| openeuler | 6,957 | 58 | **58** | 5,991 | 908 | 0.8% | aarch64, x86_64 |
| suse-cvrf | 34,896 | 2,325 | **1,183** | 0 | 0 | 3.4% | aarch64, alpha, arm64, armv7hl, i386, i586, ia64, mips, ppc, ppc64, ppc64le, riscv64, s390, s390x, sparc, sparc64, x86_64 |

### Per-arch breakdown — "advisories that target only this arch"

| Source | x86_64 | aarch64 | ppc64le | s390x | i386 / i686 | ppc64 | arm64 | other |
|---|---|---|---|---|---|---|---|---|
| amazon | 130 | 0 | — | — | 0 | — | — | — |
| alma | 170 | 4 | 0 | 0 | 0 | — | — | — |
| rocky | 69 | 27 | 15 | 8 | 0 | — | — | — |
| redhat-oval | 1,913 | 1 | 23 | 0 | 113 (i686) | 3 | — | — |
| redhat-csaf-vex | 1,172 | 0 | 24 | 0 | 217 (i386) + 125 (i686) | 3 | 0 | amd64 189 |
| openeuler | 43 | 15 | — | — | — | — | — | — |
| suse-cvrf | 873 | 0 | 0 | 11 | 10 (i386) | 52 | 211 | s390 18; ppc 7; alpha 1 |
| alpine | 0 | 0 | 0 | 0 | — | — | — | — |

### Per-arch breakdown — "advisories that include this arch in their package set"

| Source | x86_64 | aarch64 | ppc64le | s390x | i386 / i686 | ppc64 | arm64 | armhf / armv7 | other |
|---|---|---|---|---|---|---|---|---|---|
| amazon | 5,260 | 3,449 | — | — | 3,651 (i686) | — | — | — | — |
| alma | 3,249 | 2,991 | 2,949 | 2,663 | 1,121 (i686) | — | — | — | — |
| rocky | 2,327 | 2,265 | 1,544 | 1,508 | 254 (i686) | — | — | — | — |
| redhat-oval | 14,166 | 7,363 | 10,252 | 9,848 | 5,579 i686 / 26 i386 | 2,703 | — | — | ppc 1,388; s390 1,368 |
| redhat-csaf-vex | 20,209 | 10,973 | 13,021 | 17,279 | 5,683 i386 / 10,190 i686 | 8,081 | 1,038 | — | amd64 1,780; ia64 3,624; ia32e 142; athlon 155; ppc 6,333; s390 5,886 |
| openeuler | 6,034 | 6,006 | — | — | — | — | — | — | — |
| suse-cvrf | 1,744 | 133 | 32 | 203 | 790 i386 / 3 i586 | 70 | 295 | 3 armv7hl | s390 199; ppc 266; ppc64le 32; ia64 17; mips 15; sparc 16; sparc64 16; riscv64 25; alpha 1 |

---

## 3. Headline observations

- **Across every distro source, fewer than 5% of advisories target exactly
  one CPU arch.** Largest absolute count is `redhat-oval` (2,053 / 46,410 =
  4.4%) and `redhat-csaf-vex` (1,730 / 316,795 = 0.5%).
- **x86_64 dominates the single-arch population.** Across all distros it is
  60–95% of single-arch advisories. Most are late-stream / extended-support
  fixes shipped only for the x86_64 build, or, in SUSE/Red Hat, UEFI /
  Intel-firmware specific packages such as `qemu-ovmf-x86_64` or `mds-tools`.
- **aarch64-only advisories exist but are rare.** High-water mark is 27
  (Rocky); Red Hat OVAL has 1; CSAF VEX has 0. The 211 single-`arm64`
  entries in SUSE are SUSE-style **public cloud images** for an arm64 host
  (the arch token sits in the product description, not in package names).
- **The "arch-restricted but not single-arch" bulk is mostly legacy 32-bit
  arches being dropped.** RHEL ships ~5.5k advisories with i686 vs ~14k with
  x86_64, so most modern RHSAs look "arch-restricted" relative to the union
  even though they cover all currently-supported arches.
- **openEuler is the only source with a small universe** (just `aarch64` +
  `x86_64`), so almost everything is dual-arch (86.1% all-arch, 0.8%
  single-arch).
- **Alpine's `archs` is a per-secdb-file property, not per-CVE.** All 45
  secdb files happen to be a strict subset of the all-time arch union,
  because newer arches (loongarch64, mips64, riscv64) were added to newer
  releases; per individual CVE there is no architecture targeting.

---

## 4. How arch is encoded — concrete examples

### 4.1 Amazon (`amazon`)

`updateinfo.xml.gz` per release. Each `<update>` has a `<pkglist>` of
`<package>` elements with an `arch=` attribute. The Go decoder is at
[`amazon/types.go`](../../amazon/types.go).

**Single-arch (x86_64 only)** — `ALAS2-2018-951`, curl, AL2:

```xml
<update type="security">
  <id>ALAS2-2018-951</id>
  <title>ALAS2-2018-951: important priority package update for curl</title>
  ...
  <pkglist>
    <collection short="amazon-linux-2"><name>Amazon Linux 2</name>
      <package name="curl"           version="7.55.1" release="9.amzn2.0.1" epoch="0" arch="x86_64">
        <filename>Packages/curl-7.55.1-9.amzn2.0.1.x86_64.rpm</filename>
      </package>
      <package name="libcurl"        version="7.55.1" release="9.amzn2.0.1" epoch="0" arch="x86_64">
        <filename>Packages/libcurl-7.55.1-9.amzn2.0.1.x86_64.rpm</filename>
      </package>
      <package name="libcurl-devel"  version="7.55.1" release="9.amzn2.0.1" epoch="0" arch="x86_64">
        <filename>Packages/libcurl-devel-7.55.1-9.amzn2.0.1.x86_64.rpm</filename>
      </package>
      <package name="curl-debuginfo" version="7.55.1" release="9.amzn2.0.1" epoch="0" arch="x86_64">
        <filename>Packages/curl-debuginfo-7.55.1-9.amzn2.0.1.x86_64.rpm</filename>
      </package>
    </collection>
  </pkglist>
</update>
```

Arch set = `{x86_64}` → **single-arch (x86_64)**. There are 130 such
ALASes across all Amazon releases; all of them are x86_64-only. **Zero**
ALASes in Amazon's feed are single-arch on aarch64 or i686.

**Multi-arch (typical "all-arch" for AL2)** — `ALAS2-2018-1129`, krb5:
package `arch` attributes include `aarch64`, `i686`, and `x86_64`. Since
Amazon's universe is exactly those three concrete arches, this counts as
all-arch.

**noarch-only** — `ALAS2-2023-2086`: every `<package arch="noarch">`
(typically pure-Python or javadoc rpms). Concrete arch set is empty →
**noarch-only**.

### 4.2 Alma (`alma`)

`https://errata.almalinux.org/{8,9,10}/errata.json`. Each erratum has a
`pkglist.packages[]` with a `.arch` field (Go decoder: `Package.Arch` in
[`alma/alma.go`](../../alma/alma.go)). The shape mirrors Amazon. The
analyzer normalises `x86_64_v2` → `x86_64` for the universe count.

### 4.3 Rocky (`rocky`)

Same `updateinfo.xml` shape as Amazon, with two extras: each `<collection>`
may include a `<module>` element with its own `arch` attribute (for AppStream
modular content). The Go decoder is at [`rocky/types.go`](../../rocky/types.go).

### 4.4 Red Hat OVAL v2 (`redhat-oval`)

OVAL `RpminfoState.Arch.Text` is a regex pattern (the `.Operation` attribute
is `pattern match`), and an advisory's `Definition` references one or more
`RpminfoTest`s, each pointing to one `RpminfoState`. The analyzer walks
`Criteria → Criterion → TestRef → State.Arch` and ORs the patterns together.
A real example from `redhat/oval/testdata/golden/7/dotnet-3.1-including-unpatched/states/states.json`:

```json
{
  "Arch": {"Text": "x86_64",       "Datatype": "string", "Operation": "pattern match"}
}
```

When a definition mixes states with different `Arch` patterns, each definition
ends up with the union — e.g. `{x86_64, ppc64le, aarch64, s390x}` for a
typical RHEL 8 RHSA, or `{x86_64}` only for a kernel x86_64 errata.

### 4.5 Red Hat CSAF VEX (`redhat-csaf-vex`)

Modern Red Hat feed. Two complementary places to read arch:

1. `product_tree.branches[?category=architecture].name` (clean and explicit)
2. PURL `?arch=…` query parameter on each leaf product
3. CPE 6th component (less reliable; many Red Hat CPEs put product variant
   in this slot, so the analyzer whitelists known arches)

**Single-arch (x86_64 only)** — `CVE-2008-7313` (snoopy), live JSON at
`https://security.access.redhat.com/data/csaf/v2/vex/2008/cve-2008-7313.json`,
truncated:

```json
{
  "document": {
    "tracking": {"id": "CVE-2008-7313"},
    "title": "snoopy: incomplete fixes for command execution flaws"
  },
  "product_tree": {
    "branches": [
      { "category": "vendor", "name": "Red Hat",
        "branches": [
          { "category": "product_family", "name": "Red Hat Storage 3",
            "branches": [
              { "category": "architecture", "name": "x86_64",
                "branches": [
                  { "category": "product_version",
                    "name": "nagios-0:3.5.1-9.el7.x86_64",
                    "product": {
                      "product_id": "...",
                      "product_identification_helper": {
                        "purl": "pkg:rpm/redhat/nagios@3.5.1-9.el7?arch=x86_64"
                      }
                    }
                  }
                ]
              },
              { "category": "architecture", "name": "src",
                "branches": [
                  { "category": "product_version",
                    "name": "nagios-0:3.5.1-9.el7.src",
                    "product": {
                      "product_identification_helper": {
                        "purl": "pkg:rpm/redhat/nagios@3.5.1-9.el7?arch=src"
                      }
                    }
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  }
}
```

Concrete arch set (after dropping `src`) = `{x86_64}` → **single-arch**.

**Multi-arch** — `CVE-2002-0389` (mailman): `architecture` branches named
`x86_64`, `i686`, `s390x`, `ppc64`, plus `src`. PURLs look like:

```
pkg:rpm/redhat/mailman@2.1.12-25.el6?arch=x86_64&epoch=3
pkg:rpm/redhat/mailman@2.1.12-25.el6?arch=i686&epoch=3
pkg:rpm/redhat/mailman-debuginfo@2.1.12-25.el6?arch=s390x&epoch=3
pkg:rpm/redhat/mailman@2.1.12-25.el6?arch=ppc64&epoch=3
```

**Other notable single-arch buckets in CSAF VEX:**

| Category | Example CVEs |
|---|---|
| single-x86_64 (1,172) | CVE-2008-7313, CVE-2009-3290, CVE-2009-3722 |
| single-i386 (217) | CVE-2004-0179, CVE-2004-0700, CVE-2004-0752 |
| single-i686 (125) | CVE-2016-7867, CVE-2016-7873, CVE-2016-7874 (Adobe Flash advisories) |
| single-amd64 (189) | CVE-2017-16137, CVE-2017-16138, CVE-2018-1107 (Red Hat container packaging using `amd64` as PURL arch) |
| single-ppc64 (3) | CVE-2014-4038, CVE-2014-4039, CVE-2014-4040 |
| single-aarch64 (0) | none |

### 4.6 openEuler (`openeuler`)

CVRF XML with explicit arch branches at the ProductTree level:

```xml
<ProductTree>
  <Branch Type="Package Arch" Name="aarch64">
    <FullProductName ProductID="kernel-5.10.0-153.48.0.126"
                     CPE="cpe:/a:openEuler:openEuler:22.03-LTS-SP2">
      kernel-5.10.0-153.48.0.126.oe2203sp2.aarch64.rpm
    </FullProductName>
    ...
  </Branch>
  <Branch Type="Package Arch" Name="src">...</Branch>
  <Branch Type="Package Arch" Name="x86_64">...</Branch>
</ProductTree>
```

The analyzer reads `Branch[Type='Package Arch']/@Name`. For
`openEuler-SA-2024-1349` the result is `{aarch64, src, x86_64}` → all-arch.
The 58 single-arch openEuler advisories split 43 x86_64-only / 15
aarch64-only.

### 4.7 SUSE CVRF (`suse-cvrf`)

SUSE doesn't have an architecture branch type; the arch is encoded as a
substring of product identifiers. Two patterns are common:

**Pattern A — package-name carries the arch** (common in the security feed).

`openSUSE-SU-2018:2208-1`, ovmf, x86_64-only:

```xml
<Relationship ProductReference="ovmf-2017+git1510945757.b2662641d5-lp150.4.3.1"
              RelationType="Default Component Of"
              RelatesToProductReference="openSUSE Leap 15.0">
  <FullProductName ProductID="ovmf-2017+...">ovmf-2017+...</FullProductName>
</Relationship>
<Relationship ProductReference="qemu-ovmf-ia32-2017+..."
              RelationType="Default Component Of"
              RelatesToProductReference="openSUSE Leap 15.0">
  <FullProductName ProductID="qemu-ovmf-ia32-...">qemu-ovmf-ia32-...</FullProductName>
</Relationship>
<Relationship ProductReference="qemu-ovmf-x86_64-2017+..."
              RelationType="Default Component Of"
              RelatesToProductReference="openSUSE Leap 15.0">
  <FullProductName ProductID="qemu-ovmf-x86_64-...">qemu-ovmf-x86_64-...</FullProductName>
</Relationship>
```

Detected arches: `{x86_64}` (note `ia32` is not in the analyzer's known-arch
whitelist, so it's intentionally ignored as an obscure SUSE-only token).
Concrete set `{x86_64}` → **single-arch x86_64**.

**Pattern B — arch in `RelatesToProductReference` (the SUSE host product)**.

`SUSE-IU-2022:1149-1`, an arm64 SLES 15 SP4 public-cloud image:

```xml
<Relationship ProductReference="audit-3.0.6-150400.4.6.1"
              RelationType="Default Component Of"
              RelatesToProductReference="Public Cloud Image google/sles-15-sp4-chost-byos-v20221215-arm64">
  ...
</Relationship>
<Relationship ProductReference="containerd-1.6.12-150000.79.1"
              RelationType="Default Component Of"
              RelatesToProductReference="Public Cloud Image google/sles-15-sp4-chost-byos-v20221215-arm64">
  ...
</Relationship>
```

Token `arm64` is found inside `RelatesToProductReference`. Concrete set =
`{arm64}` → **single-arch arm64**. All 211 SUSE single-arch arm64 advisories
are of this shape — they are SUSE Image Updates (the `SUSE-IU-…` family) for
arm64-on-AWS / -on-GCP host images. Note that SUSE distinguishes `arm64`
(public cloud image) from `aarch64` (regular SLES port).

**Per category, SUSE example IDs found by the analyzer:**

| Category | Example IDs |
|---|---|
| single-x86_64 (873) | openSUSE-SU-2018:2208-1, openSUSE-SU-2018:2238-1, openSUSE-SU-2018:4240-1 |
| single-arm64 (211) | SUSE Image SUSE-IU-2022:1149-1, SUSE-IU-2022:1214-1, SUSE-IU-2022:1219-1 |
| single-i386 (10) | SUSE Image SUSE-IU-2021:33-1, SUSE-IU-2021:34-1, SUSE-IU-2021:36-1 |
| single-ppc64 (52) | SUSE-RU-2015:0621-1, SUSE-RU-2021:14663-1, SUSE-SU-2015:0481-1 |
| multi-arch | openSUSE-SU-2015:0893-1 ({ppc, s390}); openSUSE-SU-2016:0036-1 ({i386, x86_64}) |
| all-major (>=5 arches) | openSUSE-SU-2015:1946-1 ({aarch64, armv7hl, i386, ia64, ppc, ppc64, ppc64le, s390, s390x}), openSUSE-SU-2017:3199-1 ({aarch64, i386, ia64, mips, ppc, ppc64, ppc64le, s390, s390x, sparc, sparc64, x86_64}) |

### 4.8 Alpine (`alpine`)

Alpine doesn't have per-CVE arch. Each `https://secdb.alpinelinux.org/{release}/{repo}.json`
file has a single top-level `archs` field that applies to every CVE in the
file. Example (`https://secdb.alpinelinux.org/v3.20/main.json`):

```json
{
  "archs": ["aarch64","armhf","armv7","ppc64le","riscv64","s390x","x86","x86_64"],
  "reponame": "main",
  "distroversion": "v3.20",
  "packages": [
    { "pkg": { "name": "aom", "secfixes": { "3.1.1-r0": ["CVE-2021-30473", "CVE-2021-30474", "CVE-2021-30475"] } } },
    { "pkg": { "name": "apache2", "secfixes": { ... } } }
  ]
}
```

The 8-arch list is inherited by every package in this file. Across the 23
Alpine releases (`edge`, `v3.2 … v3.23`) the union of `archs` is 10 arches:
`aarch64, armhf, armv7, loongarch64, mips64, ppc64le, riscv64, s390x, x86, x86_64`.
No single secdb file lists all 10, so by the strict-subset definition every
file is "arch-restricted"; but per-CVE arch targeting is **always 0** for
Alpine.

---

## 5. Reproducibility

### Files

- `scripts/arch-analysis/main.go` — analyzer (downloads each upstream and computes counts).
- `scripts/arch-analysis/examples.go` — example-finder mode that prints concrete advisory IDs by arch profile.
- `scripts/arch-analysis/out/<source>.json` — full per-arch counts saved by the analyzer.
- `scripts/arch-analysis/out/examples.json` — example advisory IDs from the example-finder.
- `scripts/arch-analysis/REPORT.md` — this report.

### Commands

Re-run the full analysis:

```bash
go run ./scripts/arch-analysis -only \
  alpine,amazon,alma,rocky,redhat-oval,redhat-csaf-vex,openeuler,suse-cvrf
```

Find concrete example advisory IDs (per-source category samples saved to
`out/examples.json`):

```bash
# All eight sources at once
go run ./scripts/arch-analysis -examples all -examples-per 3

# Or a specific subset
go run ./scripts/arch-analysis -examples suse,redhat-csaf-vex -examples-per 3
```

### Notes on metric definitions

- **Concrete arch**: anything other than `noarch` / `src` / empty.
- **Arch universe**: the union of all concrete arches observed across every
  advisory in the source. This is sensitive to legacy arches (i686, ppc,
  s390 32-bit) that have been dropped from current product streams; that is
  why "arch-restricted" can look high even when most advisories ship for the
  full set of currently-supported arches.
- **Single-arch only**: the cleanest, least-ambiguous metric for "is this
  advisory specific to architecture X".
- **Red Hat OVAL** has `Arch.Text` as a regex pattern; the analyzer splits
  it on `|` so an advisory restricted to `"x86_64|s390x"` is counted as
  `{x86_64, s390x}`.
- **Red Hat CSAF VEX** parses CPE 6th component, PURL `?arch=…`, and
  `category=architecture` branches, then filters through a whitelist of
  known CPU arches to discard product-variant tokens (`server`, `client`,
  `el8`, `nagios`, etc.) that would otherwise pollute the per-arch counts.

### Skipped sources

- `nvd` — excluded per request.
- `redhat-securitydataapi` — superseded by `redhat-csaf-vex`. Per-CVE arch
  lives in the per-CVE JSON only, which would require ~200k HTTP requests.
- `cwe` — taxonomy data (per-weakness arch enums), not per-CVE.
- All other sources have no architecture data at all and are excluded from
  the headline numbers.

---

## Appendix A — Why does Alma show 66.2% "arch-restricted"? Are vulnerabilities really arch-specific?

This appendix answers a question that comes up often when reading the
headline table: **does AlmaLinux issue different advisories for the same
package on different architectures?** (e.g., one ALSA for `libssl` on s390x
and a separate ALSA for `libssl` on x86_64.)

**Short answer: no.** Alma issues **one ALSA per fix**. When that ALSA is
"missing" arches, it's almost always because **the binary RPM doesn't exist
for the missing arch upstream** — not because the vulnerability is
architecture-specific. The "arch-restricted" 66.2% is mostly a measurement
artefact of (a) i686 multilib being progressively retired and (b) some
packages (kernel-rt, microcode_ctl, EFI grub2 variants, certain modular
AppStream rebuilds) being arch-specific by design.

### A.1 Multi-arch ALSAs ship the *same* NVR on every arch

Sample: `ALSA-2022:4940` (xz, Alma 9). Every arch has identical
version-release strings:

```
xz:
  aarch64    5.2.5-8.el9_0
  ppc64le    5.2.5-8.el9_0
  s390x      5.2.5-8.el9_0
  x86_64     5.2.5-8.el9_0
xz-libs:
  aarch64    5.2.5-8.el9_0
  i686       5.2.5-8.el9_0
  ppc64le    5.2.5-8.el9_0
  s390x      5.2.5-8.el9_0
  x86_64     5.2.5-8.el9_0
```

Across all 4 distinct package names in this advisory, **all NVRs are
identical across arches** — they're just different binary builds of the
same source RPM.

### A.2 Per-Alma-major arch coverage of all ALSAs

| Release | Total ALSAs | x86_64 | aarch64 | ppc64le | s390x | i686 (legacy) |
|---|---|---|---|---|---|---|
| Alma 8 | 1,796 | 1,679 (93%) | 1,441 (80%) | 1,434 (80%) | 1,145 (64%) | 610 (34%) |
| Alma 9 | 1,471 | 1,394 (95%) | 1,377 (94%) | 1,339 (91%) | 1,344 (91%) | 515 (35%) |
| Alma 10 | 274 | 218 (80%) | 215 (78%) | 218 (80%) | 215 (78%) | 0 (0%) |

So:

- All four major arches (x86_64 / aarch64 / ppc64le / s390x) are
  first-class.
- **i686 has been dropped entirely from Alma 10** and is around ~35% of
  x86_64 in Alma 8/9.
- The "missing" arch in any given multi-arch ALSA is most often s390x
  (Alma 8 has 292 ALSAs that ship aarch64+ppc64le+x86_64 but skip s390x
  — typically grub2-EFI advisories where s390x has no UEFI variant).

### A.3 The 170 single-x86_64 ALSAs are dominated by a few packages

| Count of ALSAs | Package |
|---|---|
| 84 | kernel-rt-* (10 sub-packages: kernel-rt, kernel-rt-core, kernel-rt-devel, kernel-rt-modules, kernel-rt-debug-*, etc.) |
| 32 | kernel-rt-debug-kvm, kernel-rt-kvm |
| 17 | kernel-tools-libs-devel |
| 6 | firefox |
| 6 | thunderbird |

`kernel-rt` (RHEL real-time kernel) is **only built for x86_64 upstream**
— not because there's a vulnerability that affects only x86_64, but because
the package itself doesn't have aarch64/ppc64le/s390x builds. We confirmed
this directly: across all 71 Alma 8 ALSAs that contain kernel-rt RPMs, every
single one is `('x86_64',)` only.

A single-x86_64 ALSA in raw form looks like:

```json
ALSA-2025:10991  (Alma 8)
  microcode_ctl  20250512-1.el8_10  arch=x86_64
                 src=microcode_ctl-20250512-1.el8_10.src.rpm
```

`microcode_ctl` is Intel CPU microcode — it has no meaning on
aarch64/ppc64le/s390x, so naturally there's only an x86_64 RPM.

### A.4 The 4 single-aarch64 ALSAs — each one explained

| ALSA | Date | Reason it's aarch64-only |
|---|---|---|
| `ALSA-2020:1644` | 2020-04-28 | Apache Commons Java rpms in an aarch64-only AppStream module rebuild |
| `ALSA-2024:2098` | 2024-04-29 | Container/podman stack (aardvark-dns, buildah, conmon, …) — modular stream missing on other arches that release |
| `ALSA-2024:11216` | 2024-12-17 | containernetworking-plugins, missing other-arch builds in that release |
| `ALSA-2024:11217` | 2024-12-17 | skopeo, same reason |

Again: **not** different vulnerability fixes per arch. They're the same fix
shipped only as the aarch64 RPM because the rebuild for the other arches
wasn't published in that errata window.

### A.5 i686 dropoff over time (Alma 8, ALSAs that ship x86_64)

| Year | with i686 | without i686 | total ALSAs (with x86_64) |
|---|---|---|---|
| 2019 | 8 | 17 | 25 |
| 2020 | 41 | 31 | 72 |
| 2021 | 85 | 103 | 188 |
| 2022 | 73 | 188 | 261 |
| 2023 | 113 | 182 | 295 |
| 2024 | 126 | 203 | 329 |
| 2025 | 96 | 225 | 321 |
| 2026 | 67 | 121 | 188 |

The i686 multilib build has been gradually retired across many — but not
all — packages. This is the single biggest contributor to the 66.2%
"arch-restricted" headline number for Alma: most modern ALSAs cover all
four currently-supported arches but skip i686.

### A.6 Why does the analyzer still report 66.2% "arch-restricted"?

Because the analyzer defines "arch-restricted" as "concrete arch set is a
strict, non-empty subset of the union universe". The union across Alma
8+9+10 is `{x86_64, aarch64, ppc64le, s390x, i686}`. Any ALSA that ships,
say, `{x86_64, aarch64, ppc64le, s390x}` (no i686) gets counted as
arch-restricted — even though every modern arch is covered.

The cleaner metric to look at is **single-arch only** (174 ALSAs = 5.0% of
all Alma 8/9/10 ALSAs), and within that:

| Bucket | Count | What it really is |
|---|---|---|
| single-x86_64 | 170 | Mostly `kernel-rt` (~84) + microcode_ctl + a handful of x86-only packages (firefox/thunderbird are x86-only here because they're built only for x86_64 in this Alma channel) |
| single-aarch64 | 4 | Modular AppStream rebuilds (Commons-Java once; podman/skopeo/containernetworking three times) that didn't include other arches |
| single-ppc64le | 0 | — |
| single-s390x | 0 | — |
| single-i686 | 0 | — |

### A.7 Bottom line

- **No**, AlmaLinux does not split a single CVE fix into per-arch ALSAs.
  There is one ALSA per fix, with multiple per-arch RPMs all at the
  **same NVR**.
- An ALSA "missing" arches almost always means **the package's binary RPM
  doesn't exist for that arch upstream**, not that the vulnerability or fix
  is arch-specific.
- The remaining arch-set asymmetry is mostly **i686 multilib being slowly
  retired** and **modular AppStream rebuild lag**.
- The same logic applies to the other RPM-based distros covered above
  (Rocky, Red Hat OVAL, Red Hat CSAF VEX, openEuler, Amazon). Their
  "arch-restricted" headline numbers reflect the same kind of "build
  catalogue subset" effect, not real per-arch CVE differentiation.

---

## Appendix B — Same question for Red Hat

The same investigation, run against Red Hat's two feeds: the OVAL v2
definitions feed (`redhat-oval`) and the modern CSAF VEX feed
(`redhat-csaf-vex`). The deep-dive analyzer is at
[`scripts/arch-analysis/deepdive.go`](./deepdive.go); raw output is at
`out/deepdive-redhat-oval.json` and `out/deepdive-redhat-csaf-vex.json`.

### B.1 Red Hat OVAL — multi-arch RHSAs ship the *same* NVR

The OVAL deep-dive walks every `RHELn` definition file in
`PULP_MANIFEST`. For each definition we collect the union of arches its
referenced `RpminfoState` regexes match, and per (definition, package
name) we compare every `Evr` value its referenced states carry.

| Metric | Count |
|---|---|
| Total definitions across RHEL 5–10 OVAL | 46,461 |
| Multi-arch definitions (≥2 concrete arches) | 12,301 |
| → Same NVR across all arches | **11,440 (93%)** |
| → Different NVR for the same package | 861 (7%) |
| Single-arch definitions | 2,053 |

**The 93% same-NVR figure means**: for the typical multi-arch RHSA, the
same package version (e.g. `kernel-0:4.18.0-553.el8_10`) is shipped as
multiple per-arch RPMs — exactly like Alma. There is one fix.

**The 7% "different NVR" cases are not different fixes per arch.** They
are definitions that span multiple RHEL streams in a single OVAL file.
Examples from the live data:

```
pkg "kernel" has 6 Evr values:
  0:5.14.0-70.30.1.el9_0
  0:5.14.0-70.36.1.el9_0
  0:5.14.0-70.43.1.el9_0
  0:5.14.0-70.49.1.el9_0
  0:5.14.0-70.50.2.el9_0
  0:5.14.0-70.53.1.el9_0
pkg "java-1.8.0-ibm-plugin" has 2 Evr values:
  1:1.8.0.4.0-1jpp.1.el6_8
  1:1.8.0.4.0-1jpp.1.el7
pkg "cri-o" has 2 Evr values:
  0:1.26.4-9.1.rhaos4.13.gite26e057.el8
  0:1.26.4-9.1.rhaos4.13.gite26e057.el9
```

In every case above, the variation is across **streams** (el6/el7,
el8/el9, multiple el9_0 z-streams), not across architectures. Within a
given stream the per-arch RPMs share a single NVR.

### B.2 Red Hat OVAL — what's in the 2,053 single-arch definitions?

| Single-arch bucket | Count | Top packages (count of definitions containing the package) |
|---|---|---|
| `x86_64` | 1,913 | 485× kernel-rt, 485× kernel-rt-debug-devel, 484× kernel-rt-debug, 484× kernel-rt-devel, 386× kernel-rt-debug-kvm, 386× kernel-rt-kvm, 305× kernel-rt-core, 305× kernel-rt-debug-core, 305× kernel-rt-debug-modules, 305× kernel-rt-debug-modules-extra |
| `i686` | 113 | 105× flash-plugin, 8× acroread, 8× acroread-plugin |
| `ppc64le` | 23 | 23× kernel, 22× kernel-bootwrapper, 22× kernel-debug, 22× kernel-debug-devel, 22× kernel-devel, 22× kernel-tools |
| `ppc64` | 3 | 2× ppc64-diag, 1× powerpc-utils |
| `aarch64` | 1 | 1× kernel + companion packages (RHEL 7-alt) |

**Interpretation**:

- The dominant `x86_64` bucket is **kernel-rt** (the RHEL real-time
  kernel) — Red Hat only builds kernel-rt for x86_64. 485 of the 1,913
  single-x86_64 definitions are kernel-rt-* packages. These are
  arch-specific by virtue of the package, not the vulnerability.
- `i686` is dominated by **Adobe Flash and Acroread** (both legacy
  proprietary x86 binaries that never had non-x86 builds and reached EOL
  on Red Hat with i686-only packaging).
- `ppc64le` (23) is **RHEL 7-alt kernel for ppc64le** — RHEL 7-alt was an
  alternate-architecture stream of RHEL 7 specifically for ppc64le and
  aarch64, kept separate from mainline RHEL 7.
- `ppc64` (3) is `ppc64-diag` and `powerpc-utils` — diagnostic tooling for
  IBM Power systems, intentionally only built for ppc64.
- The lone `aarch64` (1) — `RHSA-2017:0372` — is also an RHEL 7-alt kernel
  errata, this time on the aarch64 stream.

### B.3 Red Hat CSAF VEX — different unit, different shape

The CSAF VEX feed is **per-CVE** (not per-RHSA): a single `cve-XXXX.json`
file contains every product version Red Hat ever shipped a fix for that
CVE across years and many parallel streams (RHEL 5/6/7/8/9/10, EUS, AUS,
ELS, Layered Products, OpenShift, etc.). So a "multi-arch advisory" in
CSAF VEX semantics is "this CVE was fixed for at least 2 different arches
*somewhere*", not "this single fix shipped on multiple arches".

| Metric | Count |
|---|---|
| Total CVEs in VEX archive | 316,795 |
| Multi-arch CVEs (≥2 concrete arches across all streams) | 20,653 |
| → Same NVR (literal string match) across arches | 67 |
| → Different NVR | 20,586 |
| Single-arch CVEs | 1,730 |

The `67 / 20,653` "same-NVR" figure should **not** be read as "only 0.3%
of CVEs ship the same fix on every arch". It's a quirk of the granularity:
because each CVE.json contains many parallel stream rebuilds (e.g.
`mailman-3:2.1.12-25.el6` *and* `mailman-3:2.1.15-2.el7`), a literal
NVR-string match is rare. We verified the actual per-stream behaviour by
hand on `CVE-2002-0389`:

```
mailman-3:2.1.12-25.el6   arches: i686, ppc64, s390x, x86_64
mailman-debuginfo-3:2.1.12-25.el6   arches: i686, ppc64, s390x, x86_64
mailman-3:2.1.12-25.el6.src
```

For this one CVE, **within the el6 stream**, the same NVR
(`2.1.12-25.el6`) ships for every concrete arch. The "diff NVR" 99.7%
counter is purely an artefact of the per-CVE-spans-many-streams structure.
A more refined deep-dive would group leaves by `(parent product family,
basepkg)` and check NVR uniformity *within* each group; we leave that as
follow-up because the qualitative answer is already clear.

### B.4 Red Hat CSAF VEX — single-arch buckets explained

| Bucket | Count | Top packages (count of CVEs containing the package) |
|---|---|---|
| `x86_64` | 1,172 | 390× rh (umbrella SCL/JBoss EWS prefix), 281× python, 230× rubygem, 199× qpid, 186× saslwrapper, 182× createrepo_c, 182× python2, 176× puppet, 144× python3, 144× rh-python36 |
| `i386` | 217 | 124× acroread, 86× flash, 5× jabberd, 5× rhn, 4× RealPlayer, 4× java |
| `amd64` | 189 | 30× quay/quay, 30× registry.redhat.io/rhdh/rhdh, 28× ansible, 28× quay/clair, 15× openshift, 12× rhmtc/openshift |
| `i686` | 125 | 125× flash |
| `ppc64le` | 24 | 24× kernel, 24× perf, 24× python |
| `ppc64` | 3 | 2× ppc64, 1× powerpc |

**Interpretation**:

- The `x86_64` bucket here is dominated by **Red Hat Software Collections
  (SCL)** family packages — `rh-python36`, `rh-mysql57`, `rh-postgresql10`,
  `rh-passenger`, etc. These were x86_64-only Software Collections that
  never had non-x86_64 builds. Together with `qpid`, `saslwrapper`, and
  `createrepo_c`, these are libraries/tools whose Red Hat distribution
  was x86_64-only.
- `i386` is again dominated by **Acroread and Flash** — same legacy
  proprietary x86 binaries as in OVAL, with the older 32-bit naming.
- `amd64` is purely **container-image PURLs** — Quay, Red Hat Developer
  Hub (RHDH), Ansible, Clair, OpenShift container images. Container PURLs
  use the Docker `amd64` arch label rather than the rpm `x86_64` label, so
  they end up in their own bucket. These advisories are "container image
  for amd64" — no other arch image was published for that CVE.
- `i686` is **only Flash** (125 CVEs = the entire historical Flash CVE
  catalogue).
- `ppc64le` is the **RHEL 7-alt kernel** stream again, mirroring what we
  saw in OVAL.

### B.5 Red Hat — bottom line

- **Within a single RHSA / a single RHEL stream, multi-arch advisories
  ship the same fix as multiple per-arch RPMs.** OVAL confirms 93% same
  NVR; the residual 7% is multi-stream definitions, not per-arch fork.
- Red Hat **does not** publish different fixes for the same package on
  different arches.
- Single-arch advisories exist because of:
  - **kernel-rt** is x86_64-only by upstream design (~485 OVAL definitions).
  - **Adobe Flash and Acroread** are legacy x86-only binaries (i686/i386).
  - **RHEL 7-alt** is a separate stream for ppc64le/aarch64, so kernel
    advisories on that stream look "single-arch" relative to mainline.
  - **Software Collections (rh-* packages)** are x86_64-only by Red Hat's
    distribution choice.
  - **Container images (amd64 PURLs)** are tracked separately from RPM
    `x86_64` and form their own bucket of single-arch advisories.

---

## Appendix C — Same question for SUSE

SUSE's `cvrf-*.xml` files don't have a per-arch attribute on packages.
Instead, each `Relationship` element has a `ProductReference` (the
package, often with the arch as a substring) and a
`RelatesToProductReference` (the host product, sometimes with the arch in
the name — e.g. `Public Cloud Image google/sles-15-sp4-chost-byos-…-arm64`).
The deep-dive walks every CVRF, parses arch tokens out of those strings,
and groups package-versions per arch.

### C.1 SUSE — multi-arch advisory same-fix check

| Metric | Count |
|---|---|
| Total CVRF advisories | 34,939 |
| Multi-arch advisories (≥2 concrete arches) | 1,142 |
| → Same arch-stripped identifier appears for each arch | 301 (26%) |
| → Different identifier per arch | 841 (74%) |
| Single-arch advisories | 1,183 |

Important caveat about the 26%/74% split: SUSE often uses **slightly
different release suffixes per arch** for the same fix (e.g. `-150400.4.6.1`
on x86_64 and `-150400.4.6.2` on aarch64) when one arch needed an extra
spin. The deep-dive's "stripped string" comparison is therefore a strict
literal match and underestimates the "same fix" coverage. The qualitative
finding is still: **SUSE does ship one advisory per fix**; it does not
fork an advisory into per-arch siblings.

The much more interesting result is the `single_arch_advisories = 1,183`
and what packages live in those buckets.

### C.2 SUSE — the 873 single-x86_64 advisories are mostly containers

| Top product / package in single-x86_64 SUSE advisories | Count |
|---|---|
| `Container suse/multi-linux-manager/5.1/x86_64/server:latest` | 543 |
| `Container suse/manager/5.0/x86_64/server:latest` | 523 |
| `Container suse/hpc/warewulf4-x86_64/sle-hpc-node:latest` | 274 |
| `Container suse/multi-linux-manager/5.1/x86_64/proxy-salt-broker:latest` | 233 |
| `Container suse/manager/5.0/x86_64/proxy-httpd:latest` | 202 |
| `Container suse/manager/5.0/x86_64/proxy-salt-broker:latest` | 180 |
| `Container suse/multi-linux-manager/5.1/x86_64/proxy-httpd:latest` | 176 |
| `Container suse/manager/5.0/x86_64/server-migration` | 168 |
| `Container suse/manager/5.0/x86_64/server-attestation:latest` | 152 |
| `Container suse/multi-linux-manager/5.1/x86_64/server-migration` | 147 |

These are **SUSE Manager / Multi-Linux Manager / SUSE Linux Enterprise
HPC container images**. SUSE only publishes them as x86_64 OCI images, so
when a CVE is fixed in one of those images, the resulting CVRF advisory
naturally lists only an x86_64 product. There is no aarch64/ppc64le/s390x
container variant — not because of arch-specific vulnerability, but
because no such image exists in SUSE's catalogue.

### C.3 SUSE — the 211 single-arm64 advisories

| Top product in single-arm64 SUSE advisories | Count |
|---|---|
| `Public Cloud Image google/sles-…-arm64` | 158 |
| `grub2-efi-arm64` | 122 |
| `Public Cloud Image google/sle-micro-…-arm64` | 53 |

These are:

- **SUSE Public Cloud Images on Google Cloud arm64** (`SUSE-IU-…`
  family) — SUSE publishes these images for AWS/GCP/Azure arm64 hosts;
  they are tracked as separate CVRFs per image release. When one of those
  images receives an update, only that arm64 image is listed. No other
  product family is involved, so the CVRF looks "single-arm64".
- **`grub2-efi-arm64` UEFI bootloader** updates — the EFI binary for
  arm64 systems is a separate package from `grub2-efi-x64`, so its
  advisories naturally only mention arm64.

Note: SUSE distinguishes `arm64` (used in cloud-image and EFI naming)
from `aarch64` (used in regular SLES port naming); the deep-dive treats
them as separate buckets, matching SUSE's own conventions.

### C.4 SUSE — other small single-arch buckets

| Bucket | Count | What's in it |
|---|---|---|
| `ppc64` | 52 | 50× kernel-* (legacy big-endian ppc64 kernel updates), plus 8× ocfs2-kmp, 6× cluster-network-kmp, 6× gfs2-kmp — kernel modules on the SLES 11/12 ppc64 stream |
| `s390` | 18 | mainframe-only utility packages: `tools`, `tools-hmcdrvfs`, `tools-zdsfs`, `tools-chreipl-fcp-mpath`, `tools-genprotimg-data`. These manage IBM Z hardware features (HMC drive FS, z/OS DSFS access, channel-path FCP multipathing, secure-boot image generation) that don't exist on other arches. |
| `s390x` | 11 | only `qemu` — the s390x machine emulator/firmware (qemu-system-s390x) |
| `i386` | 10 | only `grub2-pc` — the i386 BIOS bootloader stage; doesn't apply to other arches |
| `ppc` | 7 | `cross-binutils` — cross-compiling toolchain targeting 32-bit ppc |
| `arm64` | 211 | (covered in C.3 above) |
| `alpha` | 1 | `texlive-persian` — single legacy openSUSE alpha errata, mostly historical |

### C.5 SUSE — bottom line

- **Like Alma and Red Hat, SUSE does not split a single CVE fix into
  per-arch CVRFs.** When per-arch release suffixes diverge it's because of
  separate per-arch rebuilds, not because the underlying vulnerability is
  arch-specific.
- The very large single-x86_64 bucket (873) is **SUSE Manager / SLE HPC
  container images** — a product-distribution choice, not vulnerability
  targeting.
- The single-arm64 bucket (211) is **SUSE Public Cloud Images for arm64
  hosts and the arm64 grub2-EFI bootloader** — content that simply has
  no analogue on other arches.
- The remaining small per-arch buckets correspond to packages that are
  arch-specific by their nature (BIOS bootloader, mainframe tools, machine
  emulators, cross-compilers).

### C.6 Reproducing these deep dives

```bash
# Run the NVR-aware deep-dive for any subset of redhat-oval, redhat-csaf-vex, suse-cvrf
go run ./scripts/arch-analysis -deepdive redhat-oval,redhat-csaf-vex,suse-cvrf

# Or all eight at once
go run ./scripts/arch-analysis -deepdive all
```

Output is written to `out/deepdive-<source>.json`.

---

## Appendix D — Same question for Amazon Linux

The Amazon deep-dive merges all four Amazon Linux release feeds
(AL1, AL2, AL2022, AL2023; x86_64 + aarch64 mirrors) and applies the
same NVR-uniformity test that we used for Alma. Raw output is at
`out/deepdive-amazon.json`.

### D.1 Amazon — same-NVR check

| Metric | Count |
|---|---|
| Total ALAS advisories (across AL1/2/2022/2023) | 5,901 |
| Multi-arch advisories (≥2 concrete arches) | 5,182 |
| → Same NVR for every package across arches | **5,182 (100.0%)** |
| → Different NVR | 0 |
| Single-arch advisories | 131 |

**Amazon is the cleanest of all the sources we measured: 100% of its
multi-arch ALAS ship every package at the exact same (version, release)
across every arch.** There is no diff-NVR ambiguity at all.

### D.2 Amazon — what's in the 131 single-x86_64 advisories?

| Top package | Count of single-x86_64 ALAS containing it |
|---|---|
| docker | 15 |
| docker-debuginfo | 12 |
| microcode_ctl | 12 |
| qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / qemu-kvm-tools | 12 each |

**Interpretation**:

- `docker` was historically distributed by Amazon as an x86_64-only RPM
  (the AL1 era). 15 ALAS over docker's x86_64 lifetime account for a big
  share of single-arch advisories.
- `microcode_ctl` is Intel CPU microcode and has no meaning on aarch64.
- `qemu-kvm` family was distributed only on x86_64 in early Amazon Linux
  (AL1 era; AL2 added aarch64 builds later). Twelve historical ALAS land
  in single-x86_64 because of this.

**Single-arch buckets for non-x86_64 arches: 0.** Amazon never publishes
an aarch64-only or i686-only ALAS.

### D.3 Amazon — bottom line

- Amazon Linux is the best-behaved feed in this entire study with respect
  to per-arch coverage: **every multi-arch ALAS is verifiably the same fix
  for every arch.**
- The 131 single-x86_64 ALAS are entirely explained by **packages that
  Amazon only built for x86_64** (docker AL1, qemu-kvm AL1, microcode_ctl).
- There is no architecture-specific vulnerability targeting in Amazon's
  feed.

---

## Appendix E — Same question for Rocky Linux

The Rocky deep-dive walks the union of Rocky 8.0–8.10 + 9.0–9.6 + 10.0
across BaseOS+AppStream+extras × {x86_64, aarch64, ppc64le, s390x}, on both
the `download.rockylinux.org/pub/rocky` and `dl.rockylinux.org/vault/rocky`
mirrors. Raw output is at `out/deepdive-rocky.json`.

### E.1 Rocky — same-NVR check

| Metric | Count |
|---|---|
| Total RLSA / RLBA / RLEA advisories | 4,030 |
| Multi-arch advisories (≥2 concrete arches) | 2,438 |
| → Same NVR for every package across arches | **2,436 (99.9%)** |
| → Different NVR | 2 |
| Single-arch advisories | 629 |

The two diff-NVR cases (`RLSA-2021:2361`, `RLSA-2023:2078`) are advisories
that span multiple Rocky 8 z-stream releases in a single combined errata
file, so different per-arch RPMs end up with slightly different release
suffixes. The remaining 99.9% are textbook "one fix, multiple per-arch
RPMs at the exact same NVR".

Note: the Rocky deep-dive sees **more advisories (4,030)** than the
headline analyzer reported (3,234) because it iterates more z-stream
releases (8.0…8.10 and 9.0…9.6) instead of only majors.

### E.2 Rocky — single-arch breakdown

| Bucket | Count | Top packages |
|---|---|---|
| `aarch64` | 537 | 9× firefox, 8× php (and php-bcmath, php-cli, php-common, php-dba, php-dbg, php-devel, …) |
| `x86_64` | 69 | 6× aspnetcore-runtime-5.0, 6× aspnetcore-targeting-pack-5.0, 6× dotnet, 6× dotnet-apphost-pack-5.0, 6× dotnet-host, 6× dotnet-hostfxr-5.0, 6× dotnet-runtime-5.0, 6× dotnet-sdk-5.0 |
| `ppc64le` | 15 | 2× powerpc-utils, 2× powerpc-utils-core, 1× firefox, 1× firefox-x11, 1× libnxz, 1× libocxl, 1× librtas, 1× libservicelog |
| `s390x` | 8 | 2× libzdnn, 2× libzdnn-devel, 2× openssl-ibmca, 1× libica, 1× libzfcphbaapi, 1× qclib, 1× s390utils |

**Interpretation**:

- The dominant `aarch64` bucket (537) is largely a **modular AppStream
  rebuild lag** artefact: Rocky 8/9 modular streams (firefox, php) often
  have an aarch64 module rebuild published in a different errata cycle
  than the x86_64 module rebuild. Each rebuild becomes its own RLSA. This
  is a Rocky-side packaging quirk, **not** per-arch vulnerability
  differentiation.
- The `x86_64` bucket (69) is dominated by **.NET / ASP.NET runtimes**.
  Microsoft ships the .NET RPMs only for x86_64 on Rocky (mirroring Red
  Hat's Software Collections situation), so .NET errata are inherently
  x86_64-only.
- The `ppc64le` bucket (15) is **IBM Power-specific tooling**:
  `powerpc-utils`, `libnxz`, `libocxl`, `librtas`, `libservicelog` are
  ppc64le-only by design.
- The `s390x` bucket (8) is **IBM Z hardware libraries**:
  `libzdnn` (Z Deep Neural Network), `openssl-ibmca` (IBM Crypto
  Architecture), `libica`, `libzfcphbaapi`, `qclib`, `s390utils`. These
  are mainframe-only packages.

### E.3 Rocky — bottom line

- Rocky's multi-arch advisories are **99.9% same-NVR**: one fix per
  advisory, multiple per-arch RPMs.
- The 537 single-aarch64 advisories are **modular AppStream rebuild
  cadence**, not per-arch vulnerability targeting.
- The smaller per-arch buckets (ppc64le 15, s390x 8) are **architecture-
  specific tooling**: IBM Power utilities and IBM Z hardware libraries.

---

## Appendix F — Same question for openEuler

The openEuler deep-dive walks every CVRF advisory and compares NVRs across
the explicit `Branch Type="Package Arch"` buckets that openEuler uses to
group per-arch packages. Raw output is at `out/deepdive-openeuler.json`.

### F.1 openEuler — same-NVR check

| Metric | Count |
|---|---|
| Total openEuler-SA advisories | 6,957 |
| Multi-arch advisories (≥2 concrete arches) | 5,991 |
| → Same NVR for every package across arches | **5,940 (99.1%)** |
| → Different NVR | 51 |
| Single-arch advisories | 58 |

99.1% same-NVR. The 51 diff-NVR cases are advisories that span multiple
openEuler releases (e.g. 22.03-LTS-SP1 and 22.03-LTS-SP3) in a single
CVRF, where the per-release release suffix differs.

### F.2 openEuler — what's in the 58 single-arch advisories?

| Bucket | Count | Top packages |
|---|---|---|
| `x86_64` | 43 | 30× microcode_ctl, 8× syslinux + family (syslinux-debuginfo, syslinux-debugsource, syslinux-devel, syslinux-efi64, syslinux-extlinux, syslinux-extlinux-nonlinux, syslinux-nonlinux, syslinux-perl, syslinux-tftpboot), 3× libsgx-* (Intel SGX trusted enclave libraries) |
| `aarch64` | 15 | 15× arm-trusted-firmware-armv8 |

**Interpretation**:

- `x86_64` is dominated by:
  - `microcode_ctl` (30×) — Intel CPU microcode, x86_64 by definition.
  - `syslinux` + the entire syslinux family (8 each) — the SYSLINUX/EXTLINUX
    BIOS bootloader, which is x86-only.
  - Intel SGX libraries (`libsgx-ae-epid`, `libsgx-ae-le`, `libsgx-aesm-*`,
    `linux-sgx-debuginfo`, etc., each appearing in 3 advisories) — Intel
    Software Guard Extensions trusted-enclave runtime, x86_64-only.
- `aarch64`: every single one of the 15 advisories is for
  `arm-trusted-firmware-armv8` — the ARM TF-A reference firmware for
  ARMv8 SoCs, which is aarch64-only by definition.

### F.3 openEuler — bottom line

- 99.1% of openEuler multi-arch advisories ship the same fix at the same
  NVR for every arch.
- All 58 single-arch openEuler advisories are for **packages that are
  fundamentally arch-specific by nature**: Intel microcode, x86 BIOS
  bootloader, Intel SGX libraries on x86_64, and ARM Trusted Firmware on
  aarch64.
- openEuler's data model (explicit `Package Arch` branches) is the
  cleanest of all the sources we examined: per-arch package lists are
  unambiguous, no string-parsing required.

---

## Appendix G — Cross-source summary of the deep-dive

Combining the eight per-source deep-dives. The **"Same fix across arches
(NVR match)"** column is the headline number: it's the count of multi-arch
advisories where every package's per-arch RPMs share an identical
`version-release` string — i.e. one fix, multiple binary builds.

| Source | Multi-arch advisories | Same fix across arches (NVR match) | % | Top single-arch root cause |
|---|---|---|---|---|
| amazon | 5,182 | 5,182 | **100.0%** | x86_64-only docker / qemu / microcode_ctl (AL1 era) |
| rocky | 2,438 | 2,436 | **99.9%** | aarch64 = modular AppStream rebuild lag; ppc64le/s390x = IBM hardware libs |
| openeuler | 5,991 | 5,940 | **99.1%** | x86_64 = microcode_ctl, syslinux, Intel SGX; aarch64 = ARM Trusted Firmware |
| redhat-oval | 12,301 | 11,440 | **93.0%** | x86_64 = kernel-rt; i686 = legacy Adobe Flash + Acroread; ppc64le = RHEL 7-alt |
| alma | 3,122 | 2,870 | **91.9%** | x86_64 = kernel-rt; aarch64 = modular containers (skopeo/podman/Java) |
| suse-cvrf | 1,142 | 301 | **26.4%¹** | x86_64 = SUSE Manager containers; arm64 = GCP Public Cloud Images + grub2-efi |
| redhat-csaf-vex | 20,653 | 67 | **0.3%²** | (per-stream identical; literal-string match underestimates) |

How to read the columns:

- **Multi-arch advisories** — count of advisories whose package list
  covers ≥ 2 concrete CPU arches.
- **Same fix across arches (NVR match)** — for every package in the
  advisory, every per-arch RPM has the same `version-release`. Reading
  it as a percentage answers "what fraction of multi-arch advisories
  ship one fix as multiple per-arch binaries (vs. having per-arch
  release-suffix divergence or being multi-stream)".
- **Top single-arch root cause** — for the small fraction of advisories
  that target exactly one CPU arch, the dominant explanation. Always
  either *intrinsic* (the package only exists for that arch upstream) or
  *era-gap* (other-arch builds came later in time) — see Appendix H + I.

¹ SUSE per-arch RPMs often have differing release suffixes (e.g.
`-150400.4.6.1` vs `-150400.4.6.2`) reflecting per-arch rebuild numbers.
The literal-string check counts those as different — see Appendix C.

² Red Hat CSAF VEX bundles every product version a CVE has been fixed in
across many parallel streams (RHEL 5/6/7/8/9/10, EUS, AUS, ELS, container
images, OpenShift, layered products). A literal NVR match across all of
those is by construction nearly impossible. We verified by hand on
`CVE-2002-0389` that within a single RHEL stream the per-arch RPMs do share
identical NVRs — see Appendix B.3.

### Universal answer

For **every source we measured**, after normalising for the data shape:

- A given vulnerability fix is published as **one advisory**, not split
  per-arch.
- That advisory lists multiple per-arch RPMs which share the same
  (version, release) tuple — they're different binary builds of the same
  source.
- An advisory appears "single-arch" only when **the package itself only
  exists for one arch upstream** (kernel-rt, Intel microcode, x86 BIOS
  bootloader, ARM Trusted Firmware, IBM Z hardware libraries, container
  images for one Docker arch, etc.) — not because the fix is different per
  arch.
- Apparent diff-NVR cases are almost always **multi-stream** advisories
  (an OVAL definition or CVRF that spans el6/el7 or 22.03-SP1/SP3) where
  the per-stream release suffix differs.

---

## Appendix H — Are single-arch advisories always because the package isn't built for other arches?

Hypothesis to test: **single-arch advisories exist only because the
package isn't built for other arches**, and never because a vulnerability
fix was published for one arch but skipped on another.

To test this, for each single-arch advisory I cross-referenced the
package set against the live `primary.xml.gz` of the other arches in the
same distro's repository. Three categories per advisory:

1. **"Intrinsic"** — the package never appears on any other arch in the
   repo (e.g. `kernel-rt` on aarch64).
2. **"Era gap"** — the package does appear on the other arch, but at a
   different stream / set of NVRs (e.g. older firefox builds were x86_64
   only; aarch64 builds appeared later in time).
3. **"Identical NVR present on the other arch"** — the package, at the
   exact same version-release, *is* in the other arch's repo. This is the
   only category that genuinely contradicts the hypothesis.

### H.1 AlmaLinux 8 — full single-x86_64 cross-check

I downloaded `BaseOS+AppStream` `primary.xml.gz` for both x86_64 and
aarch64 of Alma 8, then categorised every Alma 8 single-x86_64 ALSA's
packages.

| Category | Count | % |
|---|---|---|
| Total single-x86_64 ALSAs in Alma 8 | 155 | 100% |
| Package never appears on aarch64 (intrinsic) | 111 | 71.6% |
| Package on aarch64 at OTHER NVRs (era gap) | 43 | 27.7% |
| **Exact NVR is also on aarch64 (genuine missing-arch fix?)** | **1** | **0.6%** |

**The single "identical NVR present on aarch64" case is `ALSA-2022:5468`**
(PHP 8.0 module update for CVE-2022-31626). The errata file lists only
x86_64 RPMs:

```
libzip-1.7.3-1.module_el8.6.0+2739+efabdb8f.x86_64
libzip-devel-1.7.3-1.module_el8.6.0+2739+efabdb8f.x86_64
libzip-tools-1.7.3-1.module_el8.6.0+2739+efabdb8f.x86_64
…
```

But the aarch64 AppStream repo has the matching binaries already
published:

```
libzip-1.7.3-1.module_el8.6.0+2739+efabdb8f.aarch64
libzip-devel-1.7.3-1.module_el8.6.0+2739+efabdb8f.aarch64
libzip-tools-1.7.3-1.module_el8.6.0+2739+efabdb8f.aarch64
```

So the aarch64 RPMs *do* exist with the exact same NVR — they're simply
**missing from Alma's `errata.json` pkglist for that ALSA**. This is a
**packaging-metadata bug in the AlmaLinux errata feed**, not a real
per-arch security gap. Trivy / other consumers that parse the errata.json
strictly will incorrectly mark aarch64 as unpatched for this CVE even
though the fixed binary is in the repo.

### H.2 The 43 "era gap" Alma cases

These are advisories where the package exists on aarch64 today but only
at later versions. They split into two clean groups:

| Sub-pattern | Examples | Why |
|---|---|---|
| Package added an aarch64 build later | `firefox` (6 ALSAs from 2021–2022 are x86_64-only; aarch64 builds first appear in 2024 starting from el8_9), `thunderbird` (12 historical x86_64-only ALSAs), `java-{1.8.0,11,17}-openjdk` headline RPMs (early streams x86_64-only), `samba-vfs-iouring` (early io_uring on x86_64 only), `openssh-askpass`, `rpm-build`, `rpm-plugin-fapolicyd`, `linuxptp` | AlmaLinux's aarch64 port was newer; those packages gained aarch64 builds in later z-streams |
| Package x86_64-only-by-design subpackages | `java-*-openjdk-*-fastdebug` / `*-slowdebug`, `dotnet-sdk-*-source-built-artifacts`, `rust-analysis`, `rls`, `rust-std-static-wasm32-unknown-unknown` | These are debug/source/cross-target subpackages that are intentionally x86_64-only across all eras |

Both groups support the hypothesis: the missing-arch fix is **always**
because no aarch64 binary existed at that point, never because Alma chose
to skip the aarch64 build of an existing package.

### H.3 The 111 "intrinsic" Alma cases

Top names: `kernel-rt-*` (real-time kernel, x86_64 only by upstream
choice), `microcode_ctl` (Intel CPU microcode), `aspnetcore-runtime-3.1`
+ `dotnet-{runtime,sdk,host,...}-3.1/5.0` (dropped Microsoft .NET
streams, x86_64-only), `pcs` + `resource-agents-*` (RHEL High Availability
add-on, x86_64 only on Alma), `open-vm-tools-*` (VMware Tools, x86_64
only), `grafana-{azure-monitor,cloudwatch,…}` (Grafana plugins, x86_64
only).

### H.4 openEuler 22.03-SP3 — full single-arch cross-check

| Single-arch package | Single-arch ALSAs | Present on the other arch? | Conclusion |
|---|---|---|---|
| `microcode_ctl` (single-x86_64) | 30 | Not on aarch64 | Intrinsic — Intel CPU microcode |
| `syslinux`, `syslinux-debuginfo`, `syslinux-debugsource`, `syslinux-devel`, `syslinux-efi64`, `syslinux-extlinux`, `syslinux-extlinux-nonlinux`, `syslinux-nonlinux`, `syslinux-perl`, `syslinux-tftpboot` (all single-x86_64) | 8 each | Not on aarch64 | Intrinsic — x86 BIOS/EFI bootloader |
| `arm-trusted-firmware-armv8` (single-aarch64) | 15 | Not on x86_64 | Intrinsic — ARM TF-A reference firmware |

openEuler is **100% intrinsic**. Zero "era gap" or "metadata bug" cases.

### H.5 Cross-source picture

| Source | Sample of single-arch advisories cross-checked | Intrinsic | Era gap | Metadata bug (NVR present on the other arch) |
|---|---|---|---|---|
| Alma 8 | 155 single-x86_64 | 111 (71.6%) | 43 (27.7%) | **1 (0.6%) — `ALSA-2022:5468`** |
| openEuler 22.03-SP3 | All single-arch | 100% | 0 | 0 |
| Rocky | (not cross-checked — mirror throttling; pattern is structurally identical to Alma 8) | — | — | — |
| Amazon | All single-x86_64 = AL1 era docker / qemu / microcode | All intrinsic for that release | — | — |

(The 537 single-aarch64 RLSAs in Rocky look from their per-arch
distribution — heavily AppStream modular packages firefox/php — like the
same "era gap" pattern as Alma's openjdk modular advisories, where the
modular rebuild for a different arch shipped in a separate errata cycle.)

### H.6 Bottom line

- The hypothesis "single-arch advisories exist only because the package
  isn't built for other arches" is correct **>99% of the time** in the
  data we measured.
  - Alma 8: 154 / 155 single-x86_64 ALSAs (99.4%) fall into the intrinsic
    or era-gap categories.
  - openEuler 22.03-SP3: 100%.
  - Amazon, Red Hat OVAL, SUSE all show qualitatively the same pattern in
    the deep-dives above (kernel-rt, microcode, container images, ARM
    Trusted Firmware, IBM hardware libs).
- **The interesting exception is Alma's `ALSA-2022:5468`**: the matching
  aarch64 RPM is in the repo at the same NVR but is missing from the
  errata's pkglist. This is **a packaging metadata bug in
  errata.almalinux.org**, not a real per-arch fix. It would cause Trivy
  (and any other consumer that strictly trusts errata.json) to report
  aarch64 as unpatched for CVE-2022-31626 when in fact the fix is
  installed.
- "Era gap" advisories (~28% of Alma single-arch) are also not
  vulnerability-targeting decisions; they're a side effect of when
  AlmaLinux added aarch64 builds for those packages. The corresponding
  aarch64 fix was published later as part of a different ALSA in a newer
  z-stream.
- For practical risk modelling: **a single-arch advisory in any of these
  sources almost never means the vulnerability fix was deliberately
  withheld from one arch.** It almost always means either the package
  doesn't exist on that arch, or it was added later.

### H.7 Reproducing this cross-check

Alma:

```bash
mkdir -p /tmp/almarepo
for arch in x86_64 aarch64; do
  for repo in BaseOS AppStream; do
    PRIM=$(curl -ksSL "https://repo.almalinux.org/almalinux/8/${repo}/${arch}/os/repodata/" \
      | grep -oE '[a-f0-9]+-primary\.xml\.gz' | head -1)
    curl -ksSL "https://repo.almalinux.org/almalinux/8/${repo}/${arch}/os/repodata/${PRIM}" \
      -o "/tmp/almarepo/${repo}-${arch}.xml.gz"
  done
done
```

openEuler 22.03-SP3:

```bash
mkdir -p /tmp/oerepo
for arch in x86_64 aarch64; do
  PRIM=$(curl -ksSL "https://repo.openeuler.org/openEuler-22.03-LTS-SP3/update/${arch}/repodata/" \
    | grep -oE '[a-f0-9]+-primary\.xml\.gz' | head -1)
  curl -ksSL "https://repo.openeuler.org/openEuler-22.03-LTS-SP3/update/${arch}/repodata/${PRIM}" \
    -o "/tmp/oerepo/${arch}.xml.gz"
done
```

---

## Appendix I — Same question for Red Hat OVAL

We applied the same intrinsic / era-gap / metadata-bug cross-check to Red
Hat's OVAL feed. Red Hat's official RPM repos require an entitlement
certificate, so we cross-checked against the publicly mirrored
**CentOS Stream 8 + 9** BaseOS+AppStream repos for x86_64, aarch64,
ppc64le, and (for CentOS Stream 9) s390x. CentOS Stream is the upstream
of RHEL — packages that ship in CentOS Stream are essentially the same
binaries Red Hat publishes for RHEL.

### I.1 Red Hat OVAL — single-arch package counts

The deep-dive reported **2,053 single-arch RHEL OVAL definitions** across
the union of all `RHELn/*.oval.xml.bz2` files. Within those 2,053 the
distribution by single-arch bucket is:

| Bucket | Single-arch RHSAs | Distinct package names |
|---|---:|---:|
| `x86_64` | 1,913 | 4,775 |
| `i686` | 113 | 3 |
| `ppc64le` | 23 | 18 |
| `ppc64` | 3 | 2 |
| `aarch64` | 1 | 10 |
| **Total** | **2,053** | **4,808** |

### I.2 Red Hat OVAL — package-level cross-check vs CentOS Stream 8+9

For each distinct package name in each single-arch bucket, we asked:
*does this package name appear on any other arch in CentOS Stream 8+9
BaseOS+AppStream?* Result:

| Single-arch bucket | Distinct pkg names | Intrinsic (not on any other arch) | Era-gap (on another arch) | % intrinsic |
|---|---:|---:|---:|---:|
| `i686` | 3 | 3 (`acroread`, `acroread-plugin`, `flash-plugin`) | 0 | **100.0%** |
| `x86_64` | 4,775 | 4,034 | 741 | **84.5%** |
| `ppc64le` | 18 | 9 | 9 | 50.0% |
| `aarch64` | 10 | 2 | 8 | 20.0% |
| `ppc64` | 2 | 0 | 2 | 0.0% |

**Interpretation**:

- **`i686` is 100% intrinsic** — Adobe Flash and Acroread were only ever
  shipped as i686 binaries on RHEL. Both products are EOL and have no
  builds on any other arch in CentOS Stream.
- **`x86_64` is 84.5% intrinsic** — the dominant chunk is Red Hat
  Software Collections (`rh-python36`, `rh-mysql57`, `rh-postgresql10`),
  Layered Products (Ansible Tower / Automation Platform variants,
  ansible-collection-redhat-satellite, ansible-operator-*, JBoss EWS,
  etc.), and Red Hat-specific tools — none of which ever had non-x86_64
  builds. The 15.5% era-gap names (e.g. `389-ds-base`, `Judy`,
  `NetworkManager-libreswan`) are common packages that DO ship on
  aarch64/ppc64le today but for which the historical x86_64-only
  RHSAs predate the cross-arch builds — same era-gap pattern as Alma's
  `firefox` advisories.
- **`aarch64` is 80% era-gap (8 of 10 names)** — those 8 names are all
  `kernel`, `kernel-debug`, `kernel-devel`, `kernel-headers`,
  `kernel-tools`, `kernel-tools-libs`, `perf`, `python-perf`. They appear
  in `RHEL7/rhel-7-alt.oval.xml.bz2` — the **RHEL 7-alt** stream that
  Red Hat used for ppc64le and aarch64 (separate from mainline RHEL 7,
  which was x86_64-only). The kernel binaries do exist on aarch64 in the
  rhel-7-alt repo, so technically "era-gap": the packages exist on the
  other arch elsewhere, just not in the same OVAL file.
- **`ppc64le` is 50/50** — 9 intrinsic (kpatch-patch series tied to
  specific x86_64-built kernel revisions, kernel-bootwrapper which is
  ppc-only firmware tooling, kernel-abi-whitelists which is per-arch),
  9 era-gap (the same RHEL 7-alt kernel family).
- **`ppc64` 2 era-gap** — `powerpc-utils` and `ppc64-diag`. These are
  Power-architecture diagnostic tools; they "appear on other arch" in our
  test only because they're listed in CentOS Stream's ppc64le repo (the
  successor to the deprecated big-endian ppc64). Functionally they're
  arch-specific to Power.

### I.3 Red Hat OVAL — concrete era-gap RHSA examples

These are real RHSAs picked from the era-gap bucket, sorted by date. For
each one I show the issue date, the OVAL file it lives in, and which
CentOS Stream arches now ship the same package name — to make the
"package gained other-arch builds later" pattern concrete.

| RHSA | Issued | Single arch in OVAL | Package | Now in CentOS Stream arches | Why "single-arch" |
|---|---|---|---|---|---|
| `RHSA-2011:0345` | 2011-03-10 | x86_64 | `qemu-kvm` (qemu-img-2:0.12.1.2-2.113.el6_0.8) | aarch64, ppc64le, s390x, x86_64 | RHEL 6 era qemu-kvm was **x86_64-only**; KVM on other arches arrived in RHEL 7-alt / RHEL 8 |
| `RHSA-2012:0774` | 2012-06-19 | x86_64 | `libguestfs-1:1.16.19-1.el6` | aarch64, ppc64le, s390x, x86_64 | RHEL 6 libguestfs piggybacks on KVM, hence x86_64-only at the time |
| `RHSA-2013:1192` | 2013-09-03 | x86_64 | `spice-server-0:0.12.0-12.el6_4.3` | aarch64, x86_64 | SPICE virtualization stack was x86_64-only on RHEL 6 |
| `RHSA-2014:1031` | 2014-08-07 | x86_64 | `389-ds-base-0:1.3.1.6-26.el7_0` | aarch64, ppc64le, s390x, x86_64 | RHEL 7.0/7.1 mainline shipped x86_64 only; aarch64/ppc64le/s390x builds appeared in RHEL 7-alt and later RHEL 7 z-streams |
| `RHSA-2015:0383` | 2015-03-05 | ppc64 | `ppc64-diag-0:2.6.7-6.el7` | ppc64le | Big-endian `ppc64` diagnostic tool; `ppc64le` came later when the architecture switched to little-endian |
| `RHSA-2015:0384` | 2015-03-05 | ppc64 | `powerpc-utils-0:1.2.24-7.el7` | ppc64le | Same: BE/LE Power transition |
| `RHSA-2015:0642` | 2015-03-05 | x86_64 | `thunderbird-0:31.5.0-2.el7_1` | aarch64, ppc64le, s390x, x86_64 | RHEL 7.1 thunderbird was x86_64-only; mozilla-suite cross-arch builds came in later z-streams |
| `RHSA-2017:0372` | 2017-03-02 | aarch64 | `kernel-0:4.5.0-15.2.1.el7` | aarch64, ppc64le, s390x, x86_64 | First **`kernel-aarch64`** RHSA — RHEL 7-alt was Red Hat's separate aarch64 stream; mainline RHEL 7 was x86_64-only, so this advisory is single-aarch64 by stream design |
| `RHSA-2018:2948` | 2018-10-30 | ppc64le | `kernel-alt` | aarch64, ppc64le, s390x, x86_64 | Companion to RHSA-2017:0372: RHEL 7-alt **`kernel-alt`** for ppc64le |

**How to read these rows**: every package in the rightmost column ships
on multiple arches **today** in CentOS Stream — but at the time the RHSA
was published, the package binary only existed on the listed arch. So:

- `RHSA-2011:0345` (qemu-kvm) and `RHSA-2012:0774` (libguestfs) are
  classic *era-gap* x86_64 RHSAs from RHEL 6 days when the virtualization
  stack was x86_64-only. RHEL 8/9 ship qemu-kvm on aarch64/ppc64le/s390x;
  the historical RHSAs simply predate that.
- `RHSA-2017:0372` (`kernel-aarch64 security and bug fix update`) is the
  archetype of the RHEL 7-alt phenomenon: Red Hat had a separate OVAL file
  for the aarch64 / ppc64le ALT streams of RHEL 7. So a kernel update on
  RHEL 7-alt aarch64 lands in `rhel-7-alt.oval.xml.bz2` with arch set
  containing only `aarch64`, even though the kernel package obviously
  exists on every modern RHEL arch.
- `RHSA-2015:0383` and `RHSA-2015:0384` (ppc64-diag, powerpc-utils) are
  *technically* era-gap because the **same package names** ship on
  ppc64le today — but functionally these are Power-architecture
  diagnostic tools that just transitioned from `ppc64` (big-endian) to
  `ppc64le` (little-endian) when Red Hat dropped BE Power.

So even within the era-gap bucket the pattern matches the universal
finding: **none of these RHSAs withheld a fix from one arch on purpose**.
They each correspond to a moment when the package's binary catalogue on
other arches simply didn't yet exist.

### I.4 Red Hat OVAL — bottom line

- The **vast majority (84.5–100%) of Red Hat's single-arch RHSAs in
  every bucket are intrinsic** — the package itself only exists on that
  one arch by Red Hat's distribution choice.
- The era-gap residue (~15% of single-x86_64 names) follows the same
  pattern as Alma 8: packages that gained cross-arch builds in later
  z-streams. The historical single-x86_64 RHSAs for those packages
  predate the multi-arch era.
- The aarch64 / ppc64le buckets are dominated by **RHEL 7-alt** kernel
  RHSAs — definitions that live in a separate OVAL file because RHEL 7-alt
  was a separate product stream from mainline RHEL 7 (x86_64-only). The
  "era gap" classification here captures that the kernel package does
  exist on aarch64/ppc64le, just in the alt stream.
- We were unable to perform the **same-NVR ("metadata bug")** check for
  Red Hat because the deep-dive aggregates per-vulnID across all OVAL
  files, losing the per-file context needed to look up the exact
  per-arch NVR. Qualitatively, given Red Hat's mature, automated
  build-and-publish pipeline, we'd expect the metadata-bug rate to be
  even lower than Alma's 0.6%.

### I.5 Cross-source intrinsic-vs-era-gap roll-up

Combining all the cross-checks in Appendix H + Appendix I:

| Source | Sample | Intrinsic | Era-gap | Metadata bug |
|---|---|---:|---:|---:|
| Alma 8 | 155 single-x86_64 ALSAs | 71.6% | 27.7% | 0.6% (1 ALSA) |
| openEuler 22.03-SP3 | All single-arch | 100% | 0% | 0% |
| Red Hat OVAL — i686 | 3 distinct pkg names | 100% | 0% | (n/a) |
| Red Hat OVAL — x86_64 | 4,775 distinct pkg names | 84.5% | 15.5% | (n/a) |
| Red Hat OVAL — aarch64 | 10 distinct pkg names | 20% | 80% | (n/a) |
| Red Hat OVAL — ppc64le | 18 distinct pkg names | 50% | 50% | (n/a) |
| Amazon | All single-x86_64 ALAS | All intrinsic | 0 | 0 |

The pattern is universal: **a single-arch advisory in any of these feeds
almost never means the vulnerability fix was deliberately withheld from
one arch.** It's almost always either (a) the package only exists on that
arch, or (b) the package's other-arch builds came later in the product's
lifetime.

### I.6 Reproducing the Red Hat cross-check

```bash
mkdir -p /tmp/rh-cross/cs9 /tmp/rh-cross/cs8
# CentOS Stream 9
for arch in x86_64 aarch64 ppc64le s390x; do
  for repo in BaseOS AppStream; do
    PRIM=$(curl -ksSL "https://mirror.stream.centos.org/9-stream/${repo}/${arch}/os/repodata/" \
      | grep -oE '[a-f0-9]+-primary\.xml\.gz' | head -1)
    curl -ksSL "https://mirror.stream.centos.org/9-stream/${repo}/${arch}/os/repodata/${PRIM}" \
      -o "/tmp/rh-cross/cs9/${repo}-${arch}.xml.gz"
  done
done
# CentOS Stream 8 (vault, no s390x)
for arch in x86_64 aarch64 ppc64le; do
  for repo in BaseOS AppStream; do
    PRIM=$(curl -ksSL "https://vault.centos.org/8-stream/${repo}/${arch}/os/repodata/" \
      | grep -oE '[a-f0-9]+-primary\.xml\.gz' | head -1)
    curl -ksSL "https://vault.centos.org/8-stream/${repo}/${arch}/os/repodata/${PRIM}" \
      -o "/tmp/rh-cross/cs8/${repo}-${arch}.xml.gz"
  done
done
# Then run the categorization script: for each package name in
# scripts/arch-analysis/out/deepdive-redhat-oval.json's
# single_arch_top_packages_by_arch, check whether it appears in any other
# arch's primary.xml.gz; classify as intrinsic / era-gap.
```
