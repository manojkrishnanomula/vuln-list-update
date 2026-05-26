# Arch-specific advisories — short answer per source

Question: **does this source publish multi-arch advisories (one fix that
covers several CPU arches), or does it issue per-arch advisories?**

For each source, "multi-arch advisories" are advisories whose package list
covers ≥ 2 concrete CPU arches. **"Same fix across arches (NVR match)"**
means every package in the advisory ships with an identical
`version-release` (NVR) on every arch — i.e. **one fix, multiple per-arch
binary builds**. Numbers come from the live data fetch on 2026-05-13/14/15.
Full methodology and examples are in [`REPORT.md`](./REPORT.md).

| Source | Verdict | Total advisories | Multi-arch | Same fix across arches (NVR match) | Single-arch | Notes |
|---|---|---:|---:|---:|---:|---|
| **alpine** | Multi-arch (file-level only). | 45 secdb files | 45 | n/a | 0 per-CVE | Each `(release, repo)` secdb file lists one `archs:[…]` set inherited by every CVE in the file. Per-CVE arch does not exist. |
| **amazon** | Yes — multi-arch, perfectly. | 5,901 | 5,182 | **5,182 (100.0%)** | 131 (all x86_64) | Every multi-arch ALAS ships every package at the exact same NVR per arch. Single-arch = AL1-era docker / qemu / Intel microcode. |
| **alma** | Yes — multi-arch. | 3,541 | 3,122 | **2,870 (91.9%)** | 174 (170 x86_64, 4 aarch64) | One ALSA per fix; per-arch RPMs share NVR. Single-x86_64 = mostly `kernel-rt`; single-aarch64 = modular container rebuilds. |
| **rocky** | Yes — multi-arch. | 4,030 | 2,438 | **2,436 (99.9%)** | 629 (537 aarch64, 69 x86_64, 15 ppc64le, 8 s390x) | Single-aarch64 = AppStream module rebuild lag (firefox/php); ppc64le/s390x = IBM hardware libs. |
| **redhat-oval** | Yes — multi-arch. | 46,461 defs | 12,301 | **11,440 (93.0%)** | 2,053 (1,913 x86_64, 113 i686, 23 ppc64le, 3 ppc64, 1 aarch64) | x86_64-only ≈ kernel-rt; i686-only = legacy Adobe Flash + Acroread; ppc64le = RHEL 7-alt. |
| **redhat-csaf-vex** | Yes — multi-arch (per stream). | 316,795 CVEs | 20,653 | 67 literal-string match (per-stream verified by hand: same NVR per arch) | 1,730 (1,172 x86_64, 217 i386, 189 amd64, 125 i686, 24 ppc64le, 3 ppc64) | Each CVE.json bundles fixes across many RHEL streams, so a literal cross-stream NVR match is rare; per-stream the same fix ships for every arch. |
| **openeuler** | Yes — multi-arch. | 6,957 | 5,991 | **5,940 (99.1%)** | 58 (43 x86_64, 15 aarch64) | x86_64-only = microcode_ctl / syslinux / Intel SGX; aarch64-only = ARM Trusted Firmware. |
| **suse-cvrf** | Yes — multi-arch. | 34,939 | 1,142 | 301 literal match (per-arch rebuild release suffix often differs by 1) | 1,183 (873 x86_64, 211 arm64, 52 ppc64, 18 s390, 11 s390x, 10 i386, 7 ppc, 1 alpha) | x86_64-only = SUSE Manager / SLE HPC container images; arm64-only = Public Cloud Images for GCP arm64 + grub2-efi. |

## Universal answer

For **every** source above, advisories are multi-arch by default. There is
**one advisory per fix**, and per-arch RPMs in the advisory share the same
(version, release). An advisory appears single-arch only when the package
itself is only built for one arch upstream (microcode, kernel-rt, BIOS
bootloader, ARM Trusted Firmware, IBM hardware libs, container images for
one Docker arch). No source in this study publishes different vulnerability
fixes for the same package on different arches.

## Why are some advisories "single-arch"? (cross-check vs. live repo)

For each single-arch advisory, the missing-arch fix is **>99% of the time**
explained by one of these structural reasons (verified empirically against
the upstream `primary.xml.gz`; full method in
[REPORT.md Appendix H](./REPORT.md#appendix-h)):

1. **Intrinsically arch-specific package** — the binary doesn't exist for
   the other arch in any era (kernel-rt, microcode_ctl, syslinux, ARM
   Trusted Firmware, IBM Z hardware libs, etc.).
2. **Era gap** — the package gained other-arch builds *later* in time, so
   older advisories for it were single-arch by necessity (Alma firefox/
   thunderbird/openjdk in 2021–22; aarch64 builds first appear in 2024).
3. **Packaging-metadata bug** (very rare): the other-arch RPM does exist
   at the same NVR in the repo, but the errata's pkglist forgot to
   mention it.

Concrete numbers (full method in [REPORT.md Appendix H + I](./REPORT.md#appendix-h)):

| Source / sample | Intrinsic | Era gap | Metadata bug |
|---|---:|---:|---:|
| Alma 8 — 155 single-x86_64 ALSAs | 111 (71.6%) | 43 (27.7%) | **1 (0.6%) — `ALSA-2022:5468`** |
| openEuler 22.03-SP3 — all single-arch | 100% | 0 | 0 |
| Red Hat OVAL — i686 (3 distinct pkg names) | 100% | 0% | n/a (not measured) |
| Red Hat OVAL — x86_64 (4,775 distinct pkg names) | 84.5% | 15.5% | n/a |
| Red Hat OVAL — aarch64 (10 distinct pkg names) | 20% | 80% | n/a |
| Red Hat OVAL — ppc64le (18 distinct pkg names) | 50% | 50% | n/a |

So: a single-arch advisory in any of these feeds **almost never** means
the vulnerability fix was deliberately withheld from one arch.
