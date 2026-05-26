// Deep-dive helper that answers the question: "for a given source, are
// per-arch RPMs in the same advisory the same NVR (i.e. one fix shipped as
// multiple per-arch binaries), or are there genuinely different advisories
// for the same package on different arches?" It also reports which packages
// dominate single-arch buckets so we can explain why those buckets exist.
//
// Run with:
//
//	go run ./scripts/arch-analysis -deepdive redhat-oval,redhat-csaf-vex,suse-cvrf
//
// Output is a JSON document under out/deepdive-<source>.json plus a human-
// readable summary on stdout. This is separate from -only (statistics) and
// -examples (per-bucket sample IDs).
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"

	almatypes "github.com/aquasecurity/vuln-list-update/alma"
	amazontypes "github.com/aquasecurity/vuln-list-update/amazon"
	openeulertypes "github.com/aquasecurity/vuln-list-update/openeuler"
	rhovaltypes "github.com/aquasecurity/vuln-list-update/redhat/oval"
	rockytypes "github.com/aquasecurity/vuln-list-update/rocky"
	susetypes "github.com/aquasecurity/vuln-list-update/suse/cvrf"
)

// DeepDive is the per-source result.
type DeepDive struct {
	Source                  string         `json:"source"`
	Notes                   string         `json:"notes,omitempty"`
	TotalAdvisories         int            `json:"total_advisories"`
	MultiArchAdvisories     int            `json:"multi_arch_advisories"`
	MultiArchSameNVR        int            `json:"multi_arch_same_nvr,omitempty"`
	MultiArchDiffNVR        int            `json:"multi_arch_diff_nvr,omitempty"`
	NVRDiffExamples         []string       `json:"nvr_diff_examples,omitempty"`
	SingleArchAdvisories    int            `json:"single_arch_advisories"`
	SingleArchByArch        map[string]int `json:"single_arch_by_arch,omitempty"`
	SingleArchTopPackages   map[string][]string `json:"single_arch_top_packages,omitempty"`
	SingleArchTopByArch     map[string]map[string]int `json:"single_arch_top_packages_by_arch,omitempty"`
}

func runDeepDive(sources []string) {
	if len(sources) == 1 && sources[0] == "all" {
		sources = []string{
			"alma", "amazon", "openeuler", "rocky",
			"redhat-oval", "redhat-csaf-vex", "suse-cvrf",
		}
	}
	for _, s := range sources {
		var dd *DeepDive
		switch s {
		case "alma":
			dd = deepDiveAlma()
		case "amazon":
			dd = deepDiveAmazon()
		case "openeuler":
			dd = deepDiveOpenEuler()
		case "rocky":
			dd = deepDiveRocky()
		case "redhat-oval", "rhoval":
			dd = deepDiveRHOVAL()
		case "redhat-csaf-vex", "rhvex":
			dd = deepDiveRHCSAFVEX()
		case "suse", "suse-cvrf":
			dd = deepDiveSUSECVRF()
		default:
			log.Printf("deepdive: unknown source %q", s)
			continue
		}
		_ = os.MkdirAll("scripts/arch-analysis/out", 0o755)
		body, _ := json.MarshalIndent(dd, "", "  ")
		f, _ := os.Create(filepath.Join("scripts/arch-analysis/out", "deepdive-"+dd.Source+".json"))
		_, _ = f.Write(body)
		_, _ = f.Write([]byte("\n"))
		f.Close()
		fmt.Println(string(body))
	}
}

// ---------------- helpers ----------------

func topN(c map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	a := make([]kv, 0, len(c))
	for k, v := range c {
		a = append(a, kv{k, v})
	}
	sort.Slice(a, func(i, j int) bool {
		if a[i].v != a[j].v {
			return a[i].v > a[j].v
		}
		return a[i].k < a[j].k
	})
	if len(a) > n {
		a = a[:n]
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, fmt.Sprintf("%dx %s", x.v, x.k))
	}
	return out
}

func archSetIsConcreteSingle(set map[string]struct{}) (string, bool) {
	concrete := map[string]struct{}{}
	for a := range set {
		if a == "" || a == "noarch" || a == "src" {
			continue
		}
		concrete[a] = struct{}{}
	}
	if len(concrete) != 1 {
		return "", false
	}
	for a := range concrete {
		return a, true
	}
	return "", false
}

// ---------------- REDHAT OVAL ----------------
//
// We re-walk the OVAL bz2 manifest, but this time record per-definition:
//   - the arch set (from RpminfoState.Arch.Text union)
//   - the package names referenced (from RpminfoTest -> RpminfoObject.Name)
// For "multi_arch_same_nvr" Red Hat OVAL doesn't ship per-arch NVR per
// state directly (Evr is a single string); we approximate by grouping by
// (definition, package_name) and checking that each (def, pkg) has a single
// Evr value across its referenced states. If yes -> same NVR; otherwise
// flag as differing NVR.
func deepDiveRHOVAL() *DeepDive {
	base := "https://security.access.redhat.com/data/oval/v2/"
	manifest, err := getBytes(base + "PULP_MANIFEST")
	if err != nil {
		return &DeepDive{Source: "redhat-oval", Notes: "manifest fetch failed"}
	}
	var files []string
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ",")
		if len(parts) < 3 || parts[2] == "0" {
			continue
		}
		if !strings.HasPrefix(parts[0], "RHEL") || !strings.HasSuffix(parts[0], ".oval.xml.bz2") {
			continue
		}
		files = append(files, parts[0])
	}
	log.Printf("[deepdive rhoval] %d files", len(files))

	type advAccum struct {
		archs    map[string]struct{}
		pkgs     map[string]struct{} // package names referenced
		pkgEvr   map[string]map[string]struct{} // pkg -> set of Evr values seen
	}
	advs := map[string]*advAccum{}
	var mu sync.Mutex
	bg := newBoundedGroup(8)
	for _, f := range files {
		f := f
		bg.Go(func() error {
			b, err := getBytes(base + f)
			if err != nil {
				return nil
			}
			r := bzip2.NewReader(bytes.NewReader(b))
			var ov rhovaltypes.OvalDefinitions
			if err := xml.NewDecoder(r).Decode(&ov); err != nil {
				return nil
			}
			stateArch := map[string]string{}
			stateEvr := map[string]string{}
			for _, st := range ov.States.RpminfoState {
				if st.Arch.Text != "" {
					stateArch[st.ID] = st.Arch.Text
				}
				if st.Evr.Text != "" {
					stateEvr[st.ID] = st.Evr.Text
				}
			}
			testState := map[string]string{}
			testObj := map[string]string{}
			for _, t := range ov.Tests.RpminfoTests {
				if t.State.StateRef != "" {
					testState[t.ID] = t.State.StateRef
				}
				if t.Object.ObjectRef != "" {
					testObj[t.ID] = t.Object.ObjectRef
				}
			}
			objName := map[string]string{}
			for _, o := range ov.Objects.RpminfoObjects {
				objName[o.ID] = o.Name
			}
			for _, d := range ov.Definitions.Definition {
				if len(d.Metadata.References) == 0 {
					continue
				}
				vulnID := d.Metadata.References[0].RefID
				for _, ref := range d.Metadata.References {
					if strings.HasPrefix(ref.RefID, "RHSA-") {
						vulnID = ref.RefID
					}
				}
				archSet := map[string]struct{}{}
				pkgs := map[string]struct{}{}
				pkgEvr := map[string]map[string]struct{}{}
				var walk func(c rhovaltypes.Criteria)
				walk = func(c rhovaltypes.Criteria) {
					for _, cr := range c.Criterions {
						sid := testState[cr.TestRef]
						pat := stateArch[sid]
						for _, p := range strings.Split(pat, "|") {
							p = strings.TrimSpace(p)
							if p != "" {
								archSet[p] = struct{}{}
							}
						}
						oid := testObj[cr.TestRef]
						if name, ok := objName[oid]; ok && name != "" {
							pkgs[name] = struct{}{}
							evr := stateEvr[sid]
							if evr != "" {
								if _, ok := pkgEvr[name]; !ok {
									pkgEvr[name] = map[string]struct{}{}
								}
								pkgEvr[name][evr] = struct{}{}
							}
						}
					}
					for _, child := range c.Criterias {
						walk(child)
					}
				}
				walk(d.Criteria)
				mu.Lock()
				acc, ok := advs[vulnID]
				if !ok {
					acc = &advAccum{
						archs:  map[string]struct{}{},
						pkgs:   map[string]struct{}{},
						pkgEvr: map[string]map[string]struct{}{},
					}
					advs[vulnID] = acc
				}
				for a := range archSet {
					acc.archs[a] = struct{}{}
				}
				for p := range pkgs {
					acc.pkgs[p] = struct{}{}
				}
				for p, evrs := range pkgEvr {
					if _, ok := acc.pkgEvr[p]; !ok {
						acc.pkgEvr[p] = map[string]struct{}{}
					}
					for e := range evrs {
						acc.pkgEvr[p][e] = struct{}{}
					}
				}
				mu.Unlock()
			}
			return nil
		})
	}
	bg.Wait()

	dd := &DeepDive{
		Source: "redhat-oval",
		Notes: "Multi-arch test: for each (advisory, package), checks that all referenced RpminfoState.Evr values are identical. " +
			"Single-arch buckets are decided on the union arch set across all RpminfoStates the definition references.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for _, acc := range advs {
		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range acc.archs {
			if a == "noarch" || a == "src" || a == "" {
				continue
			}
			concrete[a] = struct{}{}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			same := true
			for _, evrs := range acc.pkgEvr {
				if len(evrs) > 1 {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
				if len(dd.NVRDiffExamples) < 5 {
					var pkg string
					var evrs []string
					for p, vs := range acc.pkgEvr {
						if len(vs) > 1 {
							pkg = p
							for v := range vs {
								evrs = append(evrs, v)
							}
							break
						}
					}
					sort.Strings(evrs)
					dd.NVRDiffExamples = append(dd.NVRDiffExamples,
						fmt.Sprintf("pkg %q has %d Evr values: %v", pkg, len(evrs), evrs))
				}
			}
		}
		if a, ok := archSetIsConcreteSingle(acc.archs); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for p := range acc.pkgs {
				dd.SingleArchTopByArch[a][p]++
				allSinglePkgs[p]++
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// ---------------- REDHAT CSAF VEX ----------------
//
// Each VEX advisory's product_tree carries product_versions whose names
// look like "<pkgname>-<epoch>:<version>-<release>.<arch>". We parse the
// arch suffix from the leaf branch name, group package_versions by
// "<pkgname>-<epoch>:<version>-<release>" (NVR), and check whether the
// same NVR is published for every concrete arch in the advisory.
func deepDiveRHCSAFVEX() *DeepDive {
	base := "https://security.access.redhat.com/data/csaf/v2/vex/"
	nameB, err := getBytes(base + "archive_latest.txt")
	if err != nil {
		return &DeepDive{Source: "redhat-csaf-vex", Notes: "archive name fetch failed"}
	}
	name := strings.TrimSpace(string(nameB))
	log.Printf("[deepdive rhvex] downloading %s", name)
	body, err := getBytes(base + name)
	if err != nil {
		return &DeepDive{Source: "redhat-csaf-vex", Notes: "archive fetch failed"}
	}
	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return &DeepDive{Source: "redhat-csaf-vex", Notes: "zstd reader failed"}
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	purlArchRe := regexp.MustCompile(`[?&]arch=([^&]+)`)
	// Pattern at end of leaf branch name like "...-1.el9_0.x86_64"
	leafArchRe := regexp.MustCompile(`\.([a-z0-9_]+)$`)

	dd := &DeepDive{
		Source: "redhat-csaf-vex",
		Notes: "Multi-arch test: leaf product_version names look like '<name>-<epoch>:<v>-<r>.<arch>'. " +
			"We strip the trailing '.<arch>' and check that every concrete arch in the advisory has a leaf with " +
			"the same NVR prefix. Single-arch top packages are derived from the leaf names.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	var n int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			continue
		}
		var doc struct {
			Document struct {
				Tracking struct {
					ID string `json:"id"`
				} `json:"tracking"`
			} `json:"document"`
			ProductTree struct {
				Branches []branch `json:"branches"`
			} `json:"product_tree"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			continue
		}
		archSet := map[string]struct{}{}
		// nvr -> set of arches that ship it (purely from leaf branch names)
		nvrArchs := map[string]map[string]struct{}{}
		// per-arch: set of base package names (leaf name with arch trimmed and version stripped)
		pkgsByArch := map[string]map[string]struct{}{}
		var walk func(brs []branch, parentArch string)
		walk = func(brs []branch, parentArch string) {
			for _, b := range brs {
				localArch := parentArch
				if b.Category == "architecture" && b.Name != "" && isKnownArch(b.Name) {
					localArch = b.Name
					archSet[localArch] = struct{}{}
				}
				if b.Product != nil && b.Product.ProductIdentificationHelper != nil {
					h := b.Product.ProductIdentificationHelper
					var leafArch string
					if m := purlArchRe.FindStringSubmatch(h.Purl); len(m) == 2 && isKnownArch(m[1]) {
						leafArch = m[1]
					}
					if leafArch == "" {
						if m := leafArchRe.FindStringSubmatch(b.Name); len(m) == 2 && isKnownArch(m[1]) {
							leafArch = m[1]
						}
					}
					if leafArch == "" {
						leafArch = localArch
					}
					if leafArch != "" {
						archSet[leafArch] = struct{}{}
						// Strip trailing .<arch> from name to get NVR string
						nvr := strings.TrimSuffix(b.Name, "."+leafArch)
						if _, ok := nvrArchs[nvr]; !ok {
							nvrArchs[nvr] = map[string]struct{}{}
						}
						nvrArchs[nvr][leafArch] = struct{}{}
						if _, ok := pkgsByArch[leafArch]; !ok {
							pkgsByArch[leafArch] = map[string]struct{}{}
						}
						// Best-effort base package name = NVR up to first '-NUM' boundary
						base := nvr
						if i := strings.Index(base, "-"); i > 0 {
							base = base[:i]
						}
						pkgsByArch[leafArch][base] = struct{}{}
					}
				}
				if len(b.Branches) > 0 {
					walk(b.Branches, localArch)
				}
			}
		}
		walk(doc.ProductTree.Branches, "")

		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range archSet {
			if a == "noarch" || a == "src" {
				continue
			}
			concrete[a] = struct{}{}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			// Sample NVR-diff check: for each base-package (= name before
			// first '-'), do we see a single NVR or multiple?
			// We invert the nvrArchs map: per base pkg -> set of NVRs.
			nvrByPkg := map[string]map[string]struct{}{}
			for nvr := range nvrArchs {
				base := nvr
				if i := strings.Index(base, "-"); i > 0 {
					base = base[:i]
				}
				if _, ok := nvrByPkg[base]; !ok {
					nvrByPkg[base] = map[string]struct{}{}
				}
				nvrByPkg[base][nvr] = struct{}{}
			}
			same := true
			for _, nvrs := range nvrByPkg {
				if len(nvrs) > 1 {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
			}
		}
		if a, ok := archSetIsConcreteSingle(archSet); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for p := range pkgsByArch[a] {
				dd.SingleArchTopByArch[a][p]++
				allSinglePkgs[p]++
			}
		}
		n++
		if n%50000 == 0 {
			log.Printf("[deepdive rhvex] processed %d advisories", n)
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// ---------------- SUSE CVRF ----------------
//
// SUSE encodes arch as a substring of ProductReference (or
// RelatesToProductReference). Same trick as the analyzer: detect known
// arch tokens, strip them to recover an "NVR-ish" string, then check if the
// same NVR-ish string appears for every detected arch.
func deepDiveSUSECVRF() *DeepDive {
	base := "https://ftp.suse.com/pub/projects/security/cvrf/"
	idx, err := getBytes(base)
	if err != nil {
		return &DeepDive{Source: "suse-cvrf", Notes: "index fetch failed"}
	}
	re := regexp.MustCompile(`<a href="(cvrf-[^"]+\.xml)"`)
	matches := re.FindAllStringSubmatch(string(idx), -1)
	files := make([]string, 0, len(matches))
	for _, m := range matches {
		files = append(files, m[1])
	}
	log.Printf("[deepdive suse] %d files", len(files))

	type advAccum struct {
		archs map[string]struct{}
		// per arch -> set of "stripped" identifier strings
		stripped map[string]map[string]struct{}
		// per arch -> set of base pkg names (best effort: token before the first
		// version-like segment)
		pkgsByArch map[string]map[string]struct{}
	}
	advs := map[string]*advAccum{}
	var mu sync.Mutex
	bg := newBoundedGroup(48)
	for _, f := range files {
		f := f
		bg.Go(func() error {
			b, err := getBytes(base + f)
			if err != nil {
				return nil
			}
			var cv susetypes.Cvrf
			if err := xml.Unmarshal(b, &cv); err != nil {
				return nil
			}
			id := cv.Tracking.ID
			if id == "" {
				id = strings.TrimSuffix(f, ".xml")
			}
			acc := &advAccum{
				archs:      map[string]struct{}{},
				stripped:   map[string]map[string]struct{}{},
				pkgsByArch: map[string]map[string]struct{}{},
			}
			for _, r := range cv.ProductTree.Relationships {
				for _, s := range []string{r.ProductReference, r.RelatesToProductReference} {
					archs := detectArchTokens(s)
					if len(archs) == 0 {
						continue
					}
					// for each detected arch, derive a "stripped" identifier and a base pkg name
					for _, a := range archs {
						acc.archs[a] = struct{}{}
						stripped := s
						// Remove all-known-arch tokens from string for NVR comparison
						stripped = removeArchTokens(stripped)
						if _, ok := acc.stripped[a]; !ok {
							acc.stripped[a] = map[string]struct{}{}
						}
						acc.stripped[a][stripped] = struct{}{}
						base := basePkgName(stripped)
						if base != "" {
							if _, ok := acc.pkgsByArch[a]; !ok {
								acc.pkgsByArch[a] = map[string]struct{}{}
							}
							acc.pkgsByArch[a][base] = struct{}{}
						}
					}
				}
			}
			mu.Lock()
			advs[id] = acc
			mu.Unlock()
			return nil
		})
	}
	bg.Wait()

	dd := &DeepDive{
		Source: "suse-cvrf",
		Notes: "Multi-arch test: for each ProductReference string we strip out the arch token, " +
			"then check that the same stripped identifier appears under all arches in the advisory's " +
			"product tree. Same-stripped means 'same package@version' with arch removed; that is, same fix.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for _, acc := range advs {
		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range acc.archs {
			if a == "noarch" || a == "src" {
				continue
			}
			concrete[a] = struct{}{}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			// union of stripped strings across arches
			perArchStripped := map[string]map[string]struct{}{}
			for a := range concrete {
				perArchStripped[a] = acc.stripped[a]
			}
			// "same NVR" if intersection across all per-arch stripped sets is
			// non-empty (i.e. at least one fix is present for every arch).
			same := true
			var first map[string]struct{}
			for _, set := range perArchStripped {
				if first == nil {
					first = set
					continue
				}
				common := false
				for s := range first {
					if _, ok := set[s]; ok {
						common = true
						break
					}
				}
				if !common {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
			}
		}
		if a, ok := archSetIsConcreteSingle(acc.archs); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for p := range acc.pkgsByArch[a] {
				dd.SingleArchTopByArch[a][p]++
				allSinglePkgs[p]++
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// removeArchTokens removes all known-arch tokens from a hyphen-separated
// identifier so the remainder approximates an NVR string.
func removeArchTokens(s string) string {
	parts := strings.Split(s, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if isKnownArch(p) {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "-")
}

// basePkgName returns the package name guessed from an identifier like
// "wireshark-3.6.14-1.oe2203sp1" -> "wireshark".
func basePkgName(s string) string {
	// First numeric token marks the start of the version
	parts := strings.Split(s, "-")
	out := []string{}
	for _, p := range parts {
		if p == "" {
			continue
		}
		if p[0] >= '0' && p[0] <= '9' {
			break
		}
		out = append(out, p)
	}
	return strings.Join(out, "-")
}

// ---------------- ALMA ----------------
//
// Alma errata.json has each ALSA's pkglist.packages[] with .name/.version/
// .release/.arch as a structured field. For each multi-arch ALSA we group
// packages by name and check that the (version,release) tuple is identical
// across all arches the package is listed for.
func deepDiveAlma() *DeepDive {
	dd := &DeepDive{
		Source: "alma",
		Notes: "Multi-arch test: for each ALSA and each package name, " +
			"verifies that all per-arch RPMs share the same (version, release). " +
			"Single-arch top packages are computed across Alma 8/9/10.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for _, rel := range []string{"8", "9", "10"} {
		u := fmt.Sprintf("https://errata.almalinux.org/%s/errata.json", rel)
		b, err := getBytes(u)
		if err != nil {
			log.Printf("[deepdive alma] %s: %v", rel, err)
			continue
		}
		var errata []struct {
			UpdateinfoID string `json:"updateinfo_id"`
			Pkglist      struct {
				Packages []almatypes.Package `json:"packages"`
			} `json:"pkglist"`
		}
		if err := json.Unmarshal(b, &errata); err != nil {
			log.Printf("[deepdive alma] unmarshal %s: %v", rel, err)
			continue
		}
		for _, e := range errata {
			if !strings.HasPrefix(e.UpdateinfoID, "ALSA-") {
				continue
			}
			dd.TotalAdvisories++
			archs := map[string]struct{}{}
			// pkgname -> arch -> set of "v-r"
			byPkg := map[string]map[string]map[string]struct{}{}
			for _, p := range e.Pkglist.Packages {
				a := p.Arch
				if a == "x86_64_v2" {
					a = "x86_64"
				}
				archs[a] = struct{}{}
				if a == "src" || a == "" {
					continue
				}
				if _, ok := byPkg[p.Name]; !ok {
					byPkg[p.Name] = map[string]map[string]struct{}{}
				}
				if _, ok := byPkg[p.Name][a]; !ok {
					byPkg[p.Name][a] = map[string]struct{}{}
				}
				byPkg[p.Name][a][p.Version+"-"+p.Release] = struct{}{}
			}
			concrete := map[string]struct{}{}
			for a := range archs {
				if a != "noarch" && a != "src" && a != "" {
					concrete[a] = struct{}{}
				}
			}
			if len(concrete) >= 2 {
				dd.MultiArchAdvisories++
				same := true
				for _, archMap := range byPkg {
					if len(archMap) < 2 {
						continue
					}
					var common map[string]struct{}
					for _, vrset := range archMap {
						if common == nil {
							common = vrset
							continue
						}
						newCommon := map[string]struct{}{}
						for vr := range common {
							if _, ok := vrset[vr]; ok {
								newCommon[vr] = struct{}{}
							}
						}
						common = newCommon
					}
					if len(common) == 0 {
						same = false
						break
					}
				}
				if same {
					dd.MultiArchSameNVR++
				} else {
					dd.MultiArchDiffNVR++
					if len(dd.NVRDiffExamples) < 5 {
						dd.NVRDiffExamples = append(dd.NVRDiffExamples,
							fmt.Sprintf("%s (Alma %s)", e.UpdateinfoID, rel))
					}
				}
			}
			if a, ok := archSetIsConcreteSingle(archs); ok {
				dd.SingleArchAdvisories++
				dd.SingleArchByArch[a]++
				if dd.SingleArchTopByArch[a] == nil {
					dd.SingleArchTopByArch[a] = map[string]int{}
				}
				names := map[string]struct{}{}
				for _, p := range e.Pkglist.Packages {
					names[p.Name] = struct{}{}
				}
				for n := range names {
					dd.SingleArchTopByArch[a][n]++
					allSinglePkgs[n]++
				}
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// ---------------- AMAZON ----------------
//
// Walks AL1+AL2+AL2022+AL2023 (x86_64 + aarch64 mirrors), unions ALAS arch
// sets, and verifies same NVR across arches for each ALAS.
func deepDiveAmazon() *DeepDive {
	mirrors := map[string]string{
		"AL1":    "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"AL2":    "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
		"AL2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list",
		"AL2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
	}
	aarch := map[string]string{
		"AL2":    "https://cdn.amazonlinux.com/2/core/latest/aarch64/mirror.list",
		"AL2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/aarch64/mirror.list",
		"AL2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list",
	}
	type alasAccum struct {
		archs map[string]struct{}
		// pkgname -> arch -> set of "v-r"
		byPkg map[string]map[string]map[string]struct{}
		names map[string]struct{}
	}
	advs := map[string]*alasAccum{}
	parse := func(b []byte) {
		var ui amazontypes.UpdateInfo
		if err := xml.Unmarshal(b, &ui); err != nil {
			return
		}
		for _, a := range ui.ALASList {
			acc, ok := advs[a.ID]
			if !ok {
				acc = &alasAccum{
					archs: map[string]struct{}{},
					byPkg: map[string]map[string]map[string]struct{}{},
					names: map[string]struct{}{},
				}
				advs[a.ID] = acc
			}
			for _, p := range a.Packages {
				acc.archs[p.Arch] = struct{}{}
				acc.names[p.Name] = struct{}{}
				if p.Arch == "src" || p.Arch == "" {
					continue
				}
				if _, ok := acc.byPkg[p.Name]; !ok {
					acc.byPkg[p.Name] = map[string]map[string]struct{}{}
				}
				if _, ok := acc.byPkg[p.Name][p.Arch]; !ok {
					acc.byPkg[p.Name][p.Arch] = map[string]struct{}{}
				}
				acc.byPkg[p.Name][p.Arch][p.Version+"-"+p.Release] = struct{}{}
			}
		}
	}
	fetch := func(mirrorListURL string) {
		b, err := getBytes(mirrorListURL)
		if err != nil {
			return
		}
		s := bufio.NewScanner(bytes.NewReader(b))
		for s.Scan() {
			mirror := strings.TrimSpace(s.Text())
			if mirror == "" {
				continue
			}
			u, err := url.Parse(mirror)
			if err != nil {
				continue
			}
			u.Path = path.Join(u.Path, "repodata/repomd.xml")
			repomd, err := getBytes(u.String())
			if err != nil {
				continue
			}
			var rm amazontypes.RepoMd
			if err := xml.Unmarshal(repomd, &rm); err != nil {
				continue
			}
			var href string
			for _, r := range rm.RepoList {
				if r.Type == "updateinfo" {
					href = r.Location.Href
					break
				}
			}
			if href == "" {
				continue
			}
			u2 := *u
			u2.Path = path.Join(strings.TrimSuffix(u.Path, "repodata/repomd.xml"), href)
			body, err := getBytes(u2.String())
			if err != nil {
				continue
			}
			data, err := gunzip(body)
			if err != nil {
				continue
			}
			parse(data)
			return
		}
	}
	for _, m := range mirrors {
		fetch(m)
	}
	for _, m := range aarch {
		fetch(m)
	}

	dd := &DeepDive{
		Source: "amazon",
		Notes: "Combines AL1/2/2022/2023 x86_64+aarch64 feeds. Multi-arch test: " +
			"for each ALAS and each package name, checks that all per-arch RPMs share at least one " +
			"common (version,release) tuple.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for id, acc := range advs {
		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range acc.archs {
			if a != "noarch" && a != "src" && a != "" {
				concrete[a] = struct{}{}
			}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			same := true
			for _, archMap := range acc.byPkg {
				if len(archMap) < 2 {
					continue
				}
				var common map[string]struct{}
				for _, vrset := range archMap {
					if common == nil {
						common = vrset
						continue
					}
					newCommon := map[string]struct{}{}
					for vr := range common {
						if _, ok := vrset[vr]; ok {
							newCommon[vr] = struct{}{}
						}
					}
					common = newCommon
				}
				if len(common) == 0 {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
				if len(dd.NVRDiffExamples) < 5 {
					dd.NVRDiffExamples = append(dd.NVRDiffExamples, id)
				}
			}
		}
		if a, ok := archSetIsConcreteSingle(acc.archs); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for n := range acc.names {
				dd.SingleArchTopByArch[a][n]++
				allSinglePkgs[n]++
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// ---------------- ROCKY ----------------
//
// Same model as Amazon: walks each (release, repo, arch) updateinfo.xml
// across vault + download mirrors, merges per RLSA.
func deepDiveRocky() *DeepDive {
	baseURLs := []string{
		"https://download.rockylinux.org/pub/rocky",
		"https://dl.rockylinux.org/vault/rocky",
	}
	releases := []string{
		"8", "8.4", "8.5", "8.6", "8.7", "8.8", "8.9", "8.10",
		"9", "9.0", "9.1", "9.2", "9.3", "9.4", "9.5", "9.6",
		"10", "10.0",
	}
	repos := []string{"BaseOS", "AppStream", "extras"}
	arches := []string{"x86_64", "aarch64", "ppc64le", "s390x"}
	urlFormat := "%s/%s/%s/%s/os/"
	type rlsaAccum struct {
		archs map[string]struct{}
		byPkg map[string]map[string]map[string]struct{}
		names map[string]struct{}
	}
	advs := map[string]*rlsaAccum{}
	var mu sync.Mutex
	bg := newBoundedGroup(16)
	for _, base := range baseURLs {
		for _, rel := range releases {
			for _, repo := range repos {
				for _, arch := range arches {
					base, rel, repo, arch := base, rel, repo, arch
					bg.Go(func() error {
						osURL := fmt.Sprintf(urlFormat, base, rel, repo, arch)
						repomd, err := getBytes(osURL + "repodata/repomd.xml")
						if err != nil {
							return nil
						}
						var rm rockytypes.RepoMd
						if err := xml.Unmarshal(repomd, &rm); err != nil {
							return nil
						}
						var href string
						for _, r := range rm.RepoList {
							if r.Type == "updateinfo" {
								href = r.Location.Href
								break
							}
						}
						if href == "" {
							return nil
						}
						body, err := getBytes(osURL + href)
						if err != nil {
							return nil
						}
						data, err := gunzip(body)
						if err != nil {
							return nil
						}
						var ui rockytypes.UpdateInfo
						if err := xml.Unmarshal(data, &ui); err != nil {
							return nil
						}
						mu.Lock()
						defer mu.Unlock()
						for _, r := range ui.RLSAList {
							acc, ok := advs[r.ID]
							if !ok {
								acc = &rlsaAccum{
									archs: map[string]struct{}{},
									byPkg: map[string]map[string]map[string]struct{}{},
									names: map[string]struct{}{},
								}
								advs[r.ID] = acc
							}
							for _, c := range r.Collections {
								for _, p := range c.Packages {
									acc.archs[p.Arch] = struct{}{}
									acc.names[p.Name] = struct{}{}
									if p.Arch == "src" || p.Arch == "" {
										continue
									}
									if _, ok := acc.byPkg[p.Name]; !ok {
										acc.byPkg[p.Name] = map[string]map[string]struct{}{}
									}
									if _, ok := acc.byPkg[p.Name][p.Arch]; !ok {
										acc.byPkg[p.Name][p.Arch] = map[string]struct{}{}
									}
									acc.byPkg[p.Name][p.Arch][p.Version+"-"+p.Release] = struct{}{}
								}
							}
						}
						return nil
					})
				}
			}
		}
	}
	bg.Wait()

	dd := &DeepDive{
		Source: "rocky",
		Notes: "Combines Rocky 8/9/10 BaseOS+AppStream+extras across x86_64/aarch64/ppc64le/s390x; " +
			"multi-arch test verifies all per-arch RPMs share a common (version,release) per package name.",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for id, acc := range advs {
		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range acc.archs {
			if a != "noarch" && a != "src" && a != "" {
				concrete[a] = struct{}{}
			}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			same := true
			for _, archMap := range acc.byPkg {
				if len(archMap) < 2 {
					continue
				}
				var common map[string]struct{}
				for _, vrset := range archMap {
					if common == nil {
						common = vrset
						continue
					}
					newCommon := map[string]struct{}{}
					for vr := range common {
						if _, ok := vrset[vr]; ok {
							newCommon[vr] = struct{}{}
						}
					}
					common = newCommon
				}
				if len(common) == 0 {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
				if len(dd.NVRDiffExamples) < 5 {
					dd.NVRDiffExamples = append(dd.NVRDiffExamples, id)
				}
			}
		}
		if a, ok := archSetIsConcreteSingle(acc.archs); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for n := range acc.names {
				dd.SingleArchTopByArch[a][n]++
				allSinglePkgs[n]++
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}

// ---------------- OPENEULER ----------------
//
// openEuler CVRF has explicit ProductTree.Branches[Type='Package Arch']
// each containing FullProductName entries whose ProductID is the package
// NVR (e.g. "kernel-5.10.0-153.48.0.126"). For each advisory we group by
// product-id across arch branches and verify ID identity.
func deepDiveOpenEuler() *DeepDive {
	base := "https://repo.openeuler.org/security/data/cvrf/"
	idx, err := getBytes(base + "index.txt")
	if err != nil {
		return &DeepDive{Source: "openeuler", Notes: "index fetch failed"}
	}
	var entries []string
	sc := bufio.NewScanner(bytes.NewReader(idx))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		entries = append(entries, line)
	}
	log.Printf("[deepdive openeuler] %d files", len(entries))

	type advAccum struct {
		archs map[string]struct{}
		// pkgname -> arch -> set of NVR strings
		byPkg map[string]map[string]map[string]struct{}
		names map[string]struct{}
	}
	advs := map[string]*advAccum{}
	var mu sync.Mutex
	bg := newBoundedGroup(16)
	for _, e := range entries {
		e := e
		bg.Go(func() error {
			b, err := getBytes(base + e)
			if err != nil {
				return nil
			}
			var cv openeulertypes.Cvrf
			if err := xml.Unmarshal(b, &cv); err != nil {
				return nil
			}
			id := cv.Tracking.ID
			if id == "" {
				return nil
			}
			acc := &advAccum{
				archs: map[string]struct{}{},
				byPkg: map[string]map[string]map[string]struct{}{},
				names: map[string]struct{}{},
			}
			for _, br := range cv.ProductTree.Branches {
				if br.Type != "Package Arch" || br.Name == "" {
					continue
				}
				arch := br.Name
				acc.archs[arch] = struct{}{}
				if arch == "src" || arch == "" {
					continue
				}
				for _, pn := range br.Productions {
					// ProductID looks like "kernel-5.10.0-153.48.0.126"
					name := basePkgName(pn.ProductID)
					if name == "" {
						continue
					}
					nvr := strings.TrimPrefix(pn.ProductID, name+"-")
					acc.names[name] = struct{}{}
					if _, ok := acc.byPkg[name]; !ok {
						acc.byPkg[name] = map[string]map[string]struct{}{}
					}
					if _, ok := acc.byPkg[name][arch]; !ok {
						acc.byPkg[name][arch] = map[string]struct{}{}
					}
					acc.byPkg[name][arch][nvr] = struct{}{}
				}
			}
			mu.Lock()
			advs[id] = acc
			mu.Unlock()
			return nil
		})
	}
	bg.Wait()

	dd := &DeepDive{
		Source: "openeuler",
		Notes: "Multi-arch test: for each openEuler advisory and each base package name, " +
			"verifies that all per-arch ProductTree branches share a common NVR string " +
			"(after stripping the leading package name).",
		SingleArchByArch:    map[string]int{},
		SingleArchTopByArch: map[string]map[string]int{},
	}
	allSinglePkgs := map[string]int{}
	for id, acc := range advs {
		dd.TotalAdvisories++
		concrete := map[string]struct{}{}
		for a := range acc.archs {
			if a != "noarch" && a != "src" && a != "" {
				concrete[a] = struct{}{}
			}
		}
		if len(concrete) >= 2 {
			dd.MultiArchAdvisories++
			same := true
			for _, archMap := range acc.byPkg {
				if len(archMap) < 2 {
					continue
				}
				var common map[string]struct{}
				for _, vrset := range archMap {
					if common == nil {
						common = vrset
						continue
					}
					newCommon := map[string]struct{}{}
					for vr := range common {
						if _, ok := vrset[vr]; ok {
							newCommon[vr] = struct{}{}
						}
					}
					common = newCommon
				}
				if len(common) == 0 {
					same = false
					break
				}
			}
			if same {
				dd.MultiArchSameNVR++
			} else {
				dd.MultiArchDiffNVR++
				if len(dd.NVRDiffExamples) < 5 {
					dd.NVRDiffExamples = append(dd.NVRDiffExamples, id)
				}
			}
		}
		if a, ok := archSetIsConcreteSingle(acc.archs); ok {
			dd.SingleArchAdvisories++
			dd.SingleArchByArch[a]++
			if dd.SingleArchTopByArch[a] == nil {
				dd.SingleArchTopByArch[a] = map[string]int{}
			}
			for n := range acc.names {
				dd.SingleArchTopByArch[a][n]++
				allSinglePkgs[n]++
			}
		}
	}
	dd.SingleArchTopPackages = map[string][]string{}
	dd.SingleArchTopPackages["overall"] = topN(allSinglePkgs, 15)
	for a, m := range dd.SingleArchTopByArch {
		dd.SingleArchTopPackages[a] = topN(m, 10)
	}
	return dd
}
