// Package main provides a one-shot analyzer that, for each supported source,
// downloads the upstream data, counts total advisories/CVEs and how many are
// architecture-specific (i.e. restricted to a strict subset of the source's
// total set of CPU architectures).
//
// Sources covered (those with a structured arch field):
//   - alpine        (https://secdb.alpinelinux.org/)
//   - amazon        (Amazon Linux 1/2/2022/2023 mirrors)
//   - alma          (https://errata.almalinux.org/)
//   - rocky         (Rocky updateinfo)
//   - redhat-oval   (Red Hat OVAL v2)
//   - openeuler     (CVRF index)
//
// Output: a Markdown table printed to stdout plus one JSON file per source
// under scripts/arch-analysis/out/<source>.json with per-arch breakdowns.
//
// Notes / definitions used:
//   - "Advisory/CVE" is the count of unique advisory IDs (RHSA/ALAS/ALSA/RLSA/
//     openEuler-SA) or, for Alpine, the count of (CVE, package) pairs. We
//     also report unique CVE counts where available.
//   - "Arch-specific" means: the advisory's package set lists at least one
//     concrete CPU arch (x86_64, aarch64, ppc64le, s390x, armhf, armv7, riscv64,
//     etc.) and is missing at least one of the arches that the source supports
//     overall. Advisories that target only "noarch" or "src" do not count as
//     arch-specific.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/klauspost/compress/zstd"

	almatypes "github.com/aquasecurity/vuln-list-update/alma"
	amazontypes "github.com/aquasecurity/vuln-list-update/amazon"
	openeulertypes "github.com/aquasecurity/vuln-list-update/openeuler"
	rhovaltypes "github.com/aquasecurity/vuln-list-update/redhat/oval"
	rockytypes "github.com/aquasecurity/vuln-list-update/rocky"
	susetypes "github.com/aquasecurity/vuln-list-update/suse/cvrf"
)

// SourceResult is the aggregated outcome for a single source.
type SourceResult struct {
	Source            string         `json:"source"`
	UpstreamSupported []string       `json:"upstream_supported_arches"`
	TotalAdvisories   int            `json:"total_advisories"`
	UniqueCVEs        int            `json:"unique_cves,omitempty"`
	ArchSpecificCount int            `json:"arch_specific_advisories"`
	SingleArchCount   int            `json:"single_arch_advisories"`
	NoarchOnlyCount   int            `json:"noarch_only_advisories"`
	AllArchCount      int            `json:"all_arch_advisories"`
	ArchSpecificCVEs  int            `json:"arch_specific_cves,omitempty"`
	PerArchAdvisories map[string]int `json:"per_arch_advisories"`
	PerArchOnlyExcl   map[string]int `json:"per_arch_exclusive"`
	Notes             string         `json:"notes,omitempty"`
}

// httpClient is a global HTTP client with a longish timeout (some servers are slow).
var httpClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	},
}

func getBytes(u string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "vuln-list-update arch-analyzer")
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(2 * time.Second)
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("status %d for %s", resp.StatusCode, u)
			if resp.StatusCode == 404 {
				return nil, lastErr
			}
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return nil, lastErr
}

// gunzip helper.
func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// ---------------- ALPINE ----------------
//
// Strategy: alpine secdb publishes JSON files like
//   https://secdb.alpinelinux.org/v3.20/main.json
// Each file has a top-level "archs" array. We treat the "archs" set as
// arch-restrictive when it's a strict subset of the maximal alpine arch set
// seen across all releases.
func analyzeAlpine() (*SourceResult, error) {
	baseURL := "https://secdb.alpinelinux.org/"
	indexHTML, err := getBytes(baseURL)
	if err != nil {
		return nil, fmt.Errorf("alpine index: %w", err)
	}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader(indexHTML))
	var releases []string
	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSuffix(s.Text(), "/")
		if strings.HasPrefix(text, "v") || strings.HasPrefix(text, "edge") {
			releases = append(releases, text)
		}
	})
	log.Printf("[alpine] releases: %v", releases)

	totalSecfixSets := 0   // count of (release,repo) secdb files
	totalCVEPkgPairs := 0  // count of (CVE-id, pkg, release, repo)
	archSpecificSets := 0  // secdb files whose archs is a strict subset
	noarchOnly := 0        // secdb files that don't declare archs
	perArchAdv := map[string]int{}
	uniqueCVEs := map[string]struct{}{}
	maxArchSet := map[string]struct{}{}
	type group struct {
		release string
		file    string
		archs   []string
		ncves   int
	}
	var groups []group

	type secdb struct {
		Packages json.RawMessage `json:"packages"`
		Archs    []string        `json:"archs"`
	}
	type pkgEntry struct {
		Pkg struct {
			Name     string                 `json:"name"`
			Secfixes map[string]interface{} `json:"secfixes"`
		} `json:"pkg"`
	}

	for _, release := range releases {
		relURL := baseURL + release + "/"
		idx, err := getBytes(relURL)
		if err != nil {
			log.Printf("[alpine] skip %s: %v", release, err)
			continue
		}
		d, _ := goquery.NewDocumentFromReader(bytes.NewReader(idx))
		var files []string
		d.Find("a").Each(func(_ int, s *goquery.Selection) {
			t := s.Text()
			if strings.HasSuffix(t, ".json") {
				files = append(files, t)
			}
		})
		for _, f := range files {
			b, err := getBytes(relURL + f)
			if err != nil {
				log.Printf("[alpine] skip %s/%s: %v", release, f, err)
				continue
			}
			var sd secdb
			if err = json.Unmarshal(b, &sd); err != nil {
				log.Printf("[alpine] unmarshal %s/%s: %v", release, f, err)
				continue
			}
			// "packages" can be an empty object {} when there is no data
			var pkgs []pkgEntry
			if err = json.Unmarshal(sd.Packages, &pkgs); err != nil {
				continue
			}
			totalSecfixSets++
			for _, a := range sd.Archs {
				maxArchSet[a] = struct{}{}
				perArchAdv[a]++
			}
			localCVEs := 0
			for _, p := range pkgs {
				for _, v := range p.Pkg.Secfixes {
					arr, ok := v.([]interface{})
					if !ok {
						continue
					}
					for _, item := range arr {
						s, _ := item.(string)
						if strings.HasPrefix(s, "CVE-") {
							uniqueCVEs[s] = struct{}{}
							totalCVEPkgPairs++
							localCVEs++
						}
					}
				}
			}
			groups = append(groups, group{release: release, file: f, archs: sd.Archs, ncves: localCVEs})
			if len(sd.Archs) == 0 {
				noarchOnly++
			}
		}
	}
	// Determine archSpecificSets: a secdb file is arch-specific if its archs
	// is a strict, non-empty subset of the maxArchSet. Also count
	// arch-specific CVE-pkg pairs (those rolled up into such files).
	maxN := len(maxArchSet)
	archSpecificCVEPkgs := 0
	singleArchSets := 0
	for _, gr := range groups {
		if len(gr.archs) > 0 && len(gr.archs) < maxN {
			archSpecificSets++
			archSpecificCVEPkgs += gr.ncves
		}
		if len(gr.archs) == 1 {
			singleArchSets++
		}
	}

	result := &SourceResult{
		Source:            "alpine",
		UpstreamSupported: keysSorted(maxArchSet),
		TotalAdvisories:   totalSecfixSets,
		UniqueCVEs:        len(uniqueCVEs),
		ArchSpecificCount: archSpecificSets,
		SingleArchCount:   singleArchSets,
		NoarchOnlyCount:   noarchOnly,
		AllArchCount:      totalSecfixSets - noarchOnly - archSpecificSets,
		PerArchAdvisories: perArchAdv,
		Notes: fmt.Sprintf("'TotalAdvisories' = number of (release,repo) secdb files. "+
			"Alpine's 'archs' field is the same for every package within a secdb file; "+
			"individual CVE entries do not declare per-CVE arch. "+
			"CVE-pkg pair count: %d (arch-specific subset: %d).", totalCVEPkgPairs, archSpecificCVEPkgs),
	}
	return result, nil
}

// ---------------- AMAZON ----------------
//
// Amazon ships updateinfo.xml per release. Each ALAS has <pkglist>...<package
// arch="..."> entries. An ALAS is arch-specific if its packages cover a strict
// subset of the upstream's supported arches for that release. Amazon Linux 2+
// supports x86_64 and aarch64.
func analyzeAmazon() (*SourceResult, error) {
	mirrors := map[string]string{
		"1":    "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"2":    "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
		"2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list",
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
	}
	// Amazon's mirror.list URLs only enumerate x86_64. To get arch coverage
	// we also try the aarch64 mirror list where it's known to exist.
	aarchMirrors := map[string]string{
		"2":    "https://cdn.amazonlinux.com/2/core/latest/aarch64/mirror.list",
		"2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/aarch64/mirror.list",
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list",
	}

	type accumulator struct {
		alasArchs map[string]map[string]struct{} // alasID -> set of arches
	}
	acc := &accumulator{alasArchs: map[string]map[string]struct{}{}}

	parseUpdateInfo := func(b []byte) error {
		var ui amazontypes.UpdateInfo
		if err := xml.Unmarshal(b, &ui); err != nil {
			return err
		}
		for _, a := range ui.ALASList {
			set, ok := acc.alasArchs[a.ID]
			if !ok {
				set = map[string]struct{}{}
				acc.alasArchs[a.ID] = set
			}
			for _, p := range a.Packages {
				if p.Arch == "" {
					continue
				}
				set[p.Arch] = struct{}{}
			}
		}
		return nil
	}

	fetchUpdateInfoFromMirrorList := func(mirrorListURL string) error {
		b, err := getBytes(mirrorListURL)
		if err != nil {
			return err
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
			// fetch repomd.xml
			u.Path = path.Join(u.Path, "repodata/repomd.xml")
			repomd, err := getBytes(u.String())
			if err != nil {
				continue
			}
			var rm amazontypes.RepoMd
			if err = xml.Unmarshal(repomd, &rm); err != nil {
				continue
			}
			var updateInfoHref string
			for _, r := range rm.RepoList {
				if r.Type == "updateinfo" {
					updateInfoHref = r.Location.Href
					break
				}
			}
			if updateInfoHref == "" {
				continue
			}
			u2 := *u
			u2.Path = path.Join(strings.TrimSuffix(u.Path, "repodata/repomd.xml"), updateInfoHref)
			body, err := getBytes(u2.String())
			if err != nil {
				continue
			}
			data, err := gunzip(body)
			if err != nil {
				continue
			}
			if err := parseUpdateInfo(data); err != nil {
				log.Printf("[amazon] parse error: %v", err)
				continue
			}
			return nil
		}
		return fmt.Errorf("no working mirror in %s", mirrorListURL)
	}

	for v, mirror := range mirrors {
		if err := fetchUpdateInfoFromMirrorList(mirror); err != nil {
			log.Printf("[amazon] v%s x86_64 failed: %v", v, err)
		}
	}
	for v, mirror := range aarchMirrors {
		if err := fetchUpdateInfoFromMirrorList(mirror); err != nil {
			log.Printf("[amazon] v%s aarch64 failed: %v", v, err)
		}
	}

	upstreamMax := map[string]struct{}{}
	for _, set := range acc.alasArchs {
		for a := range set {
			upstreamMax[a] = struct{}{}
		}
	}
	maxN := len(upstreamMax)

	perArch := map[string]int{}
	perArchExclusive := map[string]int{}
	archSpecific := 0
	singleArch := 0
	noarchOnly := 0
	allArch := 0
	concreteArchSet := map[string]struct{}{}
	for a := range upstreamMax {
		if a != "noarch" && a != "src" {
			concreteArchSet[a] = struct{}{}
		}
	}
	concreteN := len(concreteArchSet)

	for _, set := range acc.alasArchs {
		concrete := map[string]struct{}{}
		hasNoarch := false
		for a := range set {
			if a == "noarch" || a == "src" {
				hasNoarch = true
				continue
			}
			concrete[a] = struct{}{}
			perArch[a]++
		}
		switch {
		case len(concrete) == 0 && hasNoarch:
			noarchOnly++
		case len(concrete) > 0 && len(concrete) < concreteN:
			archSpecific++
			if len(concrete) == 1 {
				singleArch++
				for a := range concrete {
					perArchExclusive[a]++
				}
			}
		case len(concrete) == concreteN:
			allArch++
		}
	}

	_ = maxN
	return &SourceResult{
		Source:            "amazon",
		UpstreamSupported: keysSorted(concreteArchSet),
		TotalAdvisories:   len(acc.alasArchs),
		ArchSpecificCount: archSpecific,
		SingleArchCount:   singleArch,
		NoarchOnlyCount:   noarchOnly,
		AllArchCount:      allArch,
		PerArchAdvisories: perArch,
		PerArchOnlyExcl:   perArchExclusive,
		Notes:             "Counts merge across Amazon Linux 1/2/2022/2023; 'arch-specific' = ALAS whose concrete arch set is a strict, non-empty subset of the union of all observed concrete arches.",
	}, nil
}

// ---------------- ALMALINUX ----------------
//
// AlmaLinux publishes a JSON errata file per release with a list of ALSAs;
// each entry has pkglist.packages[].arch.
func analyzeAlma() (*SourceResult, error) {
	releases := []string{"8", "9", "10"}
	alsa := map[string]map[string]struct{}{} // alsaID -> arches
	for _, rel := range releases {
		u := fmt.Sprintf("https://errata.almalinux.org/%s/errata.json", rel)
		b, err := getBytes(u)
		if err != nil {
			log.Printf("[alma] %s: %v", rel, err)
			continue
		}
		// Per-erratum unmarshaling; mirror the structure used by alma/alma.go.
		var errata []struct {
			UpdateinfoID string `json:"updateinfo_id"`
			Pkglist      struct {
				Packages []almatypes.Package `json:"packages"`
			} `json:"pkglist"`
		}
		if err = json.Unmarshal(b, &errata); err != nil {
			log.Printf("[alma] unmarshal %s: %v", rel, err)
			continue
		}
		for _, e := range errata {
			if !strings.HasPrefix(e.UpdateinfoID, "ALSA-") {
				continue
			}
			set, ok := alsa[e.UpdateinfoID]
			if !ok {
				set = map[string]struct{}{}
				alsa[e.UpdateinfoID] = set
			}
			for _, p := range e.Pkglist.Packages {
				a := p.Arch
				// Normalize micro-arch variants: AlmaLinux uses "x86_64_v2"
				// for a 2nd-gen baseline; downstream tooling treats it as
				// x86_64 for arch purposes.
				if a == "x86_64_v2" {
					a = "x86_64"
				}
				set[a] = struct{}{}
			}
		}
	}
	return summarizePackageArches("alma", alsa,
		"AlmaLinux 8/9/10 combined; arch from each errata package."), nil
}

// ---------------- ROCKY ----------------
//
// Rocky updateinfo is per (release, repo, arch). Each RLSA has <package
// arch="..."> entries. Iterate the same arches the project uses.
func analyzeRocky() (*SourceResult, error) {
	rlsa := map[string]map[string]struct{}{}

	// Known Rocky releases to scan. The vault hosts old z-stream releases;
	// the download mirror hosts the current GA releases. We pick a
	// reasonable union of all majors that exist as of this analysis.
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

	parseUpdateInfo := func(b []byte) error {
		var ui rockytypes.UpdateInfo
		if err := xml.Unmarshal(b, &ui); err != nil {
			return err
		}
		for _, r := range ui.RLSAList {
			set, ok := rlsa[r.ID]
			if !ok {
				set = map[string]struct{}{}
				rlsa[r.ID] = set
			}
			for _, c := range r.Collections {
				for _, p := range c.Packages {
					set[p.Arch] = struct{}{}
				}
			}
		}
		return nil
	}

	type fetchTask struct {
		base, rel, repo, arch string
	}
	var tasks []fetchTask
	for _, base := range baseURLs {
		for _, rel := range releases {
			for _, repo := range repos {
				for _, arch := range arches {
					tasks = append(tasks, fetchTask{base, rel, repo, arch})
				}
			}
		}
	}
	log.Printf("[rocky] %d (release,repo,arch,base) combinations to probe", len(tasks))

	var rmu sync.Mutex
	bg := newBoundedGroup(16)
	for _, t := range tasks {
		t := t
		bg.Go(func() error {
			osURL := fmt.Sprintf(urlFormat, t.base, t.rel, t.repo, t.arch)
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
			rmu.Lock()
			defer rmu.Unlock()
			if err := parseUpdateInfo(data); err != nil {
				log.Printf("[rocky] parse %s/%s/%s/%s: %v", t.base, t.rel, t.repo, t.arch, err)
				return nil
			}
			log.Printf("[rocky] ok %s/%s/%s/%s", t.base, t.rel, t.repo, t.arch)
			return nil
		})
	}
	bg.Wait()
	return summarizePackageArches("rocky", rlsa,
		"Rocky aggregated over discovered releases × {BaseOS,AppStream,extras} × {x86_64,aarch64,ppc64le,s390x}."), nil
}

// ---------------- REDHAT OVAL v2 ----------------
//
// Use the PULP_MANIFEST under
// https://security.access.redhat.com/data/oval/v2/ to discover RHEL OVAL bz2
// files. For each definition, the arch info lives in States[].RpminfoState[].Arch.Text
// — a regex pattern that ORs the supported arches (e.g. "x86_64|s390x").
// We map each definition (RHSA / CVE) to the union of arches declared by the
// state(s) it references.
func analyzeRedhatOVAL() (*SourceResult, error) {
	base := "https://security.access.redhat.com/data/oval/v2/"
	manifest, err := getBytes(base + "PULP_MANIFEST")
	if err != nil {
		return nil, fmt.Errorf("redhat manifest: %w", err)
	}
	var files []string
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ",")
		if len(parts) < 3 {
			continue
		}
		if parts[2] == "0" {
			continue
		}
		if !strings.HasPrefix(parts[0], "RHEL") {
			continue
		}
		if !strings.HasSuffix(parts[0], ".oval.xml.bz2") {
			continue
		}
		files = append(files, parts[0])
	}
	log.Printf("[redhat-oval] %d files", len(files))

	advisories := map[string]map[string]struct{}{}
	var mu sync.Mutex
	g, _ := errgroupConcurrency(8)
	for _, f := range files {
		f := f
		g.Go(func() error {
			b, err := getBytes(base + f)
			if err != nil {
				log.Printf("[redhat-oval] fetch %s: %v", f, err)
				return nil
			}
			r := bzip2.NewReader(bytes.NewReader(b))
			var ov rhovaltypes.OvalDefinitions
			if err := xml.NewDecoder(r).Decode(&ov); err != nil {
				log.Printf("[redhat-oval] decode %s: %v", f, err)
				return nil
			}
			// Build maps: testID -> stateID; stateID -> arch regex.
			stateArch := map[string]string{}
			for _, st := range ov.States.RpminfoState {
				if st.Arch.Text != "" {
					stateArch[st.ID] = st.Arch.Text
				}
			}
			testState := map[string]string{}
			for _, t := range ov.Tests.RpminfoTests {
				if t.State.StateRef != "" {
					testState[t.ID] = t.State.StateRef
				}
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
				var walk func(c rhovaltypes.Criteria)
				walk = func(c rhovaltypes.Criteria) {
					for _, cr := range c.Criterions {
						sid := testState[cr.TestRef]
						pat := stateArch[sid]
						if pat == "" {
							continue
						}
						for _, p := range strings.Split(pat, "|") {
							p = strings.TrimSpace(p)
							if p != "" {
								archSet[p] = struct{}{}
							}
						}
					}
					for _, child := range c.Criterias {
						walk(child)
					}
				}
				walk(d.Criteria)
				mu.Lock()
				prev, ok := advisories[vulnID]
				if !ok {
					prev = map[string]struct{}{}
					advisories[vulnID] = prev
				}
				for a := range archSet {
					prev[a] = struct{}{}
				}
				mu.Unlock()
			}
			return nil
		})
	}
	g.Wait()

	return summarizePackageArches("redhat-oval", advisories,
		"RHEL OVAL v2 across all RHELn definitions; arch from RpminfoState.Arch regex."), nil
}

// ---------------- OPENEULER ----------------
//
// openEuler publishes index.txt listing CVRF XMLs. Each CVRF has
// ProductTree.Branches[Type='Package Arch'].
func analyzeOpenEuler() (*SourceResult, error) {
	base := "https://repo.openeuler.org/security/data/cvrf/"
	idx, err := getBytes(base + "index.txt")
	if err != nil {
		return nil, fmt.Errorf("openeuler index: %w", err)
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
	log.Printf("[openeuler] %d files", len(entries))

	advisories := map[string]map[string]struct{}{}
	var mu sync.Mutex
	g, _ := errgroupConcurrency(16)
	for _, e := range entries {
		e := e
		g.Go(func() error {
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
			set := map[string]struct{}{}
			for _, br := range cv.ProductTree.Branches {
				if br.Type == "Package Arch" && br.Name != "" {
					set[br.Name] = struct{}{}
				}
			}
			mu.Lock()
			advisories[id] = set
			mu.Unlock()
			return nil
		})
	}
	g.Wait()
	return summarizePackageArches("openeuler", advisories,
		"openEuler CVRF advisory_id -> ProductTree branch arches."), nil
}

// ---------------- SUSE CVRF ----------------
//
// SUSE publishes CVRF files at http://ftp.suse.com/pub/projects/security/cvrf/.
// Each CVRF XML has ProductTree.Relationships[i].ProductReference whose value
// often encodes an architecture (e.g. iscsitarget-kmp-ppc64-1.4.20...). We
// scan all ProductReference and RelatesToProductReference strings for known
// arch tokens.
func analyzeSUSECVRF() (*SourceResult, error) {
	// SUSE redirects http -> https; use https directly so per-file requests
	// don't pay the redirect penalty.
	base := "https://ftp.suse.com/pub/projects/security/cvrf/"
	idx, err := getBytes(base)
	if err != nil {
		return nil, fmt.Errorf("suse index: %w", err)
	}
	re := regexp.MustCompile(`<a href="(cvrf-[^"]+\.xml)"`)
	matches := re.FindAllStringSubmatch(string(idx), -1)
	files := make([]string, 0, len(matches))
	for _, m := range matches {
		files = append(files, m[1])
	}
	log.Printf("[suse-cvrf] %d files", len(files))
	// Limit max files only when CVRF_MAX env is set; default scans all.
	if v := os.Getenv("CVRF_MAX"); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		if n > 0 && n < len(files) {
			files = files[:n]
			log.Printf("[suse-cvrf] limited to %d files (CVRF_MAX)", n)
		}
	}
	// Print progress every 15 seconds while we fetch.
	var done int64
	progress := time.NewTicker(15 * time.Second)
	defer progress.Stop()
	stopProgress := make(chan struct{})
	go func() {
		for {
			select {
			case <-progress.C:
				log.Printf("[suse-cvrf] progress: %d/%d", atomic.LoadInt64(&done), len(files))
			case <-stopProgress:
				return
			}
		}
	}()
	defer close(stopProgress)

	advisories := map[string]map[string]struct{}{}
	var mu sync.Mutex
	bg := newBoundedGroup(48)
	for _, f := range files {
		f := f
		bg.Go(func() error {
			defer atomic.AddInt64(&done, 1)
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
				id = f
			}
			set := map[string]struct{}{}
			for _, r := range cv.ProductTree.Relationships {
				for _, s := range []string{r.ProductReference, r.RelatesToProductReference} {
					for _, a := range detectArchTokens(s) {
						set[a] = struct{}{}
					}
				}
			}
			mu.Lock()
			advisories[id] = set
			mu.Unlock()
			return nil
		})
	}
	bg.Wait()
	return summarizePackageArches("suse-cvrf", advisories,
		"SUSE CVRF advisory_id -> arch tokens detected inside ProductReference / RelatesToProductReference strings."), nil
}

// detectArchTokens returns the set of CPU architectures found as
// dash-separated tokens inside the given identifier string.
func detectArchTokens(s string) []string {
	if s == "" {
		return nil
	}
	out := map[string]struct{}{}
	for _, sep := range []string{"-", ":", "/", ".", "_"} {
		// underscore split would chop x86_64; reinstate after splitting
		_ = sep
	}
	// Token split: replace separators with space, but keep underscores so
	// "x86_64" survives.
	for _, sep := range []string{"-", ":", "/", "."} {
		s = strings.ReplaceAll(s, sep, " ")
	}
	for _, tok := range strings.Fields(s) {
		if isKnownArch(tok) {
			out[tok] = struct{}{}
		}
	}
	res := make([]string, 0, len(out))
	for a := range out {
		res = append(res, a)
	}
	return res
}

// ---------------- REDHAT CSAF VEX ----------------
//
// Red Hat ships a daily tar.zst of all CSAF VEX advisories. Each advisory
// JSON has a product_tree with branches that contain a "purl" with an
// arch=... query parameter, and "cpe" strings whose 6th colon-separated
// component is the arch. We collect the set of concrete arches per advisory.
func analyzeRedhatCSAFVEX() (*SourceResult, error) {
	base := "https://security.access.redhat.com/data/csaf/v2/vex/"
	nameB, err := getBytes(base + "archive_latest.txt")
	if err != nil {
		return nil, fmt.Errorf("vex archive name: %w", err)
	}
	name := strings.TrimSpace(string(nameB))
	log.Printf("[redhat-csaf-vex] downloading %s", name)
	body, err := getBytes(base + name)
	if err != nil {
		return nil, fmt.Errorf("vex archive: %w", err)
	}
	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("zstd reader: %w", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)

	advisories := map[string]map[string]struct{}{}

	purlArchRe := regexp.MustCompile(`[?&]arch=([^&]+)`)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		raw, err := io.ReadAll(tr)
		if err != nil {
			return nil, fmt.Errorf("tar read %s: %w", hdr.Name, err)
		}
		// Use a minimal decoder: we only need product_tree branches' purl/cpe.
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
		id := doc.Document.Tracking.ID
		if id == "" {
			id = strings.TrimSuffix(filepath.Base(hdr.Name), filepath.Ext(hdr.Name))
		}
		set := map[string]struct{}{}
		walkBranches(doc.ProductTree.Branches, set, purlArchRe)
		advisories[id] = set
	}
	return summarizePackageArches("redhat-csaf-vex", advisories,
		"Red Hat CSAF VEX archive_latest.tar.zst; arch extracted from product_tree branch purl ?arch=... and CPE component."), nil
}

type branch struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Product  *struct {
		ProductID                  string `json:"product_id"`
		ProductIdentificationHelper *struct {
			CPE  string `json:"cpe"`
			Purl string `json:"purl"`
		} `json:"product_identification_helper"`
	} `json:"product"`
	Branches []branch `json:"branches"`
}

// isKnownArch returns true if s is a CPU architecture name we recognise.
// This is the whitelist used by both the SUSE and Red Hat analyzers to
// filter out non-arch tokens (product names, channel labels, etc.) that
// happen to share the position of arch inside identifier strings.
var knownArches = map[string]struct{}{
	"x86_64":  {},
	"i386":    {},
	"i486":    {},
	"i586":    {},
	"i686":    {},
	"amd64":   {},
	"ia32e":   {},
	"ia64":    {},
	"athlon":  {},
	"aarch64": {},
	"arm64":   {},
	"armhf":   {},
	"armv7":   {},
	"armv7hl": {},
	"armv6":   {},
	"ppc":     {},
	"ppc64":   {},
	"ppc64le": {},
	"s390":    {},
	"s390x":   {},
	"riscv64": {},
	"sparc":   {},
	"sparc64": {},
	"alpha":   {},
	"mips":    {},
	"mips64":  {},
}

func isKnownArch(s string) bool {
	_, ok := knownArches[s]
	return ok
}

// walkBranches recurses into product_tree branches and records arches it
// finds in purl and cpe identifiers.
func walkBranches(brs []branch, dst map[string]struct{}, purlRe *regexp.Regexp) {
	for _, b := range brs {
		// Architecture branch category directly names the arch.
		if b.Category == "architecture" && b.Name != "" && isKnownArch(b.Name) {
			dst[b.Name] = struct{}{}
		}
		if b.Product != nil && b.Product.ProductIdentificationHelper != nil {
			h := b.Product.ProductIdentificationHelper
			if h.Purl != "" {
				if m := purlRe.FindStringSubmatch(h.Purl); len(m) == 2 {
					if isKnownArch(m[1]) {
						dst[m[1]] = struct{}{}
					}
				}
			}
			if h.CPE != "" {
				// CPE 2.3: cpe:2.3:o:redhat:enterprise_linux:9:x86_64 -> arch in 6th comp.
				// CPE 2.2: cpe:/o:redhat:enterprise_linux:9::x86_64 -> arch later.
				parts := strings.Split(h.CPE, ":")
				for _, p := range parts {
					if isKnownArch(p) {
						dst[p] = struct{}{}
					}
				}
			}
		}
		if len(b.Branches) > 0 {
			walkBranches(b.Branches, dst, purlRe)
		}
	}
}

// summarizePackageArches takes a map of advisoryID -> arch set and produces a
// SourceResult. Concrete arches (anything other than noarch/src/empty) are
// used to determine arch-specific vs. all-arch.
func summarizePackageArches(name string, advs map[string]map[string]struct{}, notes string) *SourceResult {
	concreteUniverse := map[string]struct{}{}
	for _, set := range advs {
		for a := range set {
			if a == "" || a == "noarch" || a == "src" {
				continue
			}
			concreteUniverse[a] = struct{}{}
		}
	}
	universeN := len(concreteUniverse)
	perArch := map[string]int{}
	perArchExclusive := map[string]int{}
	archSpecific := 0
	noarchOnly := 0
	allArch := 0
	singleArch := 0
	for _, set := range advs {
		concrete := map[string]struct{}{}
		hasNoOrSrc := false
		for a := range set {
			switch a {
			case "":
				continue
			case "noarch", "src":
				hasNoOrSrc = true
				continue
			}
			concrete[a] = struct{}{}
			perArch[a]++
		}
		switch {
		case len(concrete) == 0 && hasNoOrSrc:
			noarchOnly++
		case len(concrete) == universeN && universeN > 0:
			allArch++
		case len(concrete) > 0:
			archSpecific++
			if len(concrete) == 1 {
				singleArch++
				for a := range concrete {
					perArchExclusive[a]++
				}
			}
		}
	}
	return &SourceResult{
		Source:            name,
		UpstreamSupported: keysSorted(concreteUniverse),
		TotalAdvisories:   len(advs),
		ArchSpecificCount: archSpecific,
		SingleArchCount:   singleArch,
		NoarchOnlyCount:   noarchOnly,
		AllArchCount:      allArch,
		PerArchAdvisories: perArch,
		PerArchOnlyExcl:   perArchExclusive,
		Notes:             notes,
	}
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// boundedGroup is a tiny semaphore-bounded WaitGroup that swallows errors,
// used to parallelize HTTP fetches.
type boundedGroup struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func newBoundedGroup(n int) *boundedGroup {
	return &boundedGroup{sem: make(chan struct{}, n)}
}

func (b *boundedGroup) Go(f func() error) {
	b.sem <- struct{}{}
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() { <-b.sem }()
		if err := f(); err != nil {
			log.Printf("bg task error: %v", err)
		}
	}()
}

func (b *boundedGroup) Wait() { b.wg.Wait() }

// errgroupConcurrency returns a boundedGroup with the requested parallelism.
func errgroupConcurrency(n int) (*boundedGroup, struct{}) {
	return newBoundedGroup(n), struct{}{}
}

// --------------------- runner ---------------------

func main() {
	only := flag.String("only", "", "comma-separated subset: alpine,amazon,alma,rocky,redhat-oval,openeuler,suse-cvrf,redhat-csaf-vex")
	outDir := flag.String("out", "scripts/arch-analysis/out", "output directory")
	examples := flag.String("examples", "", "comma-separated sources to extract example advisory IDs (suse,redhat-csaf-vex)")
	examplesPer := flag.Int("examples-per", 3, "max number of examples per category in -examples mode")
	deepdive := flag.String("deepdive", "", "comma-separated sources for NVR-aware deep dive (redhat-oval,redhat-csaf-vex,suse-cvrf or 'all')")
	flag.Parse()

	if *deepdive != "" {
		runDeepDive(strings.Split(*deepdive, ","))
		return
	}

	if *examples != "" {
		ex := findExamples(strings.Split(*examples, ","), *examplesPer)
		_ = os.MkdirAll(*outDir, 0o755)
		out, _ := json.MarshalIndent(ex, "", "  ")
		f, _ := os.Create(filepath.Join(*outDir, "examples.json"))
		_, _ = f.Write(out)
		_, _ = f.Write([]byte("\n"))
		f.Close()
		fmt.Println(string(out))
		return
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}

	allRunners := map[string]func() (*SourceResult, error){
		"alpine":          analyzeAlpine,
		"amazon":          analyzeAmazon,
		"alma":            analyzeAlma,
		"rocky":           analyzeRocky,
		"redhat-oval":     analyzeRedhatOVAL,
		"openeuler":       analyzeOpenEuler,
		"suse-cvrf":       analyzeSUSECVRF,
		"redhat-csaf-vex": analyzeRedhatCSAFVEX,
	}

	var keys []string
	if *only == "" {
		for k := range allRunners {
			keys = append(keys, k)
		}
	} else {
		keys = strings.Split(*only, ",")
	}
	sort.Strings(keys)

	results := make([]*SourceResult, 0, len(keys))
	for _, k := range keys {
		fn, ok := allRunners[k]
		if !ok {
			log.Printf("unknown source %q", k)
			continue
		}
		log.Printf("=== %s ===", k)
		start := time.Now()
		r, err := fn()
		if err != nil {
			log.Printf("%s failed: %v", k, err)
			continue
		}
		log.Printf("%s done in %s (total=%d, arch-specific=%d)", k, time.Since(start), r.TotalAdvisories, r.ArchSpecificCount)
		results = append(results, r)
		// persist per-source as pretty JSON for easy editor viewing
		body, _ := json.MarshalIndent(r, "", "  ")
		f, _ := os.Create(filepath.Join(*outDir, k+".json"))
		_, _ = f.Write(body)
		_, _ = f.Write([]byte("\n"))
		f.Close()
	}

	// summary markdown
	fmt.Println()
	fmt.Println("| Source | Total advisories | Arch-restricted (strict subset) | Single-arch only | All-arch | noarch-only | % arch-restricted | % single-arch | Upstream arches |")
	fmt.Println("|---|---|---|---|---|---|---|---|---|")
	for _, r := range results {
		pctR, pctS := 0.0, 0.0
		if r.TotalAdvisories > 0 {
			pctR = 100 * float64(r.ArchSpecificCount) / float64(r.TotalAdvisories)
			pctS = 100 * float64(r.SingleArchCount) / float64(r.TotalAdvisories)
		}
		fmt.Printf("| %s | %d | %d | %d | %d | %d | %.1f%% | %.1f%% | %s |\n",
			r.Source, r.TotalAdvisories, r.ArchSpecificCount, r.SingleArchCount,
			r.AllArchCount, r.NoarchOnlyCount, pctR, pctS,
			strings.Join(r.UpstreamSupported, ", "))
	}
	fmt.Println()
	for _, r := range results {
		fmt.Printf("\n### %s — per-arch advisory counts\n\n", r.Source)
		fmt.Println("| Arch | Advisories that include this arch | Advisories that target only this arch |")
		fmt.Println("|---|---|---|")
		arches := make([]string, 0, len(r.PerArchAdvisories))
		for a := range r.PerArchAdvisories {
			arches = append(arches, a)
		}
		sort.Strings(arches)
		for _, a := range arches {
			fmt.Printf("| %s | %d | %d |\n", a, r.PerArchAdvisories[a], r.PerArchOnlyExcl[a])
		}
	}
}
