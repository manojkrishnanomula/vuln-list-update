// Standalone helper that finds concrete advisory IDs in each source to use
// as illustrative examples in documentation. Run with:
//
//	go run ./scripts/arch-analysis -examples all
//	go run ./scripts/arch-analysis -examples alpine,amazon,alma,rocky,redhat-oval,redhat-csaf-vex,openeuler,suse-cvrf
//
// Output is a JSON document printed to stdout listing one or more example
// advisory IDs per arch-set category, per source. This is separate from the
// statistical run in main.go.
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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/PuerkitoBio/goquery"
	"github.com/klauspost/compress/zstd"

	almatypes "github.com/aquasecurity/vuln-list-update/alma"
	amazontypes "github.com/aquasecurity/vuln-list-update/amazon"
	openeulertypes "github.com/aquasecurity/vuln-list-update/openeuler"
	rhovaltypes "github.com/aquasecurity/vuln-list-update/redhat/oval"
	rockytypes "github.com/aquasecurity/vuln-list-update/rocky"
	susetypes "github.com/aquasecurity/vuln-list-update/suse/cvrf"
)

// findExamples is invoked by main when -examples is set. It returns a map
// of source -> category -> []advisoryID samples.
func findExamples(sources []string, perCategory int) map[string]map[string][]string {
	if len(sources) == 1 && sources[0] == "all" {
		sources = []string{
			"alpine", "amazon", "alma", "rocky",
			"redhat-oval", "redhat-csaf-vex",
			"openeuler", "suse-cvrf",
		}
	}
	out := map[string]map[string][]string{}
	for _, s := range sources {
		switch s {
		case "alpine":
			out["alpine"] = findAlpineExamples(perCategory)
		case "amazon":
			out["amazon"] = findAmazonExamples(perCategory)
		case "alma":
			out["alma"] = findAlmaExamples(perCategory)
		case "rocky":
			out["rocky"] = findRockyExamples(perCategory)
		case "redhat-oval", "rhoval":
			out["redhat-oval"] = findRHOVALExamples(perCategory)
		case "openeuler":
			out["openeuler"] = findOpenEulerExamples(perCategory)
		case "suse", "suse-cvrf":
			out["suse-cvrf"] = findSUSEExamples(perCategory)
		case "redhat-csaf-vex", "rhvex":
			out["redhat-csaf-vex"] = findRHCSAFExamples(perCategory)
		default:
			log.Printf("examples: unknown source %q", s)
		}
	}
	return out
}

// classify is a shared helper that buckets an advisory by its concrete arch
// set into single-<arch>, multi-arch, all-major, or noarch-only categories,
// adding the formatted line to cats with a per-bucket cap of `per`.
func classify(cats map[string][]string, line string, concrete map[string]struct{}, hasNoarch bool, per int) {
	switch {
	case len(concrete) == 0 && hasNoarch:
		appendCapped(cats, "noarch-only", line, per)
	case len(concrete) == 1:
		var only string
		for a := range concrete {
			only = a
		}
		appendCapped(cats, "single-"+only, line, per)
	case len(concrete) >= 5:
		appendCapped(cats, "all-major", line, per)
	case len(concrete) >= 2:
		appendCapped(cats, "multi-arch", line, per)
	}
}

func appendCapped(cats map[string][]string, key, line string, per int) {
	if len(cats[key]) >= per {
		return
	}
	cats[key] = append(cats[key], line)
}

// fmtLine formats a single example line with stable arch ordering.
func fmtLine(id string, concrete map[string]struct{}, src string) string {
	arches := make([]string, 0, len(concrete))
	for a := range concrete {
		arches = append(arches, a)
	}
	sort.Strings(arches)
	if src == "" {
		return fmt.Sprintf("%s [arches=%s]", id, strings.Join(arches, ","))
	}
	return fmt.Sprintf("%s [arches=%s] (%s)", id, strings.Join(arches, ","), src)
}

func findSUSEExamples(per int) map[string][]string {
	base := "https://ftp.suse.com/pub/projects/security/cvrf/"
	idx, err := getBytes(base)
	if err != nil {
		log.Printf("suse index: %v", err)
		return nil
	}
	re := regexp.MustCompile(`<a href="(cvrf-[^"]+\.xml)"`)
	matches := re.FindAllStringSubmatch(string(idx), -1)
	files := make([]string, 0, len(matches))
	for _, m := range matches {
		files = append(files, m[1])
	}
	log.Printf("[suse-examples] %d files", len(files))

	type sample struct {
		ID       string
		File     string
		ArchSet  []string
		Concrete []string
	}
	cats := map[string][]sample{
		"single-x86_64": nil,
		"single-arm64":  nil,
		"single-i386":   nil,
		"single-ppc64":  nil,
		"multi-arch":    nil,
		"all-major":     nil,
	}
	var mu sync.Mutex
	var done int64
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
				id = strings.TrimSuffix(f, ".xml")
			}
			set := map[string]struct{}{}
			for _, r := range cv.ProductTree.Relationships {
				for _, s := range []string{r.ProductReference, r.RelatesToProductReference} {
					for _, a := range detectArchTokens(s) {
						set[a] = struct{}{}
					}
				}
			}
			concrete := map[string]struct{}{}
			for a := range set {
				if a == "noarch" || a == "src" {
					continue
				}
				concrete[a] = struct{}{}
			}
			s := sample{
				ID:       id,
				File:     f,
				ArchSet:  keysSorted(set),
				Concrete: keysSorted(concrete),
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case len(concrete) == 1:
				for a := range concrete {
					cat := "single-" + a
					if _, ok := cats[cat]; ok && len(cats[cat]) < per {
						cats[cat] = append(cats[cat], s)
					}
				}
			case len(concrete) >= 5:
				if len(cats["all-major"]) < per {
					cats["all-major"] = append(cats["all-major"], s)
				}
			case len(concrete) >= 2:
				if len(cats["multi-arch"]) < per {
					cats["multi-arch"] = append(cats["multi-arch"], s)
				}
			}
			return nil
		})
	}
	bg.Wait()

	res := map[string][]string{}
	for cat, samples := range cats {
		ids := make([]string, 0, len(samples))
		for _, s := range samples {
			ids = append(ids, fmt.Sprintf("%s [arches=%s] (%s)", s.ID, strings.Join(s.Concrete, ","), s.File))
		}
		sort.Strings(ids)
		res[cat] = ids
	}
	return res
}

func findRHCSAFExamples(per int) map[string][]string {
	base := "https://security.access.redhat.com/data/csaf/v2/vex/"
	nameB, err := getBytes(base + "archive_latest.txt")
	if err != nil {
		log.Printf("vex name: %v", err)
		return nil
	}
	name := strings.TrimSpace(string(nameB))
	log.Printf("[rh-vex-examples] downloading %s", name)
	body, err := getBytes(base + name)
	if err != nil {
		log.Printf("vex archive: %v", err)
		return nil
	}
	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	purlArchRe := regexp.MustCompile(`[?&]arch=([^&]+)`)

	cats := map[string][]string{
		"single-x86_64":  nil,
		"single-aarch64": nil,
		"single-i386":    nil,
		"single-i686":    nil,
		"single-amd64":   nil,
		"single-ppc64":   nil,
		"multi-arch":     nil,
		"all-major":      nil,
	}
	var n int
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cats
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
		id := doc.Document.Tracking.ID
		if id == "" {
			id = strings.TrimSuffix(filepath.Base(hdr.Name), filepath.Ext(hdr.Name))
		}
		set := map[string]struct{}{}
		walkBranches(doc.ProductTree.Branches, set, purlArchRe)
		concrete := map[string]struct{}{}
		for a := range set {
			concrete[a] = struct{}{}
		}
		switch {
		case len(concrete) == 1:
			for a := range concrete {
				cat := "single-" + a
				if _, ok := cats[cat]; ok && len(cats[cat]) < per {
					cats[cat] = append(cats[cat], fmt.Sprintf("%s [arches=%s] (%s)", id, a, filepath.Base(hdr.Name)))
				}
			}
		case len(concrete) >= 6:
			if len(cats["all-major"]) < per {
				cats["all-major"] = append(cats["all-major"], fmt.Sprintf("%s [arches=%s] (%s)", id, strings.Join(keysSorted(concrete), ","), filepath.Base(hdr.Name)))
			}
		case len(concrete) >= 2:
			if len(cats["multi-arch"]) < per {
				cats["multi-arch"] = append(cats["multi-arch"], fmt.Sprintf("%s [arches=%s] (%s)", id, strings.Join(keysSorted(concrete), ","), filepath.Base(hdr.Name)))
			}
		}
		n++
		if n%50000 == 0 {
			log.Printf("[rh-vex-examples] processed %d advisories", n)
		}
	}
	return cats
}

// ---------------- ALPINE EXAMPLES ----------------
//
// Alpine's arch is per-secdb-file; we report one example per `archs` set.
func findAlpineExamples(per int) map[string][]string {
	baseURL := "https://secdb.alpinelinux.org/"
	idx, err := getBytes(baseURL)
	if err != nil {
		return nil
	}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader(idx))
	var releases []string
	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSuffix(s.Text(), "/")
		if strings.HasPrefix(text, "v") || strings.HasPrefix(text, "edge") {
			releases = append(releases, text)
		}
	})

	type secdb struct {
		Archs []string `json:"archs"`
	}
	cats := map[string][]string{}
	seenSet := map[string]bool{} // dedupe by joined arch set
	for _, release := range releases {
		relURL := baseURL + release + "/"
		idx, err := getBytes(relURL)
		if err != nil {
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
				continue
			}
			var sd secdb
			if err = json.Unmarshal(b, &sd); err != nil {
				continue
			}
			concrete := map[string]struct{}{}
			for _, a := range sd.Archs {
				concrete[a] = struct{}{}
			}
			key := strings.Join(keysSorted(concrete), ",")
			if seenSet[key] {
				continue
			}
			seenSet[key] = true
			id := fmt.Sprintf("%s/%s", release, strings.TrimSuffix(f, ".json"))
			cat := "all-arch-list"
			if len(concrete) == 1 {
				for a := range concrete {
					cat = "single-" + a
				}
			} else if len(concrete) >= 5 {
				cat = "all-major"
			} else if len(concrete) >= 2 {
				cat = "subset-arch"
			} else if len(concrete) == 0 {
				cat = "no-archs-listed"
			}
			appendCapped(cats, cat, fmtLine(id, concrete, ""), per)
		}
	}
	return cats
}

// ---------------- AMAZON EXAMPLES ----------------
//
// Walk x86_64 + aarch64 mirrors of each AL release; merge per-ALAS arch sets;
// classify by single-/multi-arch.
func findAmazonExamples(per int) map[string][]string {
	mirrors := map[string]string{
		"1":    "http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list",
		"2":    "https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list",
		"2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/x86_64/mirror.list",
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/x86_64/mirror.list",
	}
	aarch := map[string]string{
		"2":    "https://cdn.amazonlinux.com/2/core/latest/aarch64/mirror.list",
		"2022": "https://cdn.amazonlinux.com/al2022/core/mirrors/latest/aarch64/mirror.list",
		"2023": "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list",
	}
	alasArchs := map[string]map[string]struct{}{}
	alasRelease := map[string]string{}
	parse := func(release string, b []byte) {
		var ui amazontypes.UpdateInfo
		if err := xml.Unmarshal(b, &ui); err != nil {
			return
		}
		for _, a := range ui.ALASList {
			set, ok := alasArchs[a.ID]
			if !ok {
				set = map[string]struct{}{}
				alasArchs[a.ID] = set
				alasRelease[a.ID] = release
			}
			for _, p := range a.Packages {
				if p.Arch != "" {
					set[p.Arch] = struct{}{}
				}
			}
		}
	}
	fetch := func(release, mirrorListURL string) {
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
			parse(release, data)
			return
		}
	}
	for v, mirror := range mirrors {
		fetch("AL"+v, mirror)
	}
	for v, mirror := range aarch {
		fetch("AL"+v, mirror)
	}
	cats := map[string][]string{}
	for id, set := range alasArchs {
		concrete := map[string]struct{}{}
		hasNoarch := false
		for a := range set {
			if a == "noarch" || a == "src" {
				hasNoarch = true
				continue
			}
			concrete[a] = struct{}{}
		}
		classify(cats, fmtLine(id, concrete, alasRelease[id]), concrete, hasNoarch, per)
	}
	return cats
}

// ---------------- ALMA EXAMPLES ----------------
func findAlmaExamples(per int) map[string][]string {
	releases := []string{"8", "9", "10"}
	cats := map[string][]string{}
	for _, rel := range releases {
		u := fmt.Sprintf("https://errata.almalinux.org/%s/errata.json", rel)
		b, err := getBytes(u)
		if err != nil {
			continue
		}
		var errata []struct {
			UpdateinfoID string `json:"updateinfo_id"`
			Pkglist      struct {
				Packages []almatypes.Package `json:"packages"`
			} `json:"pkglist"`
		}
		if err := json.Unmarshal(b, &errata); err != nil {
			continue
		}
		for _, e := range errata {
			if !strings.HasPrefix(e.UpdateinfoID, "ALSA-") {
				continue
			}
			concrete := map[string]struct{}{}
			hasNoarch := false
			for _, p := range e.Pkglist.Packages {
				a := p.Arch
				if a == "x86_64_v2" {
					a = "x86_64"
				}
				if a == "noarch" || a == "src" {
					hasNoarch = true
					continue
				}
				concrete[a] = struct{}{}
			}
			classify(cats, fmtLine(e.UpdateinfoID, concrete, "Alma "+rel), concrete, hasNoarch, per)
		}
	}
	return cats
}

// ---------------- ROCKY EXAMPLES ----------------
func findRockyExamples(per int) map[string][]string {
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
	rlsa := map[string]map[string]struct{}{}
	rlsaRel := map[string]string{}
	var rmu sync.Mutex
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
						rmu.Lock()
						defer rmu.Unlock()
						for _, r := range ui.RLSAList {
							set, ok := rlsa[r.ID]
							if !ok {
								set = map[string]struct{}{}
								rlsa[r.ID] = set
								rlsaRel[r.ID] = "Rocky " + rel
							}
							for _, c := range r.Collections {
								for _, p := range c.Packages {
									set[p.Arch] = struct{}{}
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
	cats := map[string][]string{}
	for id, set := range rlsa {
		concrete := map[string]struct{}{}
		hasNoarch := false
		for a := range set {
			if a == "noarch" || a == "src" {
				hasNoarch = true
				continue
			}
			concrete[a] = struct{}{}
		}
		classify(cats, fmtLine(id, concrete, rlsaRel[id]), concrete, hasNoarch, per)
	}
	return cats
}

// ---------------- REDHAT OVAL EXAMPLES ----------------
func findRHOVALExamples(per int) map[string][]string {
	base := "https://security.access.redhat.com/data/oval/v2/"
	manifest, err := getBytes(base + "PULP_MANIFEST")
	if err != nil {
		return nil
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
	advisories := map[string]map[string]struct{}{}
	advisoryFile := map[string]string{}
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
				if _, ok := advisories[vulnID]; !ok {
					advisories[vulnID] = map[string]struct{}{}
					advisoryFile[vulnID] = f
				}
				for a := range archSet {
					advisories[vulnID][a] = struct{}{}
				}
				mu.Unlock()
			}
			return nil
		})
	}
	bg.Wait()
	cats := map[string][]string{}
	for id, set := range advisories {
		concrete := map[string]struct{}{}
		hasNoarch := false
		for a := range set {
			if a == "noarch" || a == "src" {
				hasNoarch = true
				continue
			}
			concrete[a] = struct{}{}
		}
		classify(cats, fmtLine(id, concrete, advisoryFile[id]), concrete, hasNoarch, per)
	}
	return cats
}

// ---------------- OPENEULER EXAMPLES ----------------
func findOpenEulerExamples(per int) map[string][]string {
	base := "https://repo.openeuler.org/security/data/cvrf/"
	idx, err := getBytes(base + "index.txt")
	if err != nil {
		return nil
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
	advisories := map[string]map[string]struct{}{}
	advisoryFile := map[string]string{}
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
			set := map[string]struct{}{}
			for _, br := range cv.ProductTree.Branches {
				if br.Type == "Package Arch" && br.Name != "" {
					set[br.Name] = struct{}{}
				}
			}
			mu.Lock()
			advisories[id] = set
			advisoryFile[id] = e
			mu.Unlock()
			return nil
		})
	}
	bg.Wait()
	cats := map[string][]string{}
	for id, set := range advisories {
		concrete := map[string]struct{}{}
		hasNoarch := false
		for a := range set {
			if a == "noarch" || a == "src" {
				hasNoarch = true
				continue
			}
			concrete[a] = struct{}{}
		}
		classify(cats, fmtLine(id, concrete, advisoryFile[id]), concrete, hasNoarch, per)
	}
	return cats
}
