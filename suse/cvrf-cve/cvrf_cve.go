package cvrfcve

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/vuln-list-update/utils"
)

var (
	cvrfCVEURL = "http://ftp.suse.com/pub/projects/security/cvrf-cve/"
	fileRegexp = regexp.MustCompile(`<a href="(cvrf-(CVE-\d{4}-\d+)\.xml)">.*`)
	retry      = 5
	// Keep concurrency modest: many large XML bodies at once can OOM GitHub-hosted runners.
	fetchConcurrency = 8
	fetchBatchSize   = 250
	wait             = 1
	cvrfDir          = "cvrf"
	suseCVEDir       = "suse-cves"
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         cvrfCVEURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CVE CVRF data...")

	res, err := utils.FetchURL(c.URL, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("cannot download SUSE CVE CVRF list: %w", err)
	}

	cveURLs := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(res))
	for scanner.Scan() {
		line := scanner.Text()
		if match := fileRegexp.FindStringSubmatch(line); len(match) != 0 {
			cveURLs[match[2]] = c.URL + match[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return xerrors.Errorf("failed reading SUSE CVE CVRF list: %w", err)
	}

	urls := make([]string, 0, len(cveURLs))
	for _, u := range cveURLs {
		urls = append(urls, u)
	}

	log.Printf("Saving %d SUSE CVE CVRF documents (batches of %d)...", len(urls), fetchBatchSize)
	bar := pb.StartNew(len(urls))
	for start := 0; start < len(urls); start += fetchBatchSize {
		end := start + fetchBatchSize
		if end > len(urls) {
			end = len(urls)
		}
		batch := urls[start:end]
		log.Printf("SUSE CVE CVRF fetch batch %d-%d of %d", start+1, end, len(urls))
		bodies, err := utils.FetchConcurrently(batch, fetchConcurrency, wait, c.Retry)
		if err != nil {
			log.Printf("batch fetch warning (SUSE CVE CVRF): %s", err)
		}
		for _, cvrfXML := range bodies {
			var cv Cvrf
			if len(cvrfXML) == 0 {
				log.Println("empty CVE CVRF xml")
				bar.Increment()
				continue
			}

			if !utf8.Valid(cvrfXML) {
				log.Println("invalid UTF-8")
				cvrfXML = []byte(strings.ToValidUTF8(string(cvrfXML), ""))
			}

			if err = xml.Unmarshal(cvrfXML, &cv); err != nil {
				return xerrors.Errorf("failed to decode SUSE CVE CVRF XML: %w", err)
			}

			cveID := extractCVEID(cv)
			if cveID == "" {
				log.Printf("invalid CVE CVRF document ID: %s", cv.Tracking.ID)
				bar.Increment()
				continue
			}

			if err = c.saveCVEPerYear(cveID, cv); err != nil {
				return xerrors.Errorf("failed to save SUSE CVE CVRF: %w", err)
			}
			bar.Increment()
		}
	}
	bar.Finish()
	return nil
}

func extractCVEID(cv Cvrf) string {
	for _, v := range cv.Vulnerabilities {
		cve := strings.TrimSpace(v.CVE)
		if cve != "" {
			return cve
		}
	}
	return strings.TrimSpace(cv.Title)
}

func (c Config) saveCVEPerYear(cveID string, data interface{}) error {
	s := strings.Split(cveID, "-")
	if len(s) < 3 {
		return nil
	}

	yearDir := filepath.Join(c.VulnListDir, cvrfDir, suseCVEDir, s[1])
	fileName := fmt.Sprintf("%s.json", cveID)
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
