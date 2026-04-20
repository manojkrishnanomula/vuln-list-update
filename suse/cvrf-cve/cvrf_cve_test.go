package cvrfcve_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cvrfcve "github.com/aquasecurity/vuln-list-update/suse/cvrf-cve"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		xmlFileNames     map[string]string
		expectedFile     string
		expectedErrorMsg string
	}{
		{
			name:  "positive test",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf-cve/":                        "testdata/cvrf-cve-list.html",
				"/pub/projects/security/cvrf-cve/cvrf-CVE-2014-6271.xml":  "testdata/cvrf-CVE-2014-6271.xml",
				"/pub/projects/security/cvrf-cve/cvrf-CVE-1234-12345.xml": "testdata/cvrf-CVE-1234-12345.xml",
			},
			expectedFile: "/tmp/cvrf/suse-cves/2014/CVE-2014-6271.json",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			xmlFileNames: map[string]string{
				"/pub/projects/security/cvrf-cve/":                       "testdata/cvrf-cve-list-invalid-single.html",
				"/pub/projects/security/cvrf-cve/cvrf-CVE-2014-6271.xml": "testdata/broken-cvrf-data.xml",
			},
			expectedErrorMsg: "failed to decode SUSE CVE CVRF XML",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filePath, ok := tc.xmlFileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()

			c := cvrfcve.Config{
				VulnListDir: "/tmp",
				URL:         ts.URL + "/pub/projects/security/cvrf-cve/",
				AppFs:       tc.appFs,
				Retry:       0,
			}
			err := c.Update()
			if tc.expectedErrorMsg != "" {
				require.Error(t, err, tc.name)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			}
			require.NoError(t, err, tc.name)

			b, err := afero.ReadFile(c.AppFs, tc.expectedFile)
			require.NoError(t, err, tc.name)
			assert.Contains(t, string(b), `"CVE": "CVE-2014-6271"`)
			assert.Contains(t, string(b), `"BaseScoreV3": "9.8"`)
		})
	}
}
