package oval

import "strings"

type Oval struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	Platform    []string    `xml:"metadata>affected>platform"`
	References  []Reference `xml:"metadata>reference"`
	Criteria    Criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Cves        []Cve       `xml:"metadata>advisory>cve"`
	Issued      Issued      `xml:"metadata>advisory>issued" json:",omitempty"`
}

type Reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type Cve struct {
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr" json:",omitempty"`
	// Oracle encodes each CVSS version as "score/vector" (e.g. cvss3="7.3/CVSS:3.1/AV:N/...").
	CVSS2 string `xml:"cvss2,attr" json:",omitempty"`
	CVSS3 string `xml:"cvss3,attr" json:",omitempty"`
	CVSS4 string `xml:"cvss4,attr" json:",omitempty"`
	// Score and vector are derived from the attributes above (not present in XML).
	CVSS2Score  string `json:",omitempty"`
	CVSS2Vector string `json:",omitempty"`
	CVSS3Score  string `json:",omitempty"`
	CVSS3Vector string `json:",omitempty"`
	CVSS4Score  string `json:",omitempty"`
	CVSS4Vector string `json:",omitempty"`
	ID          string `xml:",chardata"`
}

// SplitOracleCVSSAttr splits Oracle's per-CVE cvss2/cvss3/cvss4 attribute into numeric score and vector string.
func SplitOracleCVSSAttr(s string) (score, vector string) {
	if s == "" {
		return "", ""
	}
	i := strings.Index(s, "/")
	if i < 0 {
		return strings.TrimSpace(s), ""
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
}

// ApplyCVSSDerivedFields sets CVSS{2,3,4}Score and CVSS{2,3,4}Vector from the raw Oracle attributes.
func ApplyCVSSDerivedFields(cves []Cve) {
	for i := range cves {
		cves[i].CVSS2Score, cves[i].CVSS2Vector = SplitOracleCVSSAttr(cves[i].CVSS2)
		cves[i].CVSS3Score, cves[i].CVSS3Vector = SplitOracleCVSSAttr(cves[i].CVSS3)
		cves[i].CVSS4Score, cves[i].CVSS4Vector = SplitOracleCVSSAttr(cves[i].CVSS4)
	}
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*Criteria `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
}

type Issued struct {
	Date string `xml:"date,attr" json:",omitempty"`
}
