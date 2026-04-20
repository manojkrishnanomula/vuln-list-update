package cvrfcve

type Cvrf struct {
	Title           string           `xml:"DocumentTitle"`
	Tracking        DocumentTracking `xml:"DocumentTracking"`
	Notes           []DocumentNote   `xml:"DocumentNotes>Note"`
	References      []Reference      `xml:"DocumentReferences>Reference"`
	Vulnerabilities []Vulnerability  `xml:"Vulnerability"`
}

type DocumentTracking struct {
	ID                 string     `xml:"Identification>ID"`
	Status             string     `xml:"Status"`
	Version            string     `xml:"Version"`
	InitialReleaseDate string     `xml:"InitialReleaseDate"`
	CurrentReleaseDate string     `xml:"CurrentReleaseDate"`
	RevisionHistory    []Revision `xml:"RevisionHistory>Revision"`
}

type DocumentNote struct {
	Text  string `xml:",chardata"`
	Title string `xml:"Title,attr"`
	Type  string `xml:"Type,attr"`
}

type Revision struct {
	Number      string `xml:"Number"`
	Date        string `xml:"Date"`
	Description string `xml:"Description"`
}

type Vulnerability struct {
	CVE             string        `xml:"CVE"`
	Description     string        `xml:"Notes>Note"`
	Threats         []Threat      `xml:"Threats>Threat"`
	References      []Reference   `xml:"References>Reference"`
	ProductStatuses []Status      `xml:"ProductStatuses>Status"`
	CVSSScoreSets   CVSSScoreSets `xml:"CVSSScoreSets" json:",omitempty"`
}

type Threat struct {
	Type     string `xml:"Type,attr"`
	Severity string `xml:"Description"`
}

type Reference struct {
	URL         string `xml:"URL"`
	Description string `xml:"Description"`
}

type Status struct {
	Type      string   `xml:"Type,attr"`
	ProductID []string `xml:"ProductID"`
}

type CVSSScoreSets struct {
	ScoreSetV2 []ScoreSetV2 `xml:"ScoreSetV2" json:",omitempty"`
	ScoreSetV3 []ScoreSetV3 `xml:"ScoreSetV3" json:",omitempty"`
}

type ScoreSetV2 struct {
	BaseScoreV2 string `xml:"BaseScoreV2" json:",omitempty"`
	VectorV2    string `xml:"VectorV2" json:",omitempty"`
}

type ScoreSetV3 struct {
	BaseScoreV3 string `xml:"BaseScoreV3" json:",omitempty"`
	VectorV3    string `xml:"VectorV3" json:",omitempty"`
}
