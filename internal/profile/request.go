package profile

// Request must implement the Profile and
// IssueInformation interfaces.
var (
	_ Profile          = Request{}
	_ IssueInformation = Request{}
)

// Request represents a passive request profile.
type Request struct {
	// Basic information
	Name    string   `json:"profile_name"`
	Enabled bool     `json:"enabled"`
	Type    Type     `json:"scanner"`
	Author  string   `json:"author"`
	Tags    []string `json:"Tags"`

	Greps []string `json:"grep"`

	// Issue information
	IssueName             string `json:"issue_name"`
	IssueSeverity         string `json:"issue_severity"`
	IssueConfidence       string `json:"issue_confidence"`
	IssueDetail           string `json:"issue_detail"`
	RemediationDetail     string `json:"remediation_detail"`
	IssueBackground       string `json:"issue_background"`
	RemediationBackground string `json:"remediation_background"`
}

// GetName returns the name of the request profile.
func (r Request) GetName() string {
	return r.Name
}

// GetType returns the type of the request profile.
func (r Request) GetType() Type {
	return r.Type
}

// IsEnabled returns whether the request profile is enabled.
func (r Request) IsEnabled() bool {
	return r.Enabled
}

// GetTags returns the tags of the request profile.
func (r Request) GetTags() []string {
	return r.Tags
}

// GetIssueName returns the issue name associated with the request profile.
func (r Request) GetIssueName() string {
	return r.IssueName
}

// GetIssueSeverity returns the issue severity associated with the request profile.
func (r Request) GetIssueSeverity() string {
	return r.IssueSeverity
}

// GetIssueConfidence returns the issue confidence associated with the request profile.
func (r Request) GetIssueConfidence() string {
	return r.IssueConfidence
}

// GetIssueDetail returns the issue detail associated with the request profile.
func (r Request) GetIssueDetail() string {
	return r.IssueDetail
}

// GetIssueBackground returns the issue background associated with the request profile.
func (r Request) GetIssueBackground() string {
	return r.IssueBackground
}

// GetRemediationDetail returns the remediation detail associated with the request profile.
func (r Request) GetRemediationDetail() string {
	return r.RemediationDetail
}

// GetRemediationBackground returns the remediation background associated with the request profile.
func (r Request) GetRemediationBackground() string {
	return r.RemediationBackground
}

// GrepAt returns the grep at the given index.
// In case the index is out of range, or the format is invalid,
// an error is returned.
func (r Request) GrepAt(idx int, rr map[string]string) (Grep, error) {
	if idx >= len(r.Greps) {
		return Grep{}, ErrInvalidGrepIdx
	}

	return GrepFromString(r.Greps[idx], rr, true)
}

func (r Request) GetSteps() []Step {
	return nil
}
