package profile

// Response must implement the Profile and
// IssueInformation interfaces.
var (
	_ Profile          = Response{}
	_ IssueInformation = Response{}
)

// Response represents a passive response profile.
type Response struct {
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

// GetSteps implements Profile.
func (p Response) GetSteps() []Step {
	panic("unimplemented")
}

// GetName returns the name of the response profile.
func (p Response) GetName() string {
	return p.Name
}

// GetType returns the type of the response profile.
func (p Response) GetType() Type {
	return p.Type
}

// IsEnabled returns whether the response profile is enabled.
func (p Response) IsEnabled() bool {
	return p.Enabled
}

// GetTags returns the tags of the response profile.
func (p Response) GetTags() []string {
	return p.Tags
}

// GetIssueName returns the issue name associated with the response profile.
func (p Response) GetIssueName() string {
	return p.IssueName
}

// GetIssueSeverity returns the issue severity associated with the response profile.
func (p Response) GetIssueSeverity() string {
	return p.IssueSeverity
}

// GetIssueConfidence returns the issue confidence associated with the response profile.
func (p Response) GetIssueConfidence() string {
	return p.IssueConfidence
}

// GetIssueDetail returns the issue detail associated with the response profile.
func (p Response) GetIssueDetail() string {
	return p.IssueDetail
}

// GetIssueBackground returns the issue background associated with the response profile.
func (p Response) GetIssueBackground() string {
	return p.IssueBackground
}

// GetRemediationDetail returns the remediation detail associated with the response profile.
func (p Response) GetRemediationDetail() string {
	return p.RemediationDetail
}

// GetRemediationBackground returns the remediation background associated with the response profile.
func (p Response) GetRemediationBackground() string {
	return p.RemediationBackground
}

// GrepAt returns the grep at the given index.
// In case the index is out of range, or the format is invalid,
// an error is returned.
func (p Response) GrepAt(idx int, rr map[string]string) (Grep, error) {
	if idx >= len(p.Greps) {
		return Grep{}, ErrInvalidGrepIdx
	}

	return GrepFromString(p.Greps[idx], rr, false)
}
