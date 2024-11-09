package profile

import (
	"errors"
)

const unknown = "Unknown"

var (
	ErrInvalidPayloadIdx    = errors.New("invalid payload index")
	ErrInvalidPayloadBool   = errors.New("invalid payload bool")
	ErrInvalidPayloadFormat = errors.New("invalid payload format")

	ErrInvalidGrepIdx = errors.New("invalid grep index")
)

type SeverityGetter interface {
	GetSeverity() string
}

func (r *Request) GetSeverity() string {
	return r.IssueSeverity
}

func (r *Response) GetSeverity() string {
	return r.IssueSeverity
}

func (a *Active) GetSeverity() string {
	if len(a.GetSteps()) > 0 {
		return a.GetSteps()[0].IssueSeverity
	}
	return ""
}

// Profile represents the behavior expected from a scan profile.
// It can be a passive or active profile (e.g. Active).
type Profile interface {
	GetName() string
	GetType() Type
	IsEnabled() bool
	GetTags() []string
	GetSteps() []Step
}

// IssueInformation represents the information of an issue.
// It can be part of a step (active) or a scan profile (passive).
type IssueInformation interface {
	GetIssueName() string
	GetIssueSeverity() string
	GetIssueConfidence() string
	GetIssueDetail() string
	GetIssueBackground() string
	GetRemediationDetail() string
	GetRemediationBackground() string
}
