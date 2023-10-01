package profile

// MatchAndReplace represents a match and replace operation.
type MatchAndReplace struct {
	Type    MatchAndReplaceType  `json:"type"`
	Match   string               `json:"match"`
	Replace string               `json:"replace"`
	Regex   MatchAndReplaceRegex `json:"regex"`
}

const (
	MatchAndReplaceRequest MatchAndReplaceType = "Request"
	MatchAndReplacePayload MatchAndReplaceType = "Payload"
)

// MatchAndReplaceType represents the type of match and replace operation.
type MatchAndReplaceType string

// Request returns true if the match and replace operation is for the request.
func (t MatchAndReplaceType) Request() bool {
	return t == MatchAndReplaceRequest
}

// Payload returns true if the match and replace operation is for the payload.
func (t MatchAndReplaceType) Payload() bool {
	return t == MatchAndReplacePayload
}

const (
	MatchAndReplaceString MatchAndReplaceRegex = "String"
	MatchAndReplaceRegexp MatchAndReplaceRegex = "Regex"
)

// MatchAndReplaceRegex represents the type of match and replace operation.
type MatchAndReplaceRegex string

// String returns true if the match and replace operation is for a string.
func (r MatchAndReplaceRegex) String() bool {
	return r == MatchAndReplaceString
}

// Regex returns true if the match and replace operation is for a regular expression.
func (r MatchAndReplaceRegex) Regex() bool {
	return r == MatchAndReplaceRegexp
}
