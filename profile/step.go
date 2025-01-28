package profile

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/bountysecurity/gbounty/profile/encode"
)

// Step must implement the IssueInformation interface.
var _ IssueInformation = Step{}

// Step represents a single step, part of an Active profile.
type Step struct {
	RequestType          RequestType          `json:"request_type"`
	InsertionPoint       InsertionPointMode   `json:"insertion_point"`
	RawRequest           string               `json:"raw_request"`
	Payloads             []string             `json:"payloads"`
	PayloadPosition      PayloadPosition      `json:"payload_position"`
	ChangeHTTPMethod     bool                 `json:"change_http_request"`
	ChangeHTTPMethodType ChangeHTTPMethodType `json:"change_http_request_type"`
	InsertionPoints      []InsertionPointType `json:"insertion_points"`
	CustomHeaders        []string             `json:"new_headers"`
	MatchAndReplaces     []MatchAndReplace    `json:"match_replace"`
	Encoder              []string             `json:"encoder"`
	URLEncode            bool                 `json:"url_encode"`
	CharsToURLEncode     string               `json:"chars_to_url_encode"`
	Greps                []string             `json:"grep"`
	RedirType            string               `json:"redir_type"`
	MaxRedir             int                  `json:"max_redir"`

	// Issue information
	ShowAlert             ShowAlertType `json:"show_alert"`
	IssueName             string        `json:"issue_name"`
	IssueSeverity         string        `json:"issue_severity"`
	IssueConfidence       string        `json:"issue_confidence"`
	IssueDetail           string        `json:"issue_detail"`
	RemediationDetail     string        `json:"remediation_detail"`
	IssueBackground       string        `json:"issue_background"`
	RemediationBackground string        `json:"remediation_background"`
}

// InsertionPointEnabled returns true if the step has the given
// insertion point enabled.
//
// The method parameter is used to make the decision based on the
// HTTP method and ChangeHTTPMethodType.
func (s Step) InsertionPointEnabled(ipt InsertionPointType, method string) bool {
	for _, enabledIPT := range s.InsertionPoints {
		switch {
		// POST to GET
		case s.PostToGet() && method == http.MethodPost:
			// Only these two are relevant here:
			//nolint:exhaustive
			switch enabledIPT {
			case ParamURLName:
				enabledIPT = ParamBodyName
			case ParamURLValue:
				enabledIPT = ParamBodyValue
			}

		// GET to POST
		case s.GetToPost() && method == http.MethodGet:
			// Only these two are relevant here:
			//nolint:exhaustive
			switch enabledIPT {
			case ParamBodyName:
				enabledIPT = ParamURLName
			case ParamBodyValue:
				enabledIPT = ParamURLValue
			}

		// GET <=> POST
		case s.SwapGetAndPost() && (method == http.MethodGet || method == http.MethodPost):
			// Only these four are relevant here:
			//nolint:exhaustive
			switch enabledIPT {
			case ParamURLName:
				enabledIPT = ParamBodyName
			case ParamURLValue:
				enabledIPT = ParamBodyValue
			case ParamBodyName:
				enabledIPT = ParamURLName
			case ParamBodyValue:
				enabledIPT = ParamURLValue
			}
		}

		if enabledIPT == ipt {
			return true
		}
	}

	return false
}

// PayloadAt returns the payload at the given index, and whether it is
// enabled or not. In case the index is out of range, or the format is invalid,
// an error is returned.
func (s Step) PayloadAt(idx int) (bool, string, error) {
	if s.RequestType.RawRequest() {
		return false, "", nil
	}

	if idx < 0 || idx >= len(s.Payloads) {
		return false, "", ErrInvalidPayloadIdx
	}

	commaIdx := strings.Index(s.Payloads[idx], ",")
	if commaIdx < 0 {
		return false, "", ErrInvalidPayloadFormat
	}

	enabled, err := strconv.ParseBool(s.Payloads[idx][:commaIdx])
	if err != nil {
		return false, "", ErrInvalidPayloadBool
	}

	return enabled, s.Payloads[idx][commaIdx+1:], nil
}

// PayloadAtEncoded is the equivalent of PayloadAt,
// but it returns the Payload encoded, if so.
func (s Step) PayloadAtEncoded(idx int) (bool, string, error) {
	if s.RequestType.RawRequest() {
		return false, "", nil
	}

	enabled, raw, err := s.PayloadAt(idx)
	if err != nil {
		return enabled, raw, err
	}

	return enabled, s.encode(raw), nil
}

type encoding string

const (
	typeEncodeKeyURL     encoding = "URL-encode key characters"
	typeEncodeURL        encoding = "URL-encode all characters"
	typeEncodeUnicodeURL encoding = "URL-encode all characters (Unicode)"
	typeEncodeKeyHTML    encoding = "HTML-encode key characters"
	typeEncodeHTML       encoding = "HTML-encode all characters"
	typeEncodeBase64     encoding = "Base64-encode"
)

func (s Step) encode(payload string) string {
	for _, enc := range s.Encoder {
		switch encoding(enc) {
		case typeEncodeKeyURL:
			payload = encode.KeyURL(payload)
		case typeEncodeURL:
			payload = encode.URL(payload)
		case typeEncodeUnicodeURL:
			payload = encode.UnicodeURL(payload)
		case typeEncodeKeyHTML:
			payload = encode.KeyHTML(payload)
		case typeEncodeHTML:
			payload = encode.HTML(payload)
		case typeEncodeBase64:
			payload = encode.Base64(payload)
		}
	}

	if s.URLEncode {
		payload = encode.TheseURL(payload, s.CharsToURLEncode)
	}

	return payload
}

// MaxRedirects is a helper function that
// returns the maximum number of redirects to follow.
func (s Step) MaxRedirects() int {
	return s.MaxRedir
}

// RedirectType is a helper function that returns
// the allowed redirect type based on the profile.
func (s Step) RedirectType() Redirect {
	switch s.RedirType {
	case "on site":
		return RedirectOnSite
	case "always":
		return RedirectAlways
	case "never":
		return RedirectNever
	default:
		return RedirectNever
	}
}

// PostToGet returns false if ChangeHTTPMethod is false.
// Otherwise, returns p.ChangeHTTPMethodType.PostToGet().
func (s Step) PostToGet() bool {
	if !s.ChangeHTTPMethod {
		return false
	}

	return s.ChangeHTTPMethodType.PostToGet()
}

// GetToPost returns false if ChangeHTTPMethod is false.
// Otherwise, returns p.ChangeHTTPMethodType.GetToPost().
func (s Step) GetToPost() bool {
	if !s.ChangeHTTPMethod {
		return false
	}

	return s.ChangeHTTPMethodType.GetToPost()
}

// SwapGetAndPost returns false if ChangeHTTPMethod is false.
// Otherwise, returns p.ChangeHTTPMethodType.SwapGetAndPost().
func (s Step) SwapGetAndPost() bool {
	if !s.ChangeHTTPMethod {
		return false
	}

	return s.ChangeHTTPMethodType.SwapGetAndPost()
}

// GrepAt returns the grep at the given index.
// In case the index is out of range, or the format is invalid,
// an error is returned.
func (s Step) GrepAt(idx int, rr map[string]string) (Grep, error) {
	if idx >= len(s.Greps) {
		return Grep{}, ErrInvalidGrepIdx
	}

	return GrepFromString(s.Greps[idx], rr, false)
}

// HasBHGrepType returns true if the step has a [GrepTypeBlindHost] grep.
func (s Step) HasBHGrepType() bool {
	for idx := range s.Greps {
		// No replacements are required for [GrepTypeBlindHost].
		grep, err := s.GrepAt(idx, nil)
		if err != nil {
			continue
		}

		if grep.Type == GrepTypeBlindHost {
			return true
		}
	}

	return false
}

// GetIssueName returns the issue name associated with the step.
func (s Step) GetIssueName() string {
	return s.IssueName
}

// GetIssueSeverity returns the issue severity associated with the step.
func (s Step) GetIssueSeverity() string {
	return s.IssueSeverity
}

// GetIssueConfidence returns the issue confidence associated with the step.
func (s Step) GetIssueConfidence() string {
	return s.IssueConfidence
}

// GetIssueDetail returns the issue detail associated with the step.
func (s Step) GetIssueDetail() string {
	return s.IssueDetail
}

// GetIssueBackground returns the issue background associated with the step.
func (s Step) GetIssueBackground() string {
	return s.IssueBackground
}

// GetRemediationDetail returns the remediation detail associated with the step.
func (s Step) GetRemediationDetail() string {
	return s.RemediationDetail
}

// GetRemediationBackground returns the remediation background associated with the step.
func (s Step) GetRemediationBackground() string {
	return s.RemediationBackground
}

const (
	OriginalRequest RequestType = "original"
	RawRequest      RequestType = "raw_request"
)

// RequestType represents the type of request.
type RequestType string

// OriginalRequest returns true if the request type is original.
func (rt RequestType) OriginalRequest() bool {
	return rt == OriginalRequest
}

// RawRequest returns true if the request type is raw.
func (rt RequestType) RawRequest() bool {
	return rt == RawRequest
}
