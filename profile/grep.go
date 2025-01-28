package profile

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrInvalidGrepEnabled   = errors.New("invalid grep enabled")
	ErrInvalidGrepOperator  = errors.New("invalid grep operator")
	ErrInvalidGrepType      = errors.New("invalid grep type")
	ErrInvalidGrepOption    = errors.New("invalid grep option")
	ErrInvalidStatusCode    = errors.New("invalid status code")
	ErrInvalidTimeDelay     = errors.New("invalid time delay")
	ErrInvalidContentLength = errors.New("invalid content length")
	ErrInvalidURLExtension  = errors.New("invalid url extension")
)

// Grep represents a Grep directive, used to identify matches
// during active and passive scans.
type Grep struct {
	Enabled  bool
	Operator GrepOperator
	Type     GrepType
	Value    GrepValue
	Option   GrepOption
	Where    string // only used for passive profiles (requests)
}

// GrepFromString initializes a Grep instance from a string.
func GrepFromString(s string, rr map[string]string, includeWhere bool) (Grep, error) {
	// We determine the maximum amount of chunks,
	// based on whether the "where" clause is included or not.
	// Because, the value may include commas (","),
	// we cannot just rely on [strings.Split], but set a max.
	//
	// The amount of chunks is either:
	// -> 5, for active and response
	// -> 6, for request
	nChunks := 5
	if includeWhere {
		nChunks = 6
	}

	chunks := strings.SplitN(s, ",", nChunks)

	var (
		enabled bool
		op      GrepOperator
		typ     GrepType
		value   GrepValue
		opt     GrepOption
		where   string

		err error
	)

	enabled, err = parseGrepEnabled(strings.TrimSpace(chunks[0]))
	if err != nil {
		return Grep{}, err
	}

	op, err = parseGrepOperator(strings.TrimSpace(chunks[1]))
	if err != nil {
		return Grep{}, err
	}

	typ, err = parseGrepType(strings.TrimSpace(chunks[2]))
	if err != nil {
		return Grep{}, err
	}

	if includeWhere { //nolint:nestif
		// Perhaps add validation
		where = strings.TrimSpace(chunks[3])

		opt, err = parseGrepOption(strings.TrimSpace(chunks[4]))
		if err != nil {
			return Grep{}, err
		}

		value, err = parseGrepValue(typ, strings.TrimSpace(chunks[5]), rr)
		if err != nil {
			return Grep{}, err
		}
	} else {
		opt, err = parseGrepOption(strings.TrimSpace(chunks[3]))
		if err != nil {
			return Grep{}, err
		}

		value, err = parseGrepValue(typ, strings.TrimSpace(chunks[4]), rr)
		if err != nil {
			return Grep{}, err
		}
	}

	return Grep{
		Enabled:  enabled,
		Operator: op,
		Type:     typ,
		Value:    value,
		Option:   opt,
		Where:    where,
	}, nil
}

func parseGrepEnabled(s string) (bool, error) {
	parseBool, err := strconv.ParseBool(s)
	if err != nil {
		return false, fmt.Errorf("%w: %s", ErrInvalidGrepEnabled, s)
	}

	return parseBool, nil
}

const (
	GrepOperatorNone   GrepOperator = ""
	GrepOperatorAnd    GrepOperator = "AND"
	GrepOperatorAndNot GrepOperator = "AND NOT"
	GrepOperatorOr     GrepOperator = "OR"
	GrepOperatorOrNot  GrepOperator = "OR NOT"
)

// GrepOperator represents a Grep operator, used to combine
// multiple Grep directives within the same step/profile.
type GrepOperator string

// None returns whether the operator is None.
func (op GrepOperator) None() bool {
	return op == GrepOperatorNone
}

// And returns whether the operator is AND.
func (op GrepOperator) And() bool {
	return op == GrepOperatorAnd
}

// AndNot returns whether the operator is AND NOT.
func (op GrepOperator) AndNot() bool {
	return op == GrepOperatorAndNot
}

// Or returns whether the operator is OR.
func (op GrepOperator) Or() bool {
	return op == GrepOperatorOr
}

// OrNot returns whether the operator is OR NOT.
func (op GrepOperator) OrNot() bool {
	return op == GrepOperatorOrNot
}

// Match returns the result of the operator applied to the two
// given boolean values. So, basic logic operations are performed.
func (op GrepOperator) Match(x, y bool) bool {
	const noop = false

	switch op {
	case GrepOperatorAnd:
		return x && y
	case GrepOperatorAndNot:
		return x && !y
	case GrepOperatorOr:
		return x || y
	case GrepOperatorOrNot:
		return x || !y
	case GrepOperatorNone:
		return noop
	}

	// Return false for any non-functional operator
	return noop
}

func parseGrepOperator(s string) (GrepOperator, error) {
	switch GrepOperator(strings.ToUpper(s)) {
	case GrepOperatorNone:
		return GrepOperatorNone, nil
	case GrepOperatorAnd:
		return GrepOperatorAnd, nil
	case GrepOperatorAndNot:
		return GrepOperatorAndNot, nil
	case GrepOperatorOr:
		return GrepOperatorOr, nil
	case GrepOperatorOrNot:
		return GrepOperatorOrNot, nil
	default:
		return GrepOperator(s), fmt.Errorf("%w: %s", ErrInvalidGrepOperator, s)
	}
}

const (
	GrepTypeSimpleString      GrepType = "Simple String"
	GrepTypeRegex             GrepType = "Regex"
	GrepTypeBlindHost         GrepType = "Blind Host"
	GrepTypeStatusCode        GrepType = "Status Code"
	GrepTypeTimeDelay         GrepType = "Time Delay" // It doesn't take "connection_time" into consideration.
	GrepTypeContentType       GrepType = "Content Type"
	GrepTypeContentLength     GrepType = "Content Length"
	GrepTypeContentLengthDiff GrepType = "Content Length Diff"
	GrepTypeURLExtension      GrepType = "URL Extension"
	GrepTypePayload           GrepType = "Payload"
	GrepTypePreEncodedPayload GrepType = "Pre-Encoded Payload"
)

// GrepType represents a Grep type, used to determine the
// type of the value that should be matched.
type GrepType string

// String returns the string representation of the GrepType.
func (gt GrepType) String() string {
	return string(gt)
}

// SimpleString returns whether the GrepType is SimpleString.
func (gt GrepType) SimpleString() bool {
	return gt == GrepTypeSimpleString
}

// Regex returns whether the GrepType is Regex.
func (gt GrepType) Regex() bool {
	return gt == GrepTypeRegex
}

// BlindHost returns whether the GrepType is BlindHost.
func (gt GrepType) BlindHost() bool {
	return gt == GrepTypeBlindHost
}

// StatusCode returns whether the GrepType is StatusCode.
func (gt GrepType) StatusCode() bool {
	return gt == GrepTypeStatusCode
}

// TimeDelay returns whether the GrepType is TimeDelay.
func (gt GrepType) TimeDelay() bool {
	return gt == GrepTypeTimeDelay
}

// ContentType returns whether the GrepType is ContentType.
func (gt GrepType) ContentType() bool {
	return gt == GrepTypeContentType
}

// ContentLength returns whether the GrepType is ContentLength.
func (gt GrepType) ContentLength() bool {
	return gt == GrepTypeContentLength
}

// ContentLengthDiff returns whether the GrepType is ContentLengthDiff.
func (gt GrepType) ContentLengthDiff() bool {
	return gt == GrepTypeContentLengthDiff
}

// ContentURLExtension returns whether the GrepType is URLExtension.
func (gt GrepType) ContentURLExtension() bool {
	return gt == GrepTypeURLExtension
}

// Payload returns whether the GrepType is Payload.
func (gt GrepType) Payload() bool {
	return gt == GrepTypePayload
}

// PreEncodedPayload returns whether the GrepType is PreEncodedPayload.
func (gt GrepType) PreEncodedPayload() bool {
	return gt == GrepTypePreEncodedPayload
}

func parseGrepType(s string) (GrepType, error) {
	switch GrepType(s) {
	case GrepTypeSimpleString:
		return GrepTypeSimpleString, nil
	case GrepTypeRegex:
		return GrepTypeRegex, nil
	case GrepTypeBlindHost:
		return GrepTypeBlindHost, nil
	case GrepTypeStatusCode:
		return GrepTypeStatusCode, nil
	case GrepTypeTimeDelay:
		return GrepTypeTimeDelay, nil
	case GrepTypeContentType:
		return GrepTypeContentType, nil
	case GrepTypeContentLength:
		return GrepTypeContentLength, nil
	case GrepTypeContentLengthDiff:
		return GrepTypeContentLengthDiff, nil
	case GrepTypeURLExtension:
		return GrepTypeURLExtension, nil
	case GrepTypePayload:
		return GrepTypePayload, nil
	case GrepTypePreEncodedPayload:
		return GrepTypePreEncodedPayload, nil
	default:
		return GrepType(s), fmt.Errorf("%w: %s", ErrInvalidGrepType, s)
	}
}

// GrepValue represents the value of a Grep directive.
type GrepValue string

// Replace replaces the labels with the corresponding values.
func (v GrepValue) Replace(rr map[string]string) GrepValue {
	s := string(v)
	for label, value := range rr {
		s = strings.ReplaceAll(s, label, value)
	}

	return GrepValue(s)
}

// AsString returns the GrepValue as a string.
func (v GrepValue) AsString() string {
	return string(v)
}

// AsRegex returns the GrepValue as a regex string.
func (v GrepValue) AsRegex() string {
	return string(v)
}

// AsStatusCodes returns the GrepValue as a slice of
// status codes (integers).
func (v GrepValue) AsStatusCodes() []int {
	chunks := strings.Split(string(v), ";")
	codes := make([]int, 0, len(chunks))
	for _, c := range chunks {
		// Already checked
		code, _ := strconv.ParseInt(strings.TrimSpace(c), 10, 64)
		codes = append(codes, int(code))
	}

	return codes
}

// AsTimeDelaySeconds returns the GrepValue as an integer
// that represents the time delay in seconds.
func (v GrepValue) AsTimeDelaySeconds() int {
	// Already checked
	delay, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
	return int(delay)
}

// AsContentTypes returns the GrepValue as a slice of
// content types (strings).
func (v GrepValue) AsContentTypes() []string {
	chunks := strings.Split(string(v), ";")
	contentTypes := make([]string, 0, len(chunks))
	for _, c := range chunks {
		contentTypes = append(contentTypes, strings.TrimSpace(c))
	}

	return contentTypes
}

// AsContentLength returns the GrepValue as an integer
// that represents the content length.
func (v GrepValue) AsContentLength() int {
	// Already checked
	length, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
	return int(length)
}

// AsPayload returns the GrepValue as a string.
func (v GrepValue) AsPayload() string {
	return string(v)
}

// AsPreEncodedPayload returns the GrepValue as a string.
func (v GrepValue) AsPreEncodedPayload() string {
	return string(v)
}

// AsURLExtensions returns the GrepValue as a slice of
// URL extensions (strings).
func (v GrepValue) AsURLExtensions() []string {
	chunks := strings.Split(string(v), ";")
	extensions := make([]string, 0, len(chunks))
	for _, c := range chunks {
		extensions = append(extensions, strings.TrimSpace(c))
	}

	return extensions
}

func parseGrepValue(t GrepType, s string, rr map[string]string) (GrepValue, error) {
	// First, we apply the replacements.
	for label, value := range rr {
		s = strings.ReplaceAll(s, label, value)
	}

	switch t {
	case GrepTypeSimpleString:
		return GrepValue(s), nil
	case GrepTypeRegex:
		return GrepValue(s), nil
	case GrepTypeBlindHost:
		return GrepValue(s), nil
	case GrepTypeStatusCode:
		return parseStatusCodes(s)
	case GrepTypeTimeDelay:
		return parseTimeDelay(s)
	case GrepTypeContentType:
		return GrepValue(s), nil
	case GrepTypeContentLength, GrepTypeContentLengthDiff:
		return parseContentLength(s)
	case GrepTypeURLExtension:
		return parseURLExtensions(s)
	case GrepTypePayload:
		return GrepValue(s), nil
	case GrepTypePreEncodedPayload:
		return GrepValue(s), nil
	}

	return GrepValue(s), fmt.Errorf("%w: %s", ErrInvalidGrepType, t)
}

func parseStatusCodes(s string) (GrepValue, error) {
	for _, s := range strings.Split(s, ";") {
		code, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return "", fmt.Errorf("%w: %s", ErrInvalidStatusCode, s)
		}

		if !((code >= 100 && code <= 199) || // 1xx: Informational responses
			(code >= 200 && code <= 299) || // 2xx: Successful responses
			(code >= 300 && code <= 399) || // 3xx: Redirection messages
			(code >= 400 && code <= 499) || // 4xx: Client errors
			(code >= 500 && code <= 599)) { // 5xx: Server errors
			return "", fmt.Errorf("%w: %s", ErrInvalidStatusCode, s)
		}
	}

	return GrepValue(s), nil
}

func parseTimeDelay(s string) (GrepValue, error) {
	_, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidTimeDelay, s)
	}

	return GrepValue(s), nil
}

func parseContentLength(s string) (GrepValue, error) {
	_, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidContentLength, s)
	}

	return GrepValue(s), nil
}

func parseURLExtensions(s string) (GrepValue, error) {
	for _, s := range strings.Split(s, ";") {
		// An extension must start with dot (e.g.; .php)
		if !strings.HasPrefix(strings.TrimSpace(s), ".") {
			return "", fmt.Errorf("%w: %s", ErrInvalidURLExtension, s)
		}
	}

	return GrepValue(s), nil
}

const (
	GrepOptionNone          GrepOption = ""
	GrepOptionCaseSensitive GrepOption = "Case sensitive"
	GrepOptionOnlyInHeaders GrepOption = "Only in Headers"
	GrepOptionNotInHeaders  GrepOption = "Not in Headers"
)

// GrepOption represents a Grep option, used to determine
// how the value should be matched.
type GrepOption string

// String returns the string representation of the GrepOption.
func (opt GrepOption) String() string {
	return string(opt)
}

// None returns whether the GrepOption is None.
func (opt GrepOption) None() bool {
	return opt == GrepOptionNone
}

// CaseSensitive returns whether the GrepOption is CaseSensitive.
func (opt GrepOption) CaseSensitive() bool {
	return opt == GrepOptionCaseSensitive
}

// OnlyInHeaders returns whether the GrepOption is OnlyInHeaders.
func (opt GrepOption) OnlyInHeaders() bool {
	return opt == GrepOptionOnlyInHeaders
}

// NotInHeaders returns whether the GrepOption is NotInHeaders.
func (opt GrepOption) NotInHeaders() bool {
	return opt == GrepOptionNotInHeaders
}

func parseGrepOption(s string) (GrepOption, error) {
	switch GrepOption(s) {
	case GrepOptionNone:
		return GrepOptionNone, nil
	case GrepOptionCaseSensitive:
		return GrepOptionCaseSensitive, nil
	case GrepOptionOnlyInHeaders:
		return GrepOptionOnlyInHeaders, nil
	case GrepOptionNotInHeaders:
		return GrepOptionNotInHeaders, nil
	default:
		return GrepOption(s), fmt.Errorf("%w: %s", ErrInvalidGrepOption, s)
	}
}
