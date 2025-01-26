package modifier

import (
	"regexp"
	"strings"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// MatchAndReplace must implement the [gbounty.Modifier] interface.
var _ gbounty.Modifier = MatchAndReplace{}

// MatchAndReplace is a [gbounty.Modifier] implementation that modifies the request
// by replacing the matched string or regular expression with the given string.
type MatchAndReplace struct{}

// NewMatchAndReplace is a constructor function that creates a new instance of
// the [MatchAndReplace] modifier.
func NewMatchAndReplace() MatchAndReplace {
	return MatchAndReplace{}
}

// Modify modifies the request by replacing the matched string or regular expression.
func (m MatchAndReplace) Modify(step *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	cloned := req.Clone()

	if step == nil {
		return cloned
	}

	for _, matchAndReplace := range step.MatchAndReplaces {
		if !matchAndReplace.Type.Request() {
			continue
		}

		switch matchAndReplace.Regex {
		case profile.MatchAndReplaceString:
			cloned = replace(cloned, map[string]string{
				matchAndReplace.Match: matchAndReplace.Replace,
			})
		case profile.MatchAndReplaceRegexp:
			cloned = replaceRegex(cloned, map[string]string{
				matchAndReplace.Match: matchAndReplace.Replace,
			})
		}
	}

	return cloned
}

func replace(req request.Request, replacements map[string]string) request.Request {
	cloned := req.Clone()

	for label, replacement := range replacements {
		// Path
		cloned.Path = strings.ReplaceAll(cloned.Path, label, replacement)

		// Headers
		for name, values := range cloned.Headers {
			for i := range values {
				cloned.Headers[name][i] = strings.ReplaceAll(cloned.Headers[name][i], label, replacement)
			}
		}

		// Body
		cloned.SetBody([]byte(strings.ReplaceAll(string(cloned.Body), label, replacement)))

		// Modifications
		if cloned.Modifications == nil {
			cloned.Modifications = make(map[string]string)
		}
		cloned.Modifications[label] = replacement
	}

	return cloned
}

func replaceRegex(req request.Request, replacements map[string]string) request.Request {
	cloned := req.Clone()

	for reLabel, replacement := range replacements {
		re, err := regexp.Compile(reLabel)
		if err != nil {
			continue
		}

		// Path
		cloned.Path = re.ReplaceAllString(cloned.Path, replacement)

		// Headers
		for name, values := range cloned.Headers {
			for i := range values {
				cloned.Headers[name][i] = re.ReplaceAllString(cloned.Headers[name][i], replacement)
			}
		}

		// Body
		cloned.SetBody([]byte(re.ReplaceAllString(string(cloned.Body), replacement)))

		// Modifications
		if cloned.Modifications == nil {
			cloned.Modifications = make(map[string]string)
		}
		cloned.Modifications[reLabel] = replacement
	}

	return cloned
}
