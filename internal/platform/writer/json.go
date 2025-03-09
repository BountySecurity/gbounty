package writer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/BountySecurity/gbounty"
)

// JSON must implement the [gbounty.Writer] interface.
var _ gbounty.Writer = JSON{}

// JSON is a [gbounty.Writer] implementation that writes the output
// to the given [io.Writer], in a machine-readable format (JSON).
type JSON struct {
	writer io.Writer
}

// NewJSON creates a new instance of [JSON] with the given [io.Writer].
func NewJSON(writer io.Writer) JSON {
	return JSON{writer: writer}
}

// WriteConfig writes the [gbounty.Config] to the [io.Writer] as a JSON object.
func (j JSON) WriteConfig(_ context.Context, cfg gbounty.Config) error {
	_, err := fmt.Fprintf(j.writer, `
	"config": {
		"version": "%s",
		"rps": %d,
		"concurrency": %d,
		"saveOnStop": %v,
		"memoryOnly": %v,
		"blindHost": "%s",
		"blindHostKey": "%s"
	}`, cfg.Version, cfg.RPS, cfg.Concurrency, cfg.SaveOnStop, cfg.InMemory, cfg.BlindHost, cfg.BlindHostKey)

	return err
}

// WriteStats writes the [gbounty.Stats] to the [io.Writer] as a JSON object.
func (j JSON) WriteStats(ctx context.Context, fs gbounty.FileSystem) error {
	stats, err := fs.LoadStats(ctx)
	if err != nil {
		return err
	}

	scanDuration := time.Since(stats.StartedAt)
	if scanDuration > time.Second {
		scanDuration = scanDuration.Round(time.Second)
	} else {
		scanDuration = scanDuration.Round(time.Millisecond)
	}

	_, err = fmt.Fprintf(j.writer, `,
	"results": {
		"insertionPoints": %d,
		"requests": %d,
		"failures": %d,
		"successes": %d,
		"matches": %d,
		"duration": "%s"
	}`,
		stats.NumOfEntrypoints, stats.NumOfPerformedRequests, stats.NumOfFailedRequests,
		stats.NumOfSucceedRequests, stats.NumOfMatches, scanDuration,
	)

	return err
}

// WriteMatchesSummary writes a summary of the [gbounty.Match] instances found during the [scan],
// to the [io.Writer] as a JSON array of JSON objects.
func (j JSON) WriteMatchesSummary(ctx context.Context, fs gbounty.FileSystem) error {
	_, err := fmt.Fprint(j.writer, `,
	"summary": [`)
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	profileTypes := make(map[string]string)
	byIssue := make(map[string]map[string]struct{ count int })

	for match := range ch {
		issue := fmt.Sprintf(`{
				"name": "%s",
				"severity": "%s",
				"confidence": "%s"
			},`, match.IssueName, match.IssueSeverity, match.IssueConfidence)

		profileTypes[issue] = match.ProfileType

		if _, ok := byIssue[issue]; !ok {
			byIssue[issue] = map[string]struct{ count int }{match.URL: {count: 1}}
		} else {
			tmp := byIssue[issue][match.URL]
			tmp.count++
			byIssue[issue][match.URL] = tmp
		}
	}

	first := true

	for issue, mUrls := range byIssue {
		urls, count := sortedKeys(mUrls)

		urlsStr := `[
				` + jsonMarshaled(urls[0])

		for _, url := range urls[1:] {
			urlsStr += `,
				` + jsonMarshaled(url)
		}

		urlsStr += `
			]`

		if !first {
			_, err = fmt.Fprint(j.writer, ",")
			if err != nil {
				return err
			}
		}

		first = false

		_, err = fmt.Fprintf(j.writer, `
		{
			"issue": %s
			"type": "%s",
			"count": %d,
			"urls": %s
		}`, issue, profileTypes[issue], count, urlsStr)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
	]`)

	return err
}

// WriteError writes a [gbounty.Error] to the [io.Writer] as a JSON object.
func (j JSON) WriteError(_ context.Context, scanError gbounty.Error) error {
	_, err := fmt.Fprintf(j.writer, `{
	"domain": %s,
	"error": %s`, jsonMarshaled(scanError.Domain()), jsonMarshaled(scanError.Err))
	if err != nil {
		return err
	}

	if scanError.Requests != nil {
		_, err = fmt.Fprintf(j.writer, `,
			"requests": [`)
		if err != nil {
			return err
		}

		first := true
		for _, r := range scanError.Requests {
			if r == nil {
				continue
			}
			if !first {
				_, err = fmt.Fprint(j.writer, ",")
				if err != nil {
					return err
				}
			}

			first = false

			_, err = fmt.Fprintf(j.writer, `
				%s`, string(r.EscapedBytes()))
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(j.writer, `
			]`)
		if err != nil {
			return err
		}
	}

	if scanError.Responses != nil {
		_, err = fmt.Fprintf(j.writer, `,
			"responses": [`)
		if err != nil {
			return err
		}

		first := true
		for _, r := range scanError.Responses {
			if r == nil {
				continue
			}
			if !first {
				_, err = fmt.Fprint(j.writer, ",")
				if err != nil {
					return err
				}
			}

			first = false

			_, err = fmt.Fprintf(j.writer, `
				{
					"response": %s,
					"duration": "%s"
				}`, string(r.EscapedBytes()), fmt.Sprintf("%.2fs", r.Time.Seconds()))
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(j.writer, `
			]`)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
}`)

	return err
}

// WriteErrors writes the [gbounty.Error] instances to the [io.Writer] as a JSON array of JSON objects.
func (j JSON) WriteErrors(ctx context.Context, fs gbounty.FileSystem) error {
	_, err := fmt.Fprint(j.writer, `,
	"errors": [`)
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.ErrorsIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	first := true

	for scanError := range ch {
		if !first {
			_, err = fmt.Fprint(j.writer, ",")
			if err != nil {
				return err
			}
		}

		first = false

		_, err = fmt.Fprintf(j.writer, `
		{
			"domain": %s,
			"error": %s`, jsonMarshaled(scanError.Domain()), jsonMarshaled(scanError.Err))
		if err != nil {
			return err
		}

		if scanError.Requests != nil {
			_, err = fmt.Fprintf(j.writer, `,
			"requests": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range scanError.Requests {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				%s`, string(r.EscapedBytes()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		if scanError.Responses != nil {
			_, err = fmt.Fprintf(j.writer, `,
			"responses": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range scanError.Responses {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				{
					"response": %s,
					"duration": "%s"
				}`, string(r.EscapedBytes()), fmt.Sprintf("%.2fs", r.Time.Seconds()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprint(j.writer, `
		}`)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
	]`)

	return err
}

// WriteMatch writes a [gbounty.Match] to the [io.Writer] as a JSON object.
func (j JSON) WriteMatch(_ context.Context, m gbounty.Match, includeResponse bool) error {
	_, err := fmt.Fprintf(j.writer, `{
	"domain": %s,
	"issue": {
		"name": "%s",
		"severity": "%s",
		"confidence": "%s",
		"param": %s
	},
	"type": "%s"`, jsonMarshaled(m.Domain()), m.IssueName, m.IssueSeverity, m.IssueConfidence, jsonMarshaled(m.IssueParam), m.ProfileType)
	if err != nil {
		return err
	}

	if m.Requests != nil {
		_, err = fmt.Fprintf(j.writer, `,
			"requests": [`)
		if err != nil {
			return err
		}

		first := true
		for _, r := range m.Requests {
			if r == nil {
				continue
			}
			if !first {
				_, err = fmt.Fprint(j.writer, ",")
				if err != nil {
					return err
				}
			}

			first = false

			_, err = fmt.Fprintf(j.writer, `
				%s`, string(r.EscapedBytes()))
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(j.writer, `
			]`)
		if err != nil {
			return err
		}
	}

	if m.Responses != nil && includeResponse {
		_, err = fmt.Fprintf(j.writer, `,
			"responses": [`)
		if err != nil {
			return err
		}

		first := true
		for _, r := range m.Responses {
			if r == nil {
				continue
			}
			if !first {
				_, err = fmt.Fprint(j.writer, ",")
				if err != nil {
					return err
				}
			}

			first = false

			_, err = fmt.Fprintf(j.writer, `
				{
					"response": %s,
					"duration": "%s"
				}`, string(r.EscapedBytes()), fmt.Sprintf("%.2fs", r.Time.Seconds()))
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprintf(j.writer, `
			]`)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
}`)

	return err
}

// WriteMatches writes the [gbounty.Match] instances found during the [scan],
// as a JSON array of JSON objects.
func (j JSON) WriteMatches(ctx context.Context, fs gbounty.FileSystem, includeResponses bool) error {
	_, err := fmt.Fprint(j.writer, `,
	"matches": [`)
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	first := true

	for m := range ch {
		if !first {
			_, err = fmt.Fprint(j.writer, ",")
			if err != nil {
				return err
			}
		}

		first = false

		_, err = fmt.Fprintf(j.writer, `
		{
			"domain": %s,
			"issue": {
				"name": "%s",
				"severity": "%s",
				"confidence": "%s",
				"param": %s
			},
			"type": "%s"`, jsonMarshaled(m.Domain()), m.IssueName, m.IssueSeverity, m.IssueConfidence, jsonMarshaled(m.IssueParam), m.ProfileType)
		if err != nil {
			return err
		}

		if m.Requests != nil {
			_, err = fmt.Fprintf(j.writer, `,
			"requests": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range m.Requests {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				%s`, string(r.EscapedBytes()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		if m.Responses != nil && includeResponses {
			_, err = fmt.Fprintf(j.writer, `,
			"responses": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range m.Responses {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				{
					"response": %s,
					"duration": "%s"
				}`, string(r.EscapedBytes()), fmt.Sprintf("%.2fs", r.Time.Seconds()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprint(j.writer, `
		}`)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
	]`)

	return err
}

// WriteTasks writes the [gbounty.TaskSummary] instances to the [io.Writer] as a JSON array of JSON objects.
func (j JSON) WriteTasks(ctx context.Context, fs gbounty.FileSystem, allRequests, allResponses bool) error {
	_, err := fmt.Fprint(j.writer, `,
	"tasks": [`)
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.TasksSummariesIterator(ctx)
	if err != nil {
		return err
	}

	first := true

	for scanTask := range ch {
		if !first {
			_, err = fmt.Fprint(j.writer, ",")
			if err != nil {
				return err
			}
		}

		first = false

		_, err = fmt.Fprintf(j.writer, `
		{
			"domain": %s`, jsonMarshaled(scanTask.Domain()))
		if err != nil {
			return err
		}

		if !allResponses && scanTask.Requests != nil {
			_, err = fmt.Fprintf(j.writer, `,
			"requests": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range scanTask.Requests {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				%s`, string(r.EscapedBytes()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		if !allRequests && scanTask.Responses != nil {
			_, err = fmt.Fprintf(j.writer, `,
			"responses": [`)
			if err != nil {
				return err
			}

			first := true
			for _, r := range scanTask.Responses {
				if r == nil {
					continue
				}
				if !first {
					_, err = fmt.Fprint(j.writer, ",")
					if err != nil {
						return err
					}
				}

				first = false

				_, err = fmt.Fprintf(j.writer, `
				{
					"response": %s,
					"duration": "%s"
				}`, string(r.EscapedBytes()), fmt.Sprintf("%.2fs", r.Time.Seconds()))
				if err != nil {
					return err
				}
			}

			_, err = fmt.Fprintf(j.writer, `
			]`)
			if err != nil {
				return err
			}
		}

		_, err = fmt.Fprint(j.writer, `
		}`)
		if err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(j.writer, `
	]`)

	closeIt()

	return err
}

func jsonMarshaled(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b)
}
