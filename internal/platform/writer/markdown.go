package writer

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"github.com/BountySecurity/gbounty"
)

// Markdown must implement the [gbounty.Writer] interface.
var _ gbounty.Writer = Markdown{}

// Markdown is a [gbounty.Writer] implementation that writes the output
// to the given [io.Writer], in a styled human-readable format (Markdown).
type Markdown struct {
	writer io.Writer
}

// NewMarkdown creates a new instance of [Markdown] with the given [io.Writer].
func NewMarkdown(writer io.Writer) Markdown {
	return Markdown{writer: writer}
}

// WriteConfig writes the [gbounty.Config] to the [io.Writer] in the Markdown format.
func (md Markdown) WriteConfig(_ context.Context, cfg gbounty.Config) error {
	builder := strings.Builder{}
	builder.WriteString(pterm.DefaultSection.WithTopPadding(0).WithStyle(nil).Sprintln("Configuration"))
	builder.WriteString(fmt.Sprintf("**Version:** %s\n\n", cfg.Version))
	builder.WriteString(fmt.Sprintf("**Requests/sec:** %d\n\n", cfg.RPS))
	builder.WriteString(fmt.Sprintf("**Concurrent URLs:** %d\n\n", cfg.Concurrency))
	builder.WriteString(fmt.Sprintf("**Save on stop:** %v\n\n", cfg.SaveOnStop))
	builder.WriteString(fmt.Sprintf("**Memory-only:** %v\n\n", cfg.InMemory))

	if len(cfg.BlindHostDomain) > 0 {
		builder.WriteString(fmt.Sprintf("**Blind host:** %v\n\n", cfg.BlindHostDomain))
		builder.WriteString(fmt.Sprintf("**Blind host id:** %v\n\n", cfg.BlindHostId))
		builder.WriteString(fmt.Sprintf("**Blind host key:** %v\n\n", cfg.BlindHostPrivateKey))
	}

	_, err := fmt.Fprintln(md.writer, builder.String())

	return err
}

// WriteStats writes the [gbounty.Stats] to the [io.Writer] in the Markdown format.
func (md Markdown) WriteStats(ctx context.Context, fs gbounty.FileSystem) error {
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

	builder := strings.Builder{}
	builder.WriteString(pterm.DefaultSection.WithTopPadding(0).WithStyle(nil).Sprintln("Scan results"))
	builder.WriteString(fmt.Sprintf("**Insertion point(s) found:** %d\n\n", stats.NumOfEntrypoints))
	builder.WriteString(fmt.Sprintf("**Request(s) finished:** %d\n\n", stats.NumOfPerformedRequests))
	builder.WriteString(fmt.Sprintf("**Request(s) failed:** %d\n\n", stats.NumOfFailedRequests))
	builder.WriteString(fmt.Sprintf("**Match(es) found:** %d\n\n", stats.NumOfMatches))
	builder.WriteString(fmt.Sprintf("**Elapsed time:** %s\n\n", scanDuration))

	_, err = fmt.Fprint(md.writer, builder.String())

	return err
}

// WriteMatchesSummary writes a summary of the [gbounty.Match] instances found during the [scan],
// to the [io.Writer] in the Markdown format.
func (md Markdown) WriteMatchesSummary(ctx context.Context, fs gbounty.FileSystem) error {
	_, err := fmt.Fprint(md.writer, pterm.DefaultSection.WithStyle(nil).Sprintln("Summary"))
	if err != nil {
		return err
	}

	var atLeastOne bool

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	profileTypes := make(map[string]string)
	byIssue := make(map[string]map[string]struct{ count int })

	for match := range ch {
		atLeastOne = true

		issue := fmt.Sprintf("**Issue name:** %s\n\n**Issue severity:** %s\n\n**Issue confidence:** %s\n\n",
			match.IssueName,
			match.IssueSeverity,
			match.IssueConfidence,
		)

		profileTypes[issue] = match.ProfileType

		if _, ok := byIssue[issue]; !ok {
			byIssue[issue] = map[string]struct{ count int }{match.URL: {count: 1}}
		} else {
			tmp := byIssue[issue][match.URL]
			tmp.count++
			byIssue[issue][match.URL] = tmp
		}
	}

	for issue, mUrls := range byIssue {
		urls, count := sortedKeys(mUrls)

		builder := strings.Builder{}
		builder.WriteString(issue)
		builder.WriteString(fmt.Sprintf("**Type:** %s\n\n", profileTypes[issue]))
		builder.WriteString(fmt.Sprintf("**Count:** %d\n\n", count))

		urlsStr := urls[0]
		for _, url := range urls[1:] {
			urlsStr += "\n" + url
		}

		builder.WriteString(fmt.Sprintf("**URL(s):** %s\n\n", urlsStr))

		_, err := fmt.Fprint(md.writer, builder.String())
		if err != nil {
			return err
		}
	}

	if !atLeastOne {
		_, err := fmt.Fprint(md.writer, "**No matches found**\n")
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteError writes a [gbounty.Error] to the [io.Writer] in the Markdown format.
func (md Markdown) WriteError(_ context.Context, scanError gbounty.Error) error {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("**%s**\n\n", scanError.URL))
	builder.WriteString(fmt.Sprintf("**Error:** %s\n\n", scanError.Err))

	if scanError.Requests != nil {
		builder.WriteString("**Requests:**\n\n")
		for idx, r := range scanError.Requests {
			if r == nil {
				continue
			}
			builder.WriteString(fmt.Sprintf("Request no. %d:\n\n", idx+1))
			builder.WriteString("```\n")
			builder.WriteString(trimBytesNewline(r))
			builder.WriteString("\n```\n\n")
		}
	}

	if scanError.Responses != nil {
		builder.WriteString("**Responses:**\n\n")
		for idx, r := range scanError.Responses {
			if r == nil {
				continue
			}
			builder.WriteString(fmt.Sprintf("Response no. %d:\n\n", idx+1))
			builder.WriteString("```\n")
			builder.WriteString(trimBytesNewline(r))
			builder.WriteString("\n```\n\n")
			builder.WriteString(fmt.Sprintf("Duration: %.2fs\n\n", r.Time.Seconds()))
		}
	}

	_, err := fmt.Fprint(md.writer, builder.String())

	return err
}

// WriteErrors writes the [gbounty.Error] instances to the [io.Writer] in the Markdown format.
func (md Markdown) WriteErrors(ctx context.Context, fs gbounty.FileSystem) error {
	_, err := fmt.Fprint(md.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Errors"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.ErrorsIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	for scanError := range ch {
		builder := strings.Builder{}
		builder.WriteString(fmt.Sprintf("**%s**\n\n", scanError.URL))
		builder.WriteString(fmt.Sprintf("**Error:** %s\n\n", scanError.Err))

		if scanError.Requests != nil {
			builder.WriteString("**Requests:**\n\n")
			for idx, r := range scanError.Requests {
				if r == nil {
					continue
				}
				builder.WriteString(fmt.Sprintf("Request no. %d:\n\n", idx+1))
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(r))
				builder.WriteString("\n```\n\n")
			}
		}

		if scanError.Responses != nil {
			builder.WriteString("**Responses:**\n\n")
			for idx, r := range scanError.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(fmt.Sprintf("Response no. %d:\n\n", idx+1))
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(r))
				builder.WriteString("\n```\n\n")
				builder.WriteString(fmt.Sprintf("Duration: %.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n")

		_, err := fmt.Fprint(md.writer, builder.String())
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteMatch writes a [gbounty.Match] to the [io.Writer] in the Markdown format.
func (md Markdown) WriteMatch(_ context.Context, m gbounty.Match, includeResponse bool) error {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("**%s**\n\n", m.Domain()))
	builder.WriteString(fmt.Sprintf("**Issue name:** %s\n\n**Issue severity:** %s\n\n**Issue confidence:** %s\n\n",
		m.IssueName,
		m.IssueSeverity,
		m.IssueConfidence,
	))

	if len(m.IssueParam) > 0 {
		builder.WriteString(fmt.Sprintf("**Param:** %s\n\n", m.IssueParam))
	}

	builder.WriteString(fmt.Sprintf("**Type:** %s\n\n", m.ProfileType))

	to := max(len(m.Requests), len(m.Responses))
	for i := range to {
		if m.Requests != nil && i < len(m.Requests) && m.Requests[i] != nil {
			if len(m.Requests) > 1 {
				builder.WriteString(fmt.Sprintf("**Request no. %d:**\n\n", i+1))
			} else {
				builder.WriteString("**Request:**\n\n")
			}
			builder.WriteString("```\n")
			builder.WriteString(trimBytesNewline(m.Requests[i]))
			builder.WriteString("\n```\n\n")
		}

		if m.Responses != nil && i < len(m.Responses) && m.Responses[i] != nil && includeResponse {
			if len(m.Responses) > 1 {
				builder.WriteString(fmt.Sprintf("**Response no. %d:**\n\n", i+1))
			} else {
				builder.WriteString("**Response:**\n\n")
			}
			builder.WriteString("```\n")
			builder.WriteString(trimBytesNewline(m.Responses[i]))
			builder.WriteString("\n```\n\n")
			builder.WriteString(fmt.Sprintf("**Duration:** %.2fs\n\n", m.Responses[i].Time.Seconds()))
		}
	}

	_, err := fmt.Fprint(md.writer, builder.String())

	return err
}

// WriteMatches writes the [gbounty.Match] instances found during the [scan],
// in the Markdown format.
func (md Markdown) WriteMatches(ctx context.Context, fs gbounty.FileSystem, includeResponses bool) error {
	_, err := fmt.Fprint(md.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Matches"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}
	defer closeIt()

	for m := range ch {
		builder := strings.Builder{}
		builder.WriteString(fmt.Sprintf("**%s**\n\n", m.Domain()))
		builder.WriteString(fmt.Sprintf("**Issue name:** %s\n\n**Issue severity:** %s\n\n**Issue confidence:** %s\n\n",
			m.IssueName,
			m.IssueSeverity,
			m.IssueConfidence,
		))

		if len(m.IssueParam) > 0 {
			builder.WriteString(fmt.Sprintf("**Param:** %s\n\n", m.IssueParam))
		}

		builder.WriteString(fmt.Sprintf("**Type:** %s\n\n", m.ProfileType))

		to := max(len(m.Requests), len(m.Responses))
		for i := range to {
			if m.Requests != nil && i < len(m.Requests) && m.Requests[i] != nil {
				if len(m.Requests) > 1 {
					builder.WriteString(fmt.Sprintf("**Request no. %d:**\n\n", i+1))
				} else {
					builder.WriteString("**Request:**\n\n")
				}
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(m.Requests[i]))
				builder.WriteString("\n```\n\n")
			}

			if m.Responses != nil && i < len(m.Responses) && m.Responses[i] != nil && includeResponses {
				if len(m.Responses) > 1 {
					builder.WriteString(fmt.Sprintf("**Response no. %d:**\n\n", i+1))
				} else {
					builder.WriteString("**Response:**\n\n")
				}
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(m.Responses[i]))
				builder.WriteString("\n```\n\n")
				builder.WriteString(fmt.Sprintf("**Duration:** %.2fs\n\n", m.Responses[i].Time.Seconds()))
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(md.writer, builder.String())
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteTasks writes the [gbounty.TaskSummary] instances to the [io.Writer] in the Markdown format.
func (md Markdown) WriteTasks(ctx context.Context, fs gbounty.FileSystem, allRequests, allResponses bool) error {
	_, err := fmt.Fprint(md.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Requests / Responses"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.TasksSummariesIterator(ctx)
	if err != nil {
		return err
	}

	for scanTask := range ch {
		builder := strings.Builder{}
		builder.WriteString(fmt.Sprintf("**%s**\n\n", scanTask.URL))

		if !allResponses && scanTask.Requests != nil {
			builder.WriteString("**Requests:**\n\n")
			for idx, r := range scanTask.Requests {
				if r == nil {
					continue
				}
				builder.WriteString(fmt.Sprintf("Request no. %d:\n\n", idx+1))
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(r))
				builder.WriteString("\n```\n\n")
			}
		}

		if !allRequests && scanTask.Responses != nil {
			builder.WriteString("**Responses:**\n\n")
			for idx, r := range scanTask.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(fmt.Sprintf("Response no. %d:\n\n", idx+1))
				builder.WriteString("```\n")
				builder.WriteString(trimBytesNewline(r))
				builder.WriteString("\n```\n\n")
				builder.WriteString(fmt.Sprintf("Duration: %.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(md.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}
