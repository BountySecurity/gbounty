package writer

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pterm/pterm"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/kit/console/printer"
)

// Plain must implement the [scan.Writer] interface.
var _ scan.Writer = Plain{}

// Plain is a [scan.Writer] implementation that writes the output
// to the given [io.Writer], as plain text.
// The format is quite similar to [Console] but without colors.
type Plain struct {
	writer io.Writer
}

// NewPlain creates a new instance of [Plain] with the given [io.Writer].
func NewPlain(writer io.Writer) Plain {
	return Plain{writer: writer}
}

// WriteConfig writes the [scan.Config] to the [io.Writer] as plain text.
func (p Plain) WriteConfig(_ context.Context, cfg scan.Config) error {
	builder := strings.Builder{}
	builder.WriteString(pterm.DefaultSection.WithTopPadding(0).WithStyle(nil).Sprintln("Configuration"))
	builder.WriteString(fmt.Sprintf("        Version: %s\n", cfg.Version))
	builder.WriteString(fmt.Sprintf("   Requests/sec: %d\n", cfg.RPS))
	builder.WriteString(fmt.Sprintf("Concurrent URLs: %d\n", cfg.Concurrency))
	builder.WriteString(fmt.Sprintf("   Save on stop: %v\n", cfg.SaveOnStop))
	builder.WriteString(fmt.Sprintf("    Memory-only: %v\n", cfg.InMemory))
	builder.WriteString(fmt.Sprintf("     Blind host: %v\n", cfg.InMemory))

	if len(cfg.BlindHost) > 0 {
		builder.WriteString(fmt.Sprintf("     Blind host: %v\n", cfg.BlindHost))
		builder.WriteString(fmt.Sprintf(" Blind host key: %v\n", cfg.BlindHostKey))
	}

	_, err := fmt.Fprintln(p.writer, builder.String())

	return err
}

// WriteStats writes the [scan.Stats] to the [io.Writer] as plain text.
func (p Plain) WriteStats(ctx context.Context, fs scan.FileSystem) error {
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
	builder.WriteString(fmt.Sprintf("Insertion point(s) found: %d\n", stats.NumOfEntrypoints))
	builder.WriteString(fmt.Sprintf("Request(s) finished: %d\n", stats.NumOfPerformedRequests))
	builder.WriteString(fmt.Sprintf("  Request(s) failed: %d\n", stats.NumOfFailedRequests))
	builder.WriteString(fmt.Sprintf("    Match(es) found: %d\n", stats.NumOfMatches))
	builder.WriteString(fmt.Sprintf("       Elapsed time: %s\n\n", scanDuration))

	_, err = fmt.Fprint(p.writer, builder.String())

	return err
}

// WriteMatchesSummary writes a summary of the [scan.Match] instances found during the [scan],
// to the [io.Writer] as plain text.
func (p Plain) WriteMatchesSummary(ctx context.Context, fs scan.FileSystem) error {
	_, err := fmt.Fprint(p.writer, pterm.DefaultSection.WithTopPadding(0).WithStyle(nil).Sprintln("Summary"))
	if err != nil {
		return err
	}

	var atLeastOne bool

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}

	profileTypes := make(map[string]string)
	byIssue := make(map[string]map[string]struct{ count int })

	for match := range ch {
		atLeastOne = true

		issue := fmt.Sprintf("%s\n%s\n%s", match.IssueName, match.IssueSeverity, match.IssueConfidence)
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
		issueChunks := strings.Split(issue, "\n")

		builder := strings.Builder{}
		builder.WriteString(printer.Plain(issuePrinter()).Sprintln(issueChunks[0]))
		builder.WriteString(printer.Plain(severityPrinter(issueChunks[1])).Sprintln(issueChunks[1]))
		builder.WriteString(printer.Plain(confidencePrinter(issueChunks[2])).Sprintln(issueChunks[2]))
		builder.WriteString(printer.Plain(typePrinter()).Sprintln(profileTypes[issue]))
		builder.WriteString(printer.Plain(countPrinter()).Sprintln(count))

		urlsStr := urls[0]
		for _, url := range urls[1:] {
			urlsStr += "\n" + url
		}

		builder.WriteString(printer.Plain(urlsPrinter()).Sprintln(urlsStr))
		builder.WriteString("\n")

		_, err := fmt.Fprint(p.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	if !atLeastOne {
		_, err := fmt.Fprint(p.writer, "No matches found\n")
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteError writes a [scan.Error] to the [io.Writer] as plain text.
func (p Plain) WriteError(_ context.Context, scanError scan.Error) error {
	builder := strings.Builder{}
	builder.WriteString("\n")
	builder.WriteString(printer.Plain(urlPrinter()).Sprintln(scanError.URL))
	builder.WriteString(printer.Plain(printer.Error()).Sprintln(scanError.Err))

	if scanError.Requests != nil {
		for _, r := range scanError.Requests {
			if r == nil {
				continue
			}
			builder.WriteString(printer.Plain(requestPrinter()).Sprintln(string(r.Bytes())))
		}
	}

	if scanError.Responses != nil {
		for _, r := range scanError.Responses {
			if r == nil {
				continue
			}
			builder.WriteString(printer.Plain(responsePrinter()).Sprintln(string(r.Bytes())))
			builder.WriteString(printer.Plain(durationPrinter()).Sprintf("%.2fs\n\n", r.Time.Seconds()))
		}
	}

	_, err := fmt.Fprintln(p.writer, builder.String())

	return err
}

// WriteErrors writes the [scan.Error] instances to the [io.Writer] as plain text.
func (p Plain) WriteErrors(ctx context.Context, fs scan.FileSystem) error {
	_, err := fmt.Fprint(p.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Errors"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.ErrorsIterator(ctx)
	if err != nil {
		return err
	}

	for scanError := range ch {
		builder := strings.Builder{}
		builder.WriteString(printer.Plain(urlPrinter()).Sprintln(scanError.URL))
		builder.WriteString(printer.Plain(printer.Error()).Sprintln(scanError.Err))

		if scanError.Requests != nil {
			for _, r := range scanError.Requests {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(requestPrinter()).Sprintln(string(r.Bytes())))
			}
		}

		if scanError.Responses != nil {
			for _, r := range scanError.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(responsePrinter()).Sprintln(string(r.Bytes())))
				builder.WriteString(printer.Plain(durationPrinter()).Sprintf("%.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n")

		_, err := fmt.Fprintln(p.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}

// WriteMatch writes a [scan.Match] to the [io.Writer] as plain text.
func (p Plain) WriteMatch(_ context.Context, m scan.Match, includeResponse bool) error {
	builder := strings.Builder{}
	builder.WriteString(printer.Plain(issuePrinter()).Sprintln(m.IssueName))
	builder.WriteString(printer.Plain(severityPrinter(m.IssueSeverity)).Sprintln(m.IssueSeverity))
	builder.WriteString(printer.Plain(confidencePrinter(m.IssueConfidence)).Sprintln(m.IssueConfidence))
	builder.WriteString(printer.Plain(typePrinter()).Sprintln(m.ProfileType))
	builder.WriteString(printer.Plain(urlPrinter()).Sprintln(m.URL))

	if len(m.IssueParam) > 0 {
		builder.WriteString(printer.Plain(paramPrinter()).Sprintln(m.IssueParam))
	}

	if m.Requests != nil {
		for _, r := range m.Requests {
			if r == nil {
				continue
			}
			builder.WriteString(printer.Plain(requestPrinter()).Sprintln(string(r.Bytes())))
		}
	}

	if m.Responses != nil && includeResponse {
		for _, r := range m.Responses {
			if r == nil {
				continue
			}
			builder.WriteString(printer.Plain(responsePrinter()).Sprintln(string(r.Bytes())))
			builder.WriteString(printer.Plain(durationPrinter()).Sprintf("%.2fs\n\n", r.Time.Seconds()))
		}
	}

	_, err := fmt.Fprint(p.writer, builder.String())

	return err
}

// WriteMatches writes the [scan.Match] instances found during the [scan],
// as plain text.
func (p Plain) WriteMatches(ctx context.Context, fs scan.FileSystem, includeResponses bool) error {
	_, err := fmt.Fprint(p.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Matches"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}

	for m := range ch {
		builder := strings.Builder{}
		builder.WriteString(printer.Plain(issuePrinter()).Sprintln(m.IssueName))
		builder.WriteString(printer.Plain(severityPrinter(m.IssueSeverity)).Sprintln(m.IssueSeverity))
		builder.WriteString(printer.Plain(confidencePrinter(m.IssueConfidence)).Sprintln(m.IssueConfidence))
		builder.WriteString(printer.Plain(typePrinter()).Sprintln(m.ProfileType))
		builder.WriteString(printer.Plain(urlPrinter()).Sprintln(m.URL))

		if len(m.IssueParam) > 0 {
			builder.WriteString(printer.Plain(paramPrinter()).Sprintln(m.IssueParam))
		}

		if m.Requests != nil {
			for _, r := range m.Requests {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(requestPrinter()).Sprintln(string(r.Bytes())))
			}
		}

		if m.Responses != nil && includeResponses {
			for _, r := range m.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(responsePrinter()).Sprintln(string(r.Bytes())))
				builder.WriteString(printer.Plain(durationPrinter()).Sprintf("%.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(p.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}

// WriteTasks writes the [scan.TaskSummary] instances to the [io.Writer] as plain text.
func (p Plain) WriteTasks(ctx context.Context, fs scan.FileSystem, allRequests, allResponses bool) error {
	_, err := fmt.Fprint(p.writer, pterm.DefaultSection.WithLevel(2).WithStyle(nil).Sprintln("Requests / Responses"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.TasksSummariesIterator(ctx)
	if err != nil {
		return err
	}

	for scanTask := range ch {
		builder := strings.Builder{}
		builder.WriteString(printer.Plain(urlPrinter()).Sprintln(scanTask.URL))

		if !allResponses && scanTask.Requests != nil {
			for _, r := range scanTask.Requests {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(requestPrinter()).Sprintln(string(r.Bytes())))
			}
		}

		if !allRequests && scanTask.Responses != nil {
			for _, r := range scanTask.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(printer.Plain(responsePrinter()).Sprintln(string(r.Bytes())))
				builder.WriteString(printer.Plain(durationPrinter()).Sprintf("%.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(p.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}
