package writer

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pterm/pterm"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/kit/console/color"
	"github.com/BountySecurity/gbounty/kit/console/printer"
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
)

const (
	clearLine       = "\033[2K"
	moveToBeginning = "\033[1G"
	resetLine       = clearLine + moveToBeginning
)

// Console must implement the [gbounty.Writer] and [WithProofOfConcept] interfaces.
var (
	_ gbounty.Writer     = &Console{}
	_ WithProofOfConcept = &Console{}
)

// Console is a [gbounty.Writer] implementation that writes the output
// to the given [io.Writer], following console/terminal standards
// in a human-friendly fashion.
type Console struct {
	writer     io.Writer
	pocEnabled bool
}

// NewConsole creates a new instance of [Console] with the given [io.Writer].
func NewConsole(writer io.Writer, opts ...Option) *Console {
	c := &Console{writer: writer}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Console) SetProofOfConcept(enabled bool) {
	c.pocEnabled = enabled
}

// WriteConfig writes the [gbounty.Config] to the console.
func (c *Console) WriteConfig(_ context.Context, cfg gbounty.Config) error {
	if c.pocEnabled {
		return nil
	}

	cyan := color.Cyan()
	lightCyan := color.LightCyan()
	infoPrinter := printer.Info()

	builder := strings.Builder{}
	builder.WriteString(defaultSection().Sprintln("# Configuration"))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Version:"), lightCyan.Sprintf("%s", cfg.Version)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Requests/sec:"), lightCyan.Sprintf("%d", cfg.RPS)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Concurrent URLs:"), lightCyan.Sprintf("%d", cfg.Concurrency)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Save on stop:"), lightCyan.Sprintf("%v", cfg.SaveOnStop)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n\n", cyan.Sprint("Memory-only:"), lightCyan.Sprintf("%v", cfg.InMemory)))

	if len(cfg.BlindHost) > 0 {
		builder.WriteString(infoPrinter.Sprintf("%s %s\n\n", cyan.Sprint("Blind host:"), lightCyan.Sprintf("%s", cfg.BlindHost)))
		builder.WriteString(infoPrinter.Sprintf("%s %s\n\n", cyan.Sprint("Blind host key:"), lightCyan.Sprintf("%s", cfg.BlindHostKey)))
	}

	_, err := fmt.Fprint(c.writer, builder.String())

	return err
}

// WriteStats writes the [gbounty.Stats] to the console.
func (c *Console) WriteStats(ctx context.Context, fs gbounty.FileSystem) error {
	if c.pocEnabled {
		return nil
	}

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

	cyan := color.Cyan()
	lightCyan := color.LightCyan()
	infoPrinter := printer.Info()

	builder := strings.Builder{}
	builder.WriteString(defaultSection().Sprintln("# Scan results"))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Insertion point(s) found:"), lightCyan.Sprintf("%d", stats.NumOfEntrypoints)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Request(s) finished:"), lightCyan.Sprintf("%d", stats.NumOfPerformedRequests)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Request(s) failed:"), lightCyan.Sprintf("%d", stats.NumOfFailedRequests)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Match(es) found:"), lightCyan.Sprintf("%d", stats.NumOfMatches)))
	builder.WriteString(infoPrinter.Sprintf("%s %s\n", cyan.Sprint("Elapsed time:"), lightCyan.Sprintf("%s", scanDuration)))

	_, err = fmt.Fprint(c.writer, builder.String())

	return err
}

// WriteMatchesSummary writes a summary of the [gbounty.Match] instances found during the scan, to the console.
func (c *Console) WriteMatchesSummary(ctx context.Context, fs gbounty.FileSystem) error {
	if c.pocEnabled {
		return nil
	}

	_, err := fmt.Fprint(c.writer, defaultSection().Sprintln("# Summary"))
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
		if !c.pocEnabled {
			builder.WriteString(issuePrinter().Sprintln(issueChunks[0]))
			builder.WriteString(severityPrinter(issueChunks[1]).Sprintln(issueChunks[1]))
			builder.WriteString(confidencePrinter(issueChunks[2]).Sprintln(issueChunks[2]))
			builder.WriteString(typePrinter().Sprintln(profileTypes[issue]))
			builder.WriteString(countPrinter().Sprintln(count))
		}

		urlsStr := urls[0]
		for _, url := range urls[1:] {
			urlsStr += "\n" + url
		}

		builder.WriteString(urlsPrinter().Sprintln(urlsStr))
		builder.WriteString("\n")

		_, err := fmt.Fprint(c.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	if !atLeastOne {
		_, err := fmt.Fprint(c.writer, infoPrinter().Sprintln(color.Cyan().Sprint("No matches found")))
		if err != nil {
			return err
		}
	}

	return nil
}

// WriteError writes the [gbounty.Error] to the console.
func (c *Console) WriteError(_ context.Context, scanError gbounty.Error) error {
	if c.pocEnabled {
		return nil
	}

	builder := strings.Builder{}
	builder.WriteString("\n")
	builder.WriteString(domainPrinter().Sprintln(scanError.Domain()))
	builder.WriteString(printer.Error().Sprintln(scanError.Err))

	if scanError.Requests != nil {
		for idx, r := range scanError.Requests {
			if r == nil {
				continue
			}
			if len(scanError.Requests) > 1 {
				builder.WriteString(requestNPrinter(idx + 1).Sprintln())
			} else {
				builder.WriteString(requestPrinter().Sprintln())
			}
			builder.WriteString(trimBytesNewline(r))
		}
	}

	if scanError.Responses != nil {
		for _, r := range scanError.Responses {
			if r == nil {
				continue
			}
			builder.WriteString(responsePrinter().Sprintln(trimBytesNewline(r)))
			builder.WriteString(durationPrinter().Sprintf("%.2fs\n\n", r.Time.Seconds()))
		}
	}

	_, err := fmt.Fprintln(c.writer, "\033[2K"+builder.String())

	return err
}

// WriteErrors writes the [gbounty.Error] instances to the console.
func (c *Console) WriteErrors(ctx context.Context, fs gbounty.FileSystem) error {
	if c.pocEnabled {
		return nil
	}

	_, err := fmt.Fprint(c.writer, defaultSection().Sprintln("## Errors"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.ErrorsIterator(ctx)
	if err != nil {
		return err
	}

	for scanError := range ch {
		builder := strings.Builder{}
		builder.WriteString(domainPrinter().Sprintln(scanError.Domain()))
		builder.WriteString(printer.Error().Sprintln(scanError.Err))

		if scanError.Requests != nil {
			for idx, r := range scanError.Requests {
				if r == nil {
					continue
				}
				if len(scanError.Requests) > 1 {
					builder.WriteString(requestNPrinter(idx + 1).Sprintln())
				} else {
					builder.WriteString(requestPrinter().Sprintln())
				}
				builder.WriteString(trimBytesNewline(r))
			}
		}

		if scanError.Responses != nil {
			for _, r := range scanError.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(responsePrinter().Sprintln(trimBytesNewline(r)))
				builder.WriteString(durationPrinter().Sprintf("%.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n")

		_, err := fmt.Fprintln(c.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}

// WriteMatch writes the [gbounty.Match] to the console.
func (c *Console) WriteMatch(_ context.Context, m gbounty.Match, _ bool) error {
	builder := strings.Builder{}
	if !c.pocEnabled {
		builder.WriteString("\n")
		builder.WriteString(issuePrinter().Sprintln(m.IssueName))
		builder.WriteString(severityPrinter(m.IssueSeverity).Sprintln(m.IssueSeverity))
		builder.WriteString(confidencePrinter(m.IssueConfidence).Sprintln(m.IssueConfidence))
		builder.WriteString(typePrinter().Sprintln(m.ProfileType))
		builder.WriteString(domainPrinter().Sprintln(m.Domain()))
		if len(m.IssueParam) > 0 {
			builder.WriteString(paramPrinter().Sprintln(m.IssueParam))
		}
	} else {
		builder.WriteString("\n")
		styledURL := pterm.NewStyle(pterm.FgLightCyan).Sprintln(m.Domain())
		builder.WriteString(styledURL)
	}

	to := max(len(m.Requests), len(m.Responses))
	for i := 0; i < to; i++ {
		if m.Requests != nil && i < len(m.Requests) && m.Requests[i] != nil {
			if !c.pocEnabled {
				if len(m.Requests) > 1 {
					builder.WriteString(requestNPrinter(i + 1).Sprintln())
				} else {
					builder.WriteString(requestPrinter().Sprintln())
				}
				builder.WriteString(trimBytesNewline(m.Requests[i]))
				builder.WriteString("\n")
			} else {
				styledText := pterm.NewStyle(pterm.FgLightCyan).Sprintln(trimBytesNewline(m.Requests[i]))
				builder.WriteString(styledText)
			}
		}

		if m.Responses != nil && i < len(m.Responses) && m.Responses[i] != nil && !c.pocEnabled {
			result := formatResponseWithHighlights(trimBytesNewline(m.Responses[i]), i, m)
			if len(m.Responses) > 1 {
				builder.WriteString(responseNPrinter(i + 1).Sprintln())
			} else {
				builder.WriteString(responsePrinter().Sprintln())
			}
			builder.WriteString(result)
			builder.WriteString("\n")
			builder.WriteString(durationPrinter().Sprintf("%.2fs\n\n", m.Responses[i].Time.Seconds()))
			builder.WriteString("\n")
		}
	}

	_, err := fmt.Fprint(c.writer, resetLine+builder.String())

	return err
}

func formatResponseWithHighlights(resAsString string, resIdx int, m gbounty.Match) string {
	occurrences := make([]occurrence.Occurrence, 0)
	if len(m.Occurrences) > resIdx && m.Occurrences[resIdx] != nil {
		occurrences = m.Occurrences[resIdx]
	}

	var result strings.Builder
	lastIndex := 0
	for _, occ := range occurrences {
		result.WriteString(resAsString[lastIndex:occ[0]])
		result.WriteString(color.Red().Sprint(resAsString[occ[0]:occ[1]]))
		lastIndex = occ[1]
	}

	if lastIndex < len(resAsString) {
		result.WriteString(resAsString[lastIndex:])
	}
	return result.String()
}

// WriteMatches writes the [gbounty.Match] instances found during the scan, to the console.
func (c *Console) WriteMatches(ctx context.Context, fs gbounty.FileSystem, _ bool) error {
	_, err := fmt.Fprint(c.writer, defaultSection().Sprintln("## Matches"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.MatchesIterator(ctx)
	if err != nil {
		return err
	}

	for m := range ch {
		builder := strings.Builder{}
		builder.WriteString(issuePrinter().Sprintln(m.IssueName))
		builder.WriteString(severityPrinter(m.IssueSeverity).Sprintln(m.IssueSeverity))
		builder.WriteString(confidencePrinter(m.IssueConfidence).Sprintln(m.IssueConfidence))
		builder.WriteString(typePrinter().Sprintln(m.ProfileType))
		builder.WriteString(domainPrinter().Sprintln(m.Domain()))

		if len(m.IssueParam) > 0 {
			builder.WriteString(paramPrinter().Sprintln(m.IssueParam))
		}

		to := max(len(m.Requests), len(m.Responses))
		for i := 0; i < to; i++ {
			if m.Requests != nil && i < len(m.Requests) && m.Requests[i] != nil {
				if len(m.Requests) > 1 {
					builder.WriteString(requestNPrinter(i + 1).Sprintln())
				} else {
					builder.WriteString(requestPrinter().Sprintln())
				}
				builder.WriteString(trimBytesNewline(m.Requests[i]))
				builder.WriteString("\n")
			}

			if m.Responses != nil && i < len(m.Responses) && m.Responses[i] != nil && !c.pocEnabled {
				result := formatResponseWithHighlights(trimBytesNewline(m.Responses[i]), i, m)
				if len(m.Responses) > 1 {
					builder.WriteString(responseNPrinter(i + 1).Sprintln())
				} else {
					builder.WriteString(responsePrinter().Sprintln())
				}
				builder.WriteString(result)
				builder.WriteString("\n")
				builder.WriteString(durationPrinter().Sprintf("%.2fs\n\n", m.Responses[i].Time.Seconds()))
				builder.WriteString("\n")
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(c.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}

// WriteTasks writes the [gbounty.TaskSummary] instances to the console.
func (c *Console) WriteTasks(ctx context.Context, fs gbounty.FileSystem, allRequests, allResponses bool) error {
	if c.pocEnabled {
		return nil
	}

	_, err := fmt.Fprint(c.writer, defaultSection().Sprintln("## Requests / Responses"))
	if err != nil {
		return err
	}

	ch, closeIt, err := fs.TasksSummariesIterator(ctx)
	if err != nil {
		return err
	}

	for scanTask := range ch {
		builder := strings.Builder{}
		builder.WriteString(domainPrinter().Sprintln(scanTask.Domain()))

		if !allResponses && scanTask.Requests != nil {
			for idx, r := range scanTask.Requests {
				if r == nil {
					continue
				}
				if len(scanTask.Requests) > 1 {
					builder.WriteString(requestNPrinter(idx + 1).Sprintln())
				} else {
					builder.WriteString(requestPrinter().Sprintln())
				}
				builder.WriteString(trimBytesNewline(r))
			}
		}

		if !allRequests && scanTask.Responses != nil {
			for _, r := range scanTask.Responses {
				if r == nil {
					continue
				}
				builder.WriteString(responsePrinter().Sprintln(trimBytesNewline(r)))
				builder.WriteString(durationPrinter().Sprintf("%.2fs\n\n", r.Time.Seconds()))
			}
		}

		builder.WriteString("\n\n")

		_, err := fmt.Fprint(c.writer, builder.String())
		if err != nil {
			return err
		}
	}

	closeIt()

	return nil
}

func defaultSection() pterm.SectionPrinter {
	return pterm.SectionPrinter{
		Style:           &pterm.ThemeDefault.SectionStyle,
		Level:           1,
		TopPadding:      1,
		BottomPadding:   1,
		IndentCharacter: "",
	}
}
