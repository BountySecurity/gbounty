package filesystem

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/spf13/afero"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/kit/logger"
)

const (
	// FileStats is the name of the file where the scan stats are saved to.
	FileStats = "stats.json"

	// FileErrors is the name of the file where the scan errors are saved to.
	FileErrors = "errors.json"

	// FileMatches is the name of the file where the scan matches are saved to.
	FileMatches = "matches.json"

	// FileTasks is the name of the file where the scan tasks are saved to.
	FileTasks = "tasks.json"

	// FileTemplates is the name of the file where the scan templates are saved to.
	FileTemplates = "templates.json"
)

const maxCapacity = 50e6

// Afero must implement the [gbounty.FileSystem] interface.
var _ gbounty.FileSystem = &Afero{}

// Afero is a [gbounty.FileSystem] implementation that uses the [afero.Fs] interface
// under the hood. So, it can rely on the [afero] package abstractions  to either
// use a regular (disk-based) file-system, or a virtual one (like in-memory).
type Afero struct {
	fs       afero.Fs
	basePath string

	statsMtx sync.Mutex

	errorsMtx  sync.Mutex
	errorsFile afero.File

	matchesMtx  sync.Mutex
	matchesFile afero.File

	tasksMtx  sync.Mutex
	tasksFile afero.File

	templatesMtx  sync.RWMutex
	templatesFile afero.File
}

// New creates a new [Afero] instance, using the given [afero.Fs] and the base path.
// It also creates and opens the necessary files, and it's your responsibility to close them once done.
func New(fs afero.Fs, basePath string) (*Afero, error) {
	err := fs.MkdirAll(basePath, 0o755)
	if err != nil {
		return nil, err
	}

	errorsFile, err := fs.OpenFile(errorsFilePath(basePath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o755)
	if err != nil {
		return nil, err
	}

	matchesFile, err := fs.OpenFile(matchesFilePath(basePath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o755)
	if err != nil {
		return nil, err
	}

	tasksFile, err := fs.OpenFile(tasksFilePath(basePath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o755)
	if err != nil {
		return nil, err
	}

	templatesFile, err := fs.OpenFile(templatesFilePath(basePath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o755)
	if err != nil {
		return nil, err
	}

	return &Afero{
		fs:       fs,
		basePath: basePath,

		errorsFile:    errorsFile,
		matchesFile:   matchesFile,
		tasksFile:     tasksFile,
		templatesFile: templatesFile,
	}, nil
}

// StoreStats stores the given [gbounty.Stats] into the file system.
func (a *Afero) StoreStats(ctx context.Context, stats *gbounty.Stats) error {
	logger.For(ctx).Debug("Storing stats into the file system...")

	var err error

	a.statsMtx.Lock()
	defer a.statsMtx.Unlock()

	statsFile, err := a.fs.OpenFile(statsFilePath(a.basePath), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		if err := statsFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close stats file after writing...	name=%s, err= %s",
				statsFile.Name(), err.Error(),
			)
		}
	}()

	bytes, err := json.Marshal(&stats)
	if err != nil {
		return err
	}

	_, err = statsFile.Write(bytes)

	return err
}

// LoadStats loads the [gbounty.Stats] from the file system.
func (a *Afero) LoadStats(ctx context.Context) (*gbounty.Stats, error) {
	logger.For(ctx).Debug("Loading stats from the file system...")

	var err error

	a.statsMtx.Lock()
	defer a.statsMtx.Unlock()

	statsFile, err := a.fs.OpenFile(statsFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := statsFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close stats file after reading...	name=%s, err= %s",
				statsFile.Name(), err.Error(),
			)
		}
	}()

	_, err = statsFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(statsFile)
	if err != nil {
		return nil, err
	}

	if len(bytes) == 0 {
		return nil, nil
	}

	scanStats := gbounty.Stats{}
	err = json.Unmarshal(bytes, &scanStats)
	if err != nil {
		return nil, err
	}

	return &scanStats, nil
}

// StoreError stores the given [gbounty.Error] into the file system.
func (a *Afero) StoreError(ctx context.Context, scanError gbounty.Error) error {
	logger.For(ctx).Debug("Storing error into the file system...")

	bytes, err := json.Marshal(&scanError)
	if err != nil {
		return err
	}

	a.errorsMtx.Lock()
	defer a.errorsMtx.Unlock()

	_, err = a.errorsFile.WriteString(string(bytes) + "\n")

	return err
}

// ErrorsIterator returns a channel that iterates over the [gbounty.Error] instances.
//
// It also returns a function that can be used to close the iterator (see [gbounty.CloseFunc]).
// The channel is closed when the iterator is done (no more elements), when the [gbounty.CloseFunc]
// is called, or when the context is canceled. Thus, the context cancellation can also be used
// to stop the iteration.
//
// It is the "streaming fashion" equivalent of [LoadErrors()].
func (a *Afero) ErrorsIterator(ctx context.Context) (chan gbounty.Error, gbounty.CloseFunc, error) {
	logger.For(ctx).Debug("Reading errors from the file system...")

	a.errorsMtx.Lock()
	defer a.errorsMtx.Unlock()

	errorsFile, err := a.fs.OpenFile(errorsFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.Error)

	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(errorsFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() && ctx.Err() == nil {
			var scanError gbounty.Error

			err := json.Unmarshal(scanner.Bytes(), &scanError)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
			case ch <- scanError:
			}
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading errors: %s", err)
		}

		if ctx.Err() != nil {
			logger.For(ctx).Debugf("Errors iterator was cancelled from context: %s", context.Cause(ctx))
		}
	}()

	return ch, func() {
		if err := errorsFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close errors file after reading...	name=%s, err= %s",
				errorsFile.Name(), err.Error(),
			)
		}
	}, nil
}

// CloseErrors closes the file where [gbounty.Error] are written to.
func (a *Afero) CloseErrors(ctx context.Context) error {
	logger.For(ctx).Debug("Closing errors file...")

	a.errorsMtx.Lock()
	defer a.errorsMtx.Unlock()

	if err := a.errorsFile.Close(); err != nil && !isFileClosedErr(err) {
		return err
	}

	return nil
}

// StoreMatch stores the given [gbounty.Match] into the file system.
func (a *Afero) StoreMatch(ctx context.Context, scanMatch gbounty.Match) error {
	logger.For(ctx).Debug("Storing match into the file system...")

	bytes, err := json.Marshal(&scanMatch)
	if err != nil {
		return err
	}

	a.matchesMtx.Lock()
	defer a.matchesMtx.Unlock()

	_, err = a.matchesFile.WriteString(string(bytes) + "\n")

	return err
}

// MatchesIterator returns a channel that iterates over the [gbounty.Match] instances.
//
// It also returns a function that can be used to close the iterator (see [gbounty.CloseFunc]).
// The channel is closed when the iterator is done (no more elements), when the [gbounty.CloseFunc]
// is called, or when the context is canceled. Thus, the context cancellation can also be used
// to stop the iteration.
//
// It is the "streaming fashion" equivalent of [LoadMatches()].
func (a *Afero) MatchesIterator(ctx context.Context) (chan gbounty.Match, gbounty.CloseFunc, error) {
	logger.For(ctx).Debug("Reading matches from the file system...")

	a.matchesMtx.Lock()
	defer a.matchesMtx.Unlock()

	matchesFile, err := a.fs.OpenFile(matchesFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.Match)

	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(matchesFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() && ctx.Err() == nil {
			var scanMatch gbounty.Match

			err := json.Unmarshal(scanner.Bytes(), &scanMatch)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
			case ch <- scanMatch:
			}
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading matches: %s", err)
		}

		if ctx.Err() != nil {
			logger.For(ctx).Debugf("Matches iterator was cancelled from context: %s", context.Cause(ctx))
		}
	}()

	return ch, func() {
		if err := matchesFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close matches file after reading...	name=%s, err= %s",
				matchesFile.Name(), err.Error(),
			)
		}
	}, nil
}

// CloseMatches closes the file where [gbounty.Match] are written to.
func (a *Afero) CloseMatches(ctx context.Context) error {
	logger.For(ctx).Debug("Closing matches file...")

	a.matchesMtx.Lock()
	defer a.matchesMtx.Unlock()

	if err := a.matchesFile.Close(); err != nil && !isFileClosedErr(err) {
		return err
	}

	return nil
}

// StoreTaskSummary stores the given [gbounty.TaskSummary] into the file system.
func (a *Afero) StoreTaskSummary(ctx context.Context, scanTaskSummary gbounty.TaskSummary) error {
	logger.For(ctx).Debug("Storing task summary into the file system...")

	bytes, err := json.Marshal(&scanTaskSummary)
	if err != nil {
		return err
	}

	a.tasksMtx.Lock()
	defer a.tasksMtx.Unlock()

	_, err = a.tasksFile.WriteString(string(bytes) + "\n")

	return err
}

// TasksSummariesIterator returns a channel that iterates over the [gbounty.TaskSummary] instances.
//
// It also returns a function that can be used to close the iterator (see [gbounty.CloseFunc]).
// The channel is closed when the iterator is done (no more elements), when the [gbounty.CloseFunc]
// is called, or when the context is canceled. Thus, the context cancellation can also be used
// to stop the iteration.
//
// It is the "streaming fashion" equivalent of [LoadTasksSummaries()].
func (a *Afero) TasksSummariesIterator(ctx context.Context) (chan gbounty.TaskSummary, gbounty.CloseFunc, error) {
	logger.For(ctx).Debug("Reading task summaries from the file system...")

	a.tasksMtx.Lock()
	defer a.tasksMtx.Unlock()

	tasksFile, err := a.fs.OpenFile(tasksFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.TaskSummary)

	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(tasksFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() && ctx.Err() == nil {
			var scanTask gbounty.TaskSummary

			err := json.Unmarshal(scanner.Bytes(), &scanTask)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
			case ch <- scanTask:
			}
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading task summaries: %s", err)
		}

		if ctx.Err() != nil {
			logger.For(ctx).Debugf("Tasks iterator was cancelled from context: %s", context.Cause(ctx))
		}
	}()

	return ch, func() {
		if err := tasksFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close tasks file after reading...	name=%s, err= %s",
				tasksFile.Name(), err.Error(),
			)
		}
	}, nil
}

// CloseTasksSummaries closes the file where [gbounty.TaskSummary] are written to.
func (a *Afero) CloseTasksSummaries(ctx context.Context) error {
	logger.For(ctx).Debug("Closing tasks summaries file...")

	a.tasksMtx.Lock()
	defer a.tasksMtx.Unlock()

	if err := a.tasksFile.Close(); err != nil && !isFileClosedErr(err) {
		return err
	}

	return nil
}

// StoreTemplate stores the given [gbounty.Template] into the file system.
func (a *Afero) StoreTemplate(ctx context.Context, scanTemplate gbounty.Template) error {
	logger.For(ctx).Debug("Storing template into the file system...")

	bytes, err := json.Marshal(&scanTemplate)
	if err != nil {
		return err
	}

	a.templatesMtx.Lock()
	defer a.templatesMtx.Unlock()

	_, err = a.templatesFile.WriteString(string(bytes) + "\n")

	return err
}

// CloseTemplates closes the file where [gbounty.Template] are written to.
func (a *Afero) CloseTemplates(ctx context.Context) error {
	logger.For(ctx).Debug("Closing templates file...")

	a.templatesMtx.Lock()
	defer a.templatesMtx.Unlock()

	if err := a.templatesFile.Close(); err != nil && !isFileClosedErr(err) {
		return err
	}

	return nil
}

// TemplatesIterator returns a channel that iterates over the [gbounty.Template] instances.
func (a *Afero) TemplatesIterator(ctx context.Context) (chan gbounty.Template, gbounty.CloseFunc, error) {
	logger.For(ctx).Debug("Reading templates from the file system...")

	a.templatesMtx.Lock()
	defer a.templatesMtx.Unlock()

	templatesFile, err := a.fs.OpenFile(templatesFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.Template)

	go func() {
		defer close(ch)
		scanner := bufio.NewScanner(templatesFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() && ctx.Err() == nil {
			var scanTemplate gbounty.Template

			err := json.Unmarshal(scanner.Bytes(), &scanTemplate)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
			case ch <- scanTemplate:
			}
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading templates: %s", err)
		}

		if ctx.Err() != nil {
			logger.For(ctx).Debugf("Templates iterator was cancelled from context: %s", context.Cause(ctx))
		}
	}()

	return ch, func() {
		if err := templatesFile.Close(); err != nil && !isFileClosedErr(err) {
			logger.For(ctx).Warnf("Cannot close templates file after reading...	name=%s, err= %s",
				templatesFile.Name(), err.Error(),
			)
		}
	}, nil
}

// Cleanup removes all the files from the file system.
func (a *Afero) Cleanup(ctx context.Context) error {
	logger.For(ctx).Info("Removing files from the file system...")
	closeFn := map[afero.File]func(ctx context.Context) error{
		a.errorsFile:    a.CloseErrors,
		a.matchesFile:   a.CloseMatches,
		a.tasksFile:     a.CloseTasksSummaries,
		a.templatesFile: a.CloseTemplates,
	}
	for f, fn := range closeFn {
		if err := fn(ctx); err != nil {
			logger.For(ctx).Warnf("Cannot close file during cleanup...	name=%s, err= %s",
				f.Name(), err.Error(),
			)
		}
	}
	return a.fs.RemoveAll(a.basePath)
}

func statsFilePath(basePath string) string {
	return fmt.Sprintf("%s/%s", basePath, FileStats)
}

func errorsFilePath(basePath string) string {
	return fmt.Sprintf("%s/%s", basePath, FileErrors)
}

func matchesFilePath(basePath string) string {
	return fmt.Sprintf("%s/%s", basePath, FileMatches)
}

func tasksFilePath(basePath string) string {
	return fmt.Sprintf("%s/%s", basePath, FileTasks)
}

func templatesFilePath(basePath string) string {
	return fmt.Sprintf("%s/%s", basePath, FileTemplates)
}

// isFileClosedErr returns true if the given error is a file closed error, which could be either
// [os.ErrClosed] or [afero.ErrFileClosed], because we use [afero] as an abstraction, which relies on [os] under the hood.
func isFileClosedErr(err error) bool {
	switch {
	case errors.Is(err, afero.ErrFileClosed):
		return true
	case errors.Is(err, os.ErrClosed):
		return true
	default:
		return false
	}
}
