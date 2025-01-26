package filesystem

import (
	"bufio"
	"context"
	"encoding/json"
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

	statsMtx  sync.Mutex
	statsFile afero.File

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
func New(fs afero.Fs, basePath string) (*Afero, error) {
	err := fs.MkdirAll(basePath, 0o755)
	if err != nil {
		return nil, err
	}

	statsFile, err := fs.OpenFile(statsFilePath(basePath), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o755)
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

		statsFile:     statsFile,
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

	if a.statsFile != nil {
		_ = a.statsFile.Close()
	}

	a.statsFile, err = a.fs.OpenFile(statsFilePath(a.basePath), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}

	bytes, err := json.Marshal(&stats)
	if err != nil {
		return err
	}

	_, err = a.statsFile.Write(bytes)

	return err
}

// LoadStats loads the [gbounty.Stats] from the file system.
func (a *Afero) LoadStats(ctx context.Context) (*gbounty.Stats, error) {
	logger.For(ctx).Debug("Loading stats from the file system...")

	a.statsMtx.Lock()
	defer a.statsMtx.Unlock()

	_, err := a.statsFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	bytes, err := io.ReadAll(a.statsFile)
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

// LoadErrors loads the [gbounty.Error] instances from the file system.
func (a *Afero) LoadErrors(ctx context.Context) ([]gbounty.Error, error) {
	logger.For(ctx).Info("Loading errors from the file system...")

	a.errorsMtx.Lock()
	defer a.errorsMtx.Unlock()

	// Get the current seek offset and defer reset
	currSeekOffset, err := a.errorsFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = a.errorsFile.Seek(currSeekOffset, io.SeekStart) }()

	_, err = a.errorsFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var scanErrors []gbounty.Error

	scanner := bufio.NewScanner(a.errorsFile)
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		var scanError gbounty.Error

		err := json.Unmarshal(scanner.Bytes(), &scanError)
		if err != nil {
			return nil, err
		}

		scanErrors = append(scanErrors, scanError)
	}

	if scanner.Err() != nil {
		logger.For(ctx).Errorf("Error while loading errors: %s", err)
	}

	return scanErrors, nil
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
	logger.For(ctx).Info("Reading errors from the file system...")

	a.errorsMtx.Lock()
	defer a.errorsMtx.Unlock()

	errorsFile, err := a.fs.OpenFile(errorsFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.Error)

	go func() {
		scanner := bufio.NewScanner(errorsFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() {
			var scanError gbounty.Error

			err := json.Unmarshal(scanner.Bytes(), &scanError)
			if err != nil {
				continue
			}

			ch <- scanError
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading errors: %s", err)
		}

		close(ch)
	}()

	return ch, func() { _ = errorsFile.Close() }, nil
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

// LoadMatches loads the [gbounty.Match] instances from the file system.
func (a *Afero) LoadMatches(ctx context.Context) ([]gbounty.Match, error) {
	logger.For(ctx).Info("Loading matches from the file system...")

	a.matchesMtx.Lock()
	defer a.matchesMtx.Unlock()

	// Get the current seek offset and defer reset
	currSeekOffset, err := a.matchesFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = a.matchesFile.Seek(currSeekOffset, io.SeekStart) }()

	_, err = a.matchesFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var scanMatches []gbounty.Match

	scanner := bufio.NewScanner(a.matchesFile)
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		var scanMatch gbounty.Match

		err := json.Unmarshal(scanner.Bytes(), &scanMatch)
		if err != nil {
			return nil, err
		}

		scanMatches = append(scanMatches, scanMatch)
	}

	if scanner.Err() != nil {
		logger.For(ctx).Errorf("Error while loading matches: %s", err)
	}

	return scanMatches, nil
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
		scanner := bufio.NewScanner(matchesFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() {
			var scanMatch gbounty.Match

			err := json.Unmarshal(scanner.Bytes(), &scanMatch)
			if err != nil {
				continue
			}

			ch <- scanMatch
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading matches: %s", err)
		}

		close(ch)
	}()

	return ch, func() { _ = matchesFile.Close() }, nil
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

// LoadTasksSummaries loads the [gbounty.TaskSummary] instances from the file system.
func (a *Afero) LoadTasksSummaries(ctx context.Context) ([]gbounty.TaskSummary, error) {
	logger.For(ctx).Info("Loading task summaries from the file system...")

	a.tasksMtx.Lock()
	defer a.tasksMtx.Unlock()

	// Get the current seek offset and defer reset
	currSeekOffset, err := a.tasksFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = a.tasksFile.Seek(currSeekOffset, io.SeekStart) }()

	_, err = a.tasksFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var scanTasks []gbounty.TaskSummary

	scanner := bufio.NewScanner(a.tasksFile)
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		var scanTask gbounty.TaskSummary

		err := json.Unmarshal(scanner.Bytes(), &scanTask)
		if err != nil {
			return nil, err
		}

		scanTasks = append(scanTasks, scanTask)
	}

	if scanner.Err() != nil {
		logger.For(ctx).Errorf("Error while loading task summaries: %s", err)
	}

	return scanTasks, nil
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
	logger.For(ctx).Info("Reading task summaries from the file system...")

	a.tasksMtx.Lock()
	defer a.tasksMtx.Unlock()

	tasksFile, err := a.fs.OpenFile(tasksFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan gbounty.TaskSummary)

	go func() {
		scanner := bufio.NewScanner(tasksFile)
		buf := make([]byte, maxCapacity)
		scanner.Buffer(buf, maxCapacity)

		for scanner.Scan() {
			var scanTask gbounty.TaskSummary

			err := json.Unmarshal(scanner.Bytes(), &scanTask)
			if err != nil {
				continue
			}

			ch <- scanTask
		}

		if scanner.Err() != nil {
			logger.For(ctx).Errorf("Error while reading task summaries: %s", err)
		}

		close(ch)
	}()

	return ch, func() { _ = tasksFile.Close() }, nil
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

// LoadTemplates loads the [gbounty.Template] instances from the file system.
func (a *Afero) LoadTemplates(ctx context.Context) ([]gbounty.Template, error) {
	logger.For(ctx).Info("Loading templates from the file system...")

	a.templatesMtx.Lock()
	defer a.templatesMtx.Unlock()

	// Get the current seek offset and defer reset
	currSeekOffset, err := a.templatesFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = a.templatesFile.Seek(currSeekOffset, io.SeekStart) }()

	_, err = a.templatesFile.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	var scanTemplates []gbounty.Template

	scanner := bufio.NewScanner(a.templatesFile)
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	for scanner.Scan() {
		var scanTemplate gbounty.Template

		err := json.Unmarshal(scanner.Bytes(), &scanTemplate)
		if err != nil {
			return nil, err
		}

		scanTemplates = append(scanTemplates, scanTemplate)
	}

	if scanner.Err() != nil {
		logger.For(ctx).Errorf("Error while loading templates: %s", err)
	}

	return scanTemplates, nil
}

// TemplatesIterator returns a channel that iterates over the [gbounty.Template] instances.
//
// It also returns a function that can be used to close the iterator (see [gbounty.CloseFunc]).
// The channel is closed when the iterator is done (no more elements), when the [gbounty.CloseFunc]
// is called, or when the context is canceled. Thus, the context cancellation can also be used
// to stop the iteration.
//
// It is the "streaming fashion" equivalent of [LoadTemplates()].
func (a *Afero) TemplatesIterator(ctx context.Context) (chan gbounty.Template, error) {
	logger.For(ctx).Info("Reading templates from the file system...")

	a.templatesMtx.RLock()

	templatesFile, err := a.fs.OpenFile(templatesFilePath(a.basePath), os.O_RDONLY, 0o755)
	if err != nil {
		a.templatesMtx.RUnlock()
		return nil, err
	}

	ch := make(chan gbounty.Template)

	go func() {
		// Once the iterator finishes, we close the file.
		defer func() {
			if err := templatesFile.Close(); err != nil {
				logger.For(ctx).Errorf("Error while closing templates file: %s", err)
			}
		}()
		// Unlock the mutex protecting the file.
		defer a.templatesMtx.RUnlock()
		// And close the channel used as the iterator.
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
			logger.For(ctx).Infof("Templates iterator was cancelled from context: %s", context.Cause(ctx))
		}
	}()

	return ch, nil
}

// Cleanup removes all the files from the file system.
func (a *Afero) Cleanup(ctx context.Context) error {
	logger.For(ctx).Info("Removing files from the file system...")
	toClose := []afero.File{a.statsFile, a.errorsFile, a.matchesFile, a.tasksFile, a.templatesFile}
	for _, f := range toClose {
		if err := f.Close(); err != nil {
			logger.For(ctx).Errorf("Error while closing file '%s': %v", f.Name(), err)
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
