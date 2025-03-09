package filesystem_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/kit/ulid"
	"github.com/BountySecurity/gbounty/platform/filesystem"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

func TestAfero_New(t *testing.T) {
	t.Parallel()

	t.Run("no existing directory", func(t *testing.T) {
		t.Parallel()

		fs, basePath := initializeFsTest()

		_, err := filesystem.New(fs, basePath)
		require.NoError(t, err)

		assertEmptyFiles(t, fs, basePath)
	})

	t.Run("existing directory", func(t *testing.T) {
		t.Parallel()

		fs, basePath := initializeFsTest()

		aferoFS, err := filesystem.New(fs, basePath)
		require.NoError(t, err)

		stats := initializeTestData(t, aferoFS, fs, basePath)
		assertNonEmptyFiles(t, fs, basePath, stats)
	})
}

func TestAfero_LoadStats(t *testing.T) {
	t.Parallel()

	fs, basePath := initializeFsTest()

	aferoFS, err := filesystem.New(fs, basePath)
	require.NoError(t, err)

	storeSomeStats(t, aferoFS)

	scanStats, err := aferoFS.LoadStats(context.Background())
	require.NoError(t, err)

	assert.EqualValues(t, &gbounty.Stats{}, scanStats)
}

func TestAfero_ErrorsIterator(t *testing.T) {
	t.Parallel()

	fs, basePath := initializeFsTest()

	aferoFS, err := filesystem.New(fs, basePath)
	require.NoError(t, err)

	storeSomeErrors(t, aferoFS)

	var numErrors int

	scanErrorsIterator, closeIt, err := aferoFS.ErrorsIterator(context.Background())
	require.NoError(t, err)
	defer closeIt()

	for scanError := range scanErrorsIterator {
		numErrors++

		assert.Equal(t, dummyError(), scanError)
	}

	assert.Equal(t, 5, numErrors)
}

func TestAfero_MatchesIterator(t *testing.T) {
	t.Parallel()

	fs, basePath := initializeFsTest()

	aferoFS, err := filesystem.New(fs, basePath)
	require.NoError(t, err)

	storeSomeMatches(t, aferoFS)

	var numMatches int

	scanMatchesIterator, closeIt, err := aferoFS.MatchesIterator(context.Background())
	require.NoError(t, err)
	defer closeIt()

	for scanMatch := range scanMatchesIterator {
		numMatches++

		assert.Equal(t, dummyMatch(), scanMatch)
	}

	assert.Equal(t, 5, numMatches)
}

func TestAfero_TasksSummariesIterator(t *testing.T) {
	t.Parallel()

	fs, basePath := initializeFsTest()

	aferoFS, err := filesystem.New(fs, basePath)
	require.NoError(t, err)

	storeSomeTaskSummaries(t, aferoFS)

	var numTasks int

	scanTasksIterator, closeIt, err := aferoFS.TasksSummariesIterator(context.Background())
	require.NoError(t, err)

	for scanTask := range scanTasksIterator {
		numTasks++

		assert.Equal(t, dummyTask(), scanTask)
	}

	closeIt()

	assert.Equal(t, 5, numTasks)
}

func TestAfero_TemplatesIterator(t *testing.T) {
	t.Parallel()

	fs, basePath := initializeFsTest()

	aferoFS, err := filesystem.New(fs, basePath)
	require.NoError(t, err)

	storeSomeTemplates(t, aferoFS)

	var numTemplates int

	scanTemplatesIterator, closeIt, err := aferoFS.TemplatesIterator(context.Background())
	require.NoError(t, err)
	defer closeIt()

	for scanTemplate := range scanTemplatesIterator {
		numTemplates++

		assert.Equal(t, dummyTemplate(), scanTemplate)
	}

	assert.Equal(t, 5, numTemplates)
}

func initializeFsTest() (*afero.MemMapFs, string) {
	fs := &afero.MemMapFs{}
	tmp := os.TempDir()
	id := ulid.New()

	return fs, tmp + id
}

func initializeTestData(t *testing.T, aferoFS *filesystem.Afero, fs afero.Fs, basePath string) []os.FileInfo {
	t.Helper()

	storeSomeStats(t, aferoFS)

	statsInfo, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, filesystem.FileStats))
	require.NoError(t, err)

	storeSomeErrors(t, aferoFS)

	errorsInfo, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, filesystem.FileErrors))
	require.NoError(t, err)

	storeSomeMatches(t, aferoFS)

	matchesInfo, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, filesystem.FileMatches))
	require.NoError(t, err)

	storeSomeTaskSummaries(t, aferoFS)

	tasksInfo, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, filesystem.FileTasks))
	require.NoError(t, err)

	storeSomeTemplates(t, aferoFS)

	templatesInfo, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, filesystem.FileTemplates))
	require.NoError(t, err)

	return []os.FileInfo{statsInfo, errorsInfo, matchesInfo, tasksInfo, templatesInfo}
}

func storeSomeStats(t *testing.T, aferoFS *filesystem.Afero) {
	t.Helper()

	require.NoError(t, aferoFS.StoreStats(context.Background(), &gbounty.Stats{}))
}

func storeSomeErrors(t *testing.T, aferoFS *filesystem.Afero) {
	t.Helper()

	for i := 0; i < 5; i++ {
		require.NoError(t, aferoFS.StoreError(context.Background(), dummyError()))
	}
}

func storeSomeMatches(t *testing.T, aferoFS *filesystem.Afero) {
	t.Helper()

	for i := 0; i < 5; i++ {
		require.NoError(t, aferoFS.StoreMatch(context.Background(), dummyMatch()))
	}
}

func storeSomeTaskSummaries(t *testing.T, aferoFS *filesystem.Afero) {
	t.Helper()

	for i := 0; i < 5; i++ {
		require.NoError(t, aferoFS.StoreTaskSummary(context.Background(), dummyTask()))
	}
}

func storeSomeTemplates(t *testing.T, aferoFS *filesystem.Afero) {
	t.Helper()

	for i := 0; i < 5; i++ {
		require.NoError(t, aferoFS.StoreTemplate(context.Background(), dummyTemplate()))
	}
}

func assertEmptyFiles(t *testing.T, fs afero.Fs, basePath string) {
	t.Helper()

	toBeCreated := []string{filesystem.FileErrors, filesystem.FileMatches, filesystem.FileTasks}

	for _, f := range toBeCreated {
		stat, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, f))
		require.NoError(t, err)
		assert.Equal(t, int64(0), stat.Size())
	}
}

func assertNonEmptyFiles(t *testing.T, fs afero.Fs, basePath string, stats []os.FileInfo) {
	t.Helper()

	for _, stat := range stats {
		currStat, err := fs.Stat(fmt.Sprintf("%s/%s", basePath, stat.Name()))
		require.NoError(t, err)
		assert.Equal(t, stat.Size(), currStat.Size())
		assert.NotEqual(t, stat.ModTime(), currStat.Size())
	}
}

func dummyError() gbounty.Error {
	return gbounty.Error{
		URL:       "localhost:8080",
		Requests:  []*request.Request{dummyRequest()},
		Responses: []*response.Response{dummyResponse()},
		Err:       "something went wrong",
	}
}

func dummyMatch() gbounty.Match {
	return gbounty.Match{
		URL:             "localhost:8080",
		Requests:        []*request.Request{dummyRequest()},
		Responses:       []*response.Response{dummyResponse()},
		IssueName:       "Issue for tests",
		IssueSeverity:   "Low",
		IssueConfidence: "Tentative",
		IssueParam:      "URL Path",
		ProfileType:     "Active",
	}
}

func dummyTask() gbounty.TaskSummary {
	return gbounty.TaskSummary{
		URL:       "localhost:8080",
		Requests:  []*request.Request{dummyRequest()},
		Responses: []*response.Response{dummyResponse()},
	}
}

func dummyTemplate() gbounty.Template {
	return gbounty.Template{
		Request: *dummyRequest(),
	}
}

func dummyRequest() *request.Request {
	return &request.Request{
		URL:    "http://localhost:8080",
		Method: "POST",
		Path:   "/search.php?test=query",
		Proto:  "HTTP/1.1",
		Headers: map[string][]string{
			"Host":                      {"testphp.vulnweb.com"},
			"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
			"Accept-Language":           {"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3"},
			"Accept-Encoding":           {"gzip, deflate"},
			"Content-Type":              {"application/x-www-form-urlencoded"},
			"Content-Length":            {"26"},
			"Origin":                    {"http://testphp.vulnweb.com"},
			"Dnt":                       {"1"},
			"Connection":                {"close"},
			"Referer":                   {"http://testphp.vulnweb.com/search.php?test=query"},
			"Upgrade-Insecure-Requests": {"1"},
		},
		Body: []byte(`searchFor=test&goButton=go

`),
	}
}

func dummyResponse() *response.Response {
	return &response.Response{
		Code:   404,
		Status: "Not Found",
		Proto:  "HTTP/1.1",
		Headers: map[string][]string{
			"Server":         {"nginx/1.19.0"},
			"Date":           {"Sun, 07 Feb 2021 23:44:49 GMT"},
			"Content-Type":   {"text/html; charset=utf-8"},
			"Connection":     {"close"},
			"Content-Length": {"150"},
		},
		Body: []byte(`<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.19.0</center>
</body>
</html>
`),
	}
}
