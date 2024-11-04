package scan_test

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/platform/filesystem"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/profile/profilefakes"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/ulid"
)

func TestRunner(t *testing.T) {
	t.Parallel()

	t.Run("Nothing", func(t *testing.T) {
		t.Parallel()
		r := scan.NewRunner(nil)
		require.ErrorIs(t, r.Start(), scan.ErrMissingProfiles)
	})

	t.Run("SingleActiveProfile", func(t *testing.T) {
		t.Parallel()
		r := scan.NewRunner((&scan.RunnerOpts{}).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), scan.ErrMissingEntryPoints)
	})

	t.Run("SingleActiveProfile+Entrypoints", func(t *testing.T) {
		t.Parallel()
		r := scan.NewRunner((&scan.RunnerOpts{}).
			WithEntrypointFinders(entrypoint.Finders()).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), scan.ErrMissingRequestBuilder)
	})

	t.Run("SingleActiveProfile+Entrypoints+ReqBuilder", func(t *testing.T) {
		t.Parallel()
		r := scan.NewRunner((&scan.RunnerOpts{}).
			WithRequesterBuilder(func(_ *request.Request) (scan.Requester, error) {
				return &fakeRequester{}, nil
			}).
			WithEntrypointFinders(entrypoint.Finders()).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), scan.ErrMissingFileSystemAbstraction)
	})

	t.Run("SingleActiveProfile+Entrypoints+ReqBuilder+Fs", func(t *testing.T) {
		t.Parallel()

		aferoFs, basePath := initializeFsTest()
		fs, err := filesystem.New(aferoFs, basePath)
		require.NoError(t, err)

		r := scan.NewRunner((&scan.RunnerOpts{}).
			WithRequesterBuilder(func(_ *request.Request) (scan.Requester, error) {
				return &fakeRequester{}, nil
			}).
			WithFileSystem(fs).
			WithEntrypointFinders(entrypoint.Finders()).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.NoError(t, r.Start())
	})
}

type fakeRequester struct{}

func (fr *fakeRequester) Do(context.Context, *request.Request) (response.Response, error) {
	return response.Response{}, nil
}

func initializeFsTest() (*afero.MemMapFs, string) {
	fs := &afero.MemMapFs{}
	tmp := os.TempDir()
	id := ulid.New()

	return fs, tmp + id
}
