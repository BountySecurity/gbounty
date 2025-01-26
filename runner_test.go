package gbounty_test

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/kit/ulid"
	"github.com/BountySecurity/gbounty/platform/filesystem"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/profile/profilefakes"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

func TestRunner(t *testing.T) {
	t.Parallel()

	t.Run("Nothing", func(t *testing.T) {
		t.Parallel()
		r := gbounty.NewRunner(nil)
		require.ErrorIs(t, r.Start(), gbounty.ErrMissingProfiles)
	})

	t.Run("SingleActiveProfile", func(t *testing.T) {
		t.Parallel()
		r := gbounty.NewRunner((&gbounty.RunnerOpts{}).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), gbounty.ErrMissingEntryPoints)
	})

	t.Run("SingleActiveProfile+Entrypoints", func(t *testing.T) {
		t.Parallel()
		r := gbounty.NewRunner((&gbounty.RunnerOpts{}).
			WithEntrypointFinders(entrypoint.Finders()).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), gbounty.ErrMissingRequestBuilder)
	})

	t.Run("SingleActiveProfile+Entrypoints+ReqBuilder", func(t *testing.T) {
		t.Parallel()
		r := gbounty.NewRunner((&gbounty.RunnerOpts{}).
			WithRequesterBuilder(func(_ *request.Request) (gbounty.Requester, error) {
				return &fakeRequester{}, nil
			}).
			WithEntrypointFinders(entrypoint.Finders()).
			WithActiveProfiles([]*profile.Active{
				profilefakes.SQLiTimeBased(),
			}))
		require.ErrorIs(t, r.Start(), gbounty.ErrMissingFileSystemAbstraction)
	})

	t.Run("SingleActiveProfile+Entrypoints+ReqBuilder+Fs", func(t *testing.T) {
		t.Parallel()

		aferoFs, basePath := initializeFsTest()
		fs, err := filesystem.New(aferoFs, basePath)
		require.NoError(t, err)

		r := gbounty.NewRunner((&gbounty.RunnerOpts{}).
			WithRequesterBuilder(func(_ *request.Request) (gbounty.Requester, error) {
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
