package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pterm/pterm"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/kit/selfupdate"
	"github.com/BountySecurity/gbounty/kit/semver"
	"github.com/BountySecurity/gbounty/kit/slices"
)

const (
	gitHubSlugEnvVar  = "GBOUNTY_GITHUB_SLUG"
	defaultGitHubSlug = "BountySecurity/gbounty"

	gitHubProfilesSlugEnvVar  = "GBOUNTY_GITHUB_PROFILES_SLUG"
	defaultGitHubProfilesSlug = "BountySecurity/gbounty-profiles"
)

var (
	errNoApplicationReleaseFound = errors.New("no application release found")
	errNoProfilesReleaseFound    = errors.New("no profiles release found")
)

func checkVer() (u update, err error) {
	// In general, we don't error out in this function fails, we just print a warning.
	// But, if there is a panic, we want to catch it and error out.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r) //nolint:err113
		}
	}()

	appUpdate, appErr := updateAppNeeds()
	if appErr != nil {
		pterm.Warning.Printfln("Could not detect if there are application updates available: %s", appErr.Error())
	}

	latestProfilesRelease, profErr := latestProfileRelease()
	if profErr != nil {
		pterm.Warning.Printfln("Could not detect if there are profile updates available: %s", profErr.Error())
		return update{
			app: appUpdate,
		}, nil
	}

	if slices.In(os.Args, "--force-update-profiles") {
		return update{
			app: appUpdate,
			profiles: updateNeeds{
				needed:  true,
				current: semver.Zero().String(),
				latest:  latestProfilesRelease,
			},
		}, nil
	}

	profilesDir, profErr := getProfilesDir()
	if profErr != nil {
		switch {
		case errors.Is(profErr, errMultipleProfilesFlag) || errors.Is(profErr, errProfileFlagIsAFile):
			pterm.Warning.Println("You either provided a specific profile file or more than one profile(s) path.")
			pterm.Warning.Println("So, skipping profiles update check...")
		case errors.Is(profErr, errNoProfilesFlag):
			pterm.Info.Println("No profiles were found, and no profiles path (-p/--profiles) was specified.")
			pterm.Info.Println("So, the official profiles will be downloaded...")
			return update{
				app: appUpdate,
				profiles: updateNeeds{
					needed:  true,
					current: semver.Zero().String(),
					latest:  latestProfilesRelease,
				},
			}, nil
		default:
			pterm.Warning.Printf("Unexpected error happened while checking the current profiles version: %s\n", profErr.Error())
			pterm.Warning.Println("So, skipping profiles update check...")
		}
		fmt.Println() //nolint:forbidigo
		return update{
			app: appUpdate,
		}, nil
	}

	currentProfilesVersion, profErr := detectProfilesVersion(profilesDir)
	if profErr != nil {
		if errors.Is(profErr, git.ErrRepositoryNotExists) {
			pterm.Warning.Println("Looks like you are not using the official GBounty profiles repository.")
			pterm.Warning.Println("So, skipping profiles update check...")
			return update{
				app: appUpdate,
			}, nil
		}
		if errors.Is(profErr, errProfilesRepositoryIsNotClean) ||
			errors.Is(profErr, errProfilesRepositoryUnknownState) {
			pterm.Warning.Println("The profiles repository is either not clean, or in an unknown state, so skipping profiles update check...")
			pterm.Warning.Println("You can use the --force-update-profiles flag to force the download of the latest version.")
			return update{
				app: appUpdate,
			}, nil
		}

		pterm.Warning.Printf("Unexpected error happened while checking profiles version: %s\n", profErr.Error())
		pterm.Warning.Println("So, skipping profiles update check...")
		return update{
			app: appUpdate,
		}, nil
	}

	return update{
		app: appUpdate,
		profiles: updateNeeds{
			needed:  currentProfilesVersion.ShouldUpdate(latestProfilesRelease.Version),
			current: currentProfilesVersion.String(),
			latest:  latestProfilesRelease,
		},
	}, nil
}

func updateAppNeeds() (updateNeeds, error) {
	// Enable slug override via an environment variable.
	slug := defaultGitHubSlug
	if s, defined := os.LookupEnv(gitHubSlugEnvVar); defined {
		slug = s
	}

	// Detect the latest release.
	rel, ok, err := selfupdate.DetectLatest(context.Background(), slug, true)
	if err != nil {
		return updateNeeds{}, err
	}
	if !ok {
		return updateNeeds{}, errNoApplicationReleaseFound
	}

	// Determine whether an update is available for the application, or not.
	appVer := semver.MustParse(gbounty.Version)
	return updateNeeds{
		current: appVer.String(),
		latest:  rel,
		needed:  appVer.ShouldUpdate(rel.Version),
	}, nil
}

func latestProfileRelease() (*selfupdate.Release, error) {
	// Enable slug override via an environment variable.
	slug := defaultGitHubProfilesSlug
	if s, defined := os.LookupEnv(gitHubProfilesSlugEnvVar); defined {
		slug = s
	}
	// Detect the latest release.
	rel, ok, err := selfupdate.DetectLatest(context.Background(), slug, false)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errNoProfilesReleaseFound
	}

	return rel, nil
}

var (
	errProfilesRepositoryIsNotClean   = errors.New("profiles repository is not clean")
	errProfilesRepositoryUnknownState = errors.New("profiles repository is in an unknown state")
)

func detectProfilesVersion(path string) (semver.Version, error) {
	// Open the repository in the given path.
	// At this point, we assume the path is a directory, and it contains a Git repository.
	repo, err := git.PlainOpen(path)
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to open the profiles repository: %w", err)
	}

	// Check if the repository's worktree is clean. Otherwise, it's risky to proceed.
	worktree, err := repo.Worktree()
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to read the worktree of the profiles repository: %w", err)
	}
	worktreeStatus, err := worktree.Status()
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to read the worktree of the profiles repository: %w", err)
	}
	if !worktreeStatus.IsClean() {
		return semver.Version{}, errProfilesRepositoryIsNotClean
	}

	// Get the HEAD reference.
	ref, err := repo.Head()
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to read the profiles repository HEAD: %w", err)
	}

	// HEAD is not detached. So, probably it isn't on a known tag.
	if ref.Name() != plumbing.HEAD {
		return semver.Version{}, errProfilesRepositoryUnknownState
	}

	// Fetch the tags from remote.
	err = repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{"refs/tags/*:refs/tags/*"},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return semver.Version{}, fmt.Errorf("failed to fetch the profiles repository: %w", err)
	}

	// Check if the current commit is a tag.
	tags, err := repo.Tags()
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to list the profiles repository tags: %w", err)
	}

	var refName plumbing.ReferenceName
	err = tags.ForEach(func(tag *plumbing.Reference) error {
		commitHash, err := repo.ResolveRevision(plumbing.Revision(tag.Name().String()))
		if err != nil {
			return err
		}

		if commitHash.String() == ref.Hash().String() {
			refName = tag.Name()
			return nil
		}

		return nil
	})
	if err != nil {
		return semver.Version{}, fmt.Errorf("failed to iterate over the profiles repository tags: %w", err)
	}

	// Current commit doesn't match any release tag.
	if len(refName) == 0 {
		return semver.Version{}, errProfilesRepositoryUnknownState
	}

	ver, err := semver.ShouldParse(filepath.Base(string(refName)))
	if err != nil {
		err = errors.Join(err, errProfilesRepositoryUnknownState)
	}

	return ver, err
}

const (
	profilesDirName = "profiles"
)

var (
	errNoProfilesFlag       = errors.New("no profiles flag specified")
	errMultipleProfilesFlag = errors.New("multiple profiles flag specified")
	errProfileFlagIsAFile   = errors.New("specified profiles flag is a file")
)

func getProfilesDir() (string, error) {
	flag, err := getProfilesFlag()
	switch {
	// We'll use either the one from $HOME
	// or the one in the current working directory.
	case errors.Is(err, errNoProfilesFlag):
		break
	// We propagate the error, no updates check
	case errors.Is(err, errMultipleProfilesFlag):
		return "", err
	// Happy path, single profiles flag
	case err == nil:
		s, err := os.Stat(flag)
		if err != nil {
			return "", err
		}

		if !s.IsDir() {
			return "", errProfileFlagIsAFile
		}

		return filepath.Abs(flag)
	}

	if location := defaultProfilesLocation(); len(location) > 0 {
		return location, nil
	}
	return "", errNoProfilesFlag
}

func getProfilesFlag() (string, error) {
	const (
		short = "-p"
		long  = "--profiles"
	)

	count := slices.Occurrences(os.Args, short) + slices.Occurrences(os.Args, long)
	switch count {
	case 0:
		return "", errNoProfilesFlag
	case 1:
		break
	default:
		return "", errMultipleProfilesFlag
	}

	// We may need to cover the case when the flag
	// is specified with '=' syntax.
	if val, ok := slices.ValForKey(os.Args, short); ok {
		return val, nil
	}

	if val, ok := slices.ValForKey(os.Args, long); ok {
		return val, nil
	}

	return "", errNoProfilesFlag
}

func defaultProfilesLocation() string {
	// We first try with:
	// 	$HOME/.gbounty/profiles
	dir, err := gbountyDir()
	if err != nil {
		return ""
	}
	homeProfilesDir := filepath.Join(dir, profilesDirName)

	stat, err := os.Stat(homeProfilesDir)
	// If it exists and is a dir
	if err == nil && stat.IsDir() {
		return homeProfilesDir
	}

	// Otherwise, we'll try with $CWD
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}

	cwdProfilesDir := filepath.Join(cwd, profilesDirName)
	stat, err = os.Stat(cwdProfilesDir)
	// If it exists and is a dir
	if err == nil && stat.IsDir() {
		return cwdProfilesDir
	}

	return ""
}

type update struct {
	app      updateNeeds
	profiles updateNeeds
}

type updateNeeds struct {
	needed  bool
	current string
	latest  *selfupdate.Release
}
