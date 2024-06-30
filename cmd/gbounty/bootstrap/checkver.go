package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/cmd/version"
	"github.com/bountysecurity/gbounty/kit/selfupdate"
	"github.com/bountysecurity/gbounty/kit/semver"
	"github.com/bountysecurity/gbounty/kit/slices"
)

const (
	gitHubSlugEnvVar  = "GBOUNTY_GITHUB_SLUG"
	defaultGitHubSlug = "BountySecurity/gbounty"

	gitHubProfilesSlugEnvVar  = "GBOUNTY_GITHUB_PROFILES_SLUG"
	defaultGitHubProfilesSlug = "BountySecurity/gbounty-profiles"
)

func checkVer() (u update, err error) {
	// In general, we don't error out in this function fails, we just print a warning.
	// But, if there is a panic, we want to catch it and error out.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
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

	profilesDir, profErr := getProfilesDir()
	if profErr != nil {
		switch {
		case errors.Is(profErr, errMultipleProfilesFlag) || errors.Is(profErr, errProfileFlagIsAFile):
			pterm.Warning.Println("You either provided a specific profile file or more than one profile(s) path.")
			pterm.Warning.Println("So, skipping profiles update check...")
		case errors.Is(profErr, errNoProfilesFlag):
			// TODO: Download profiles from the latest release.
			pterm.Info.Println("No profiles path (-p/--profiles) specified nor default one found, will download...")
			return update{
				app: appUpdate,
				profiles: updateNeeds{
					needed:  true,
					current: semver.Zero().String(),
					latest:  latestProfilesRelease,
				},
			}, nil
		default:
			pterm.Warning.Printf("Unexpected error happened while checking the current profiles version: %s\n", err.Error())
			pterm.Warning.Println("So, skipping profiles update check...")
		}
		fmt.Println() //nolint:forbidigo
		return update{
			app: appUpdate,
		}, nil
	}

	profilesVersionFile, profErr := profilesVersionFilePath(profilesDir)
	if profErr != nil {
		if errors.Is(profErr, errProfileFlagIsAFile) {
			pterm.Warning.Println("You either provided a specific profile file or more than one profile(s) path.")
			pterm.Warning.Println("So, skipping profiles update check...")
		} else {
			pterm.Warning.Printf("Unexpected error happened while checking profiles version: %s\n", err.Error())
			pterm.Warning.Println("So, skipping profiles update check...")
		}
		fmt.Println() //nolint:forbidigo
		return update{
			app: appUpdate,
		}, nil
	}

	currentProfilesVersion, profErr := readProfilesVersionFile(profilesVersionFile)
	if profErr != nil {
		pterm.Warning.Printf("Unexpected error happened while checking profiles version: %s\n", err.Error())
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
	rel, ok, err := selfupdate.DetectLatest(context.Background(), slug)
	if err != nil {
		return updateNeeds{}, err
	}
	if !ok {
		return updateNeeds{}, errors.New("no application release found")
	}

	// Determine whether an update is available for the application, or not.
	appVer := semver.MustParse(version.Version)
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
	rel, ok, err := selfupdate.DetectLatest(context.Background(), slug)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("no profiles release found")
	}

	return rel, nil
}

func readProfilesVersionFile(path string) (semver.Version, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return semver.Zero(), nil
		}
		return semver.Version{}, err
	}

	return semver.ShouldParse(strings.TrimSpace(string(b)))
}

const (
	profilesDirName         = "profiles"
	profilesVersionFileName = "version.txt"
)

var (
	errNoProfilesFlag       = errors.New("no profiles flag specified")
	errMultipleProfilesFlag = errors.New("multiple profiles flag specified")
	errProfileFlagIsAFile   = errors.New("specified profiles flag is a file")
)

func profilesVersionFilePath(dir string) (string, error) {
	s, err := os.Stat(dir)
	if err != nil {
		return "", err
	}

	if !s.IsDir() {
		return "", errProfileFlagIsAFile
	}

	return filepath.Join(dir, profilesVersionFileName), nil
}

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
