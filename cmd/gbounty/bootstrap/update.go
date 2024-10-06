package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/kit/die"
	"github.com/bountysecurity/gbounty/kit/osext"
	"github.com/bountysecurity/gbounty/kit/selfupdate"
	"github.com/bountysecurity/gbounty/kit/semver"
	"github.com/bountysecurity/gbounty/kit/slices"
)

func getLastCheckTime() (time.Time, error) {
	filePath, err := lastCheckFilePath()
	if err != nil {
		return time.Time{}, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, string(data))
}
func checkForUpdatesRequired() bool {
	lastCheckTime, err := getLastCheckTime()
	currentTime := time.Now()

	if err != nil || lastCheckTime.IsZero() || currentTime.Sub(lastCheckTime) > UpdateInterval {
		pterm.Info.Println("Updates Required. Checking for updates...")
		return true
	}
	pterm.Info.Println("Updates Not Required.")
	return false
}

func CheckForUpdates() {
	// Disable checks on CI jobs and when updates not required.
	if _, isCI := os.LookupEnv("CI"); isCI || !checkForUpdatesRequired() {
		return
	}
	updateLastCheckFile()

	// Ensure the home directory exists.
	die.OnErr(homeDir, "Failed to create the $HOME directory (.gbounty)")

	// Fetch current and latest version.
	update := die.OrRet(checkVer, "Could not detect if there are updates available")

	// If no update is needed, return.
	if !(update.app.needed || update.profiles.needed) {
		return
	}

	// Parse CLI arguments to determine if the user wants to update.
	var appUpdate, profUpdate, forceProfUpdate bool
	if slices.In(os.Args, "--update") {
		appUpdate, profUpdate = true, true
	} else {
		appUpdate = slices.In(os.Args, "--update-app")
		profUpdate = slices.In(os.Args, "--update-profiles")

		cloneProfiles := update.profiles.needed && update.profiles.current == semver.Zero().String()
		forceProfUpdate = cloneProfiles || slices.In(os.Args, "--force-update-profiles")
	}

	wg := new(sync.WaitGroup)

	// Update application (if needed)
	if update.app.needed {
		if appUpdate {
			pterm.Info.Println("Self-updating application...")
			wg.Add(1)
			updateApp := func() error { defer wg.Done(); return updateApp(update.app) }
			go die.OnErr(updateApp, "Failed to update the application")
		} else {
			pterm.Info.Printf("There is a new app version available: %s (curr. %s)\n",
				update.app.latest.Version, update.app.current)
			pterm.Info.Println("Use --update or --update-app to update")
		}
	}

	if update.profiles.needed {
		if profUpdate || forceProfUpdate {
			pterm.Info.Println("Downloading new profiles...")
			wg.Add(1)
			checkoutProfiles := func() error { defer wg.Done(); return checkoutProfiles(update.profiles, forceProfUpdate) }
			go die.OnErr(checkoutProfiles, "Failed to check out the profiles")
		} else {
			pterm.Info.Printf("There is a new profiles version available: %s (curr. %s)\n",
				update.profiles.latest.Version, update.profiles.current)
			pterm.Info.Println("Use --update or --update-profiles to update")
		}
	}

	// Wait till updates finish
	wg.Wait()

	if update.app.needed && appUpdate {
		pterm.Success.Println("Application updated successfully!")
	}

	if update.profiles.needed && (profUpdate || forceProfUpdate) {
		pterm.Success.Println("Profiles downloaded successfully!")
	}

	fmt.Println() //nolint:forbidigo
}

func updateApp(info updateNeeds) error {
	// First, we try to get the path of the current executable.
	// Which, later, will be used to replace the binary.
	cmdPath, err := osext.Executable()
	if err != nil {
		return fmt.Errorf("failed to get the executable's path: %s", err) //nolint:err113,errorlint
	}

	// When on Windows, the executable path might have the '.exe' suffix.
	if runtime.GOOS == "windows" && !strings.HasSuffix(cmdPath, ".exe") {
		cmdPath += ".exe"
	}

	// Check if the binary is a symlink.
	stat, err := os.Lstat(cmdPath)
	if err != nil {
		return fmt.Errorf("failed to stat: %s - file may not exist: %s", cmdPath, err) //nolint:err113,errorlint
	}

	// If it is, we resolve the symlink.
	if stat.Mode()&os.ModeSymlink != 0 {
		p, err := filepath.EvalSymlinks(cmdPath)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink: %s - for executable: %s", cmdPath, err) //nolint:err113,errorlint
		}
		cmdPath = p
	}

	return selfupdate.UpdateTo(context.Background(), info.latest, cmdPath)
}

func checkoutProfiles(info updateNeeds, forced bool) error {
	dir, err := profilesDir()
	if err != nil {
		return err
	}

	_, err = git.PlainClone(dir, false, &git.CloneOptions{
		URL:           "https://github.com/" + defaultGitHubProfilesSlug,
		SingleBranch:  true,
		ReferenceName: plumbing.NewTagReferenceName(info.latest.Version.String()),
	})
	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return fmt.Errorf("failed to clone the profiles repository: %s", err) //nolint:err113,errorlint
	}

	repo, err := git.PlainOpen(dir)
	if err != nil {
		return fmt.Errorf("failed to open the profiles repository: %w", err)
	}

	err = repo.Fetch(&git.FetchOptions{
		RefSpecs: []config.RefSpec{"refs/tags/*:refs/tags/*"},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to fetch the profiles repository: %w", err)
	}

	tagRef, err := repo.Tag(info.latest.Version.String())
	if err != nil {
		return fmt.Errorf("failed to find the tag ref: %w", err)
	}

	tagCommit, err := repo.ResolveRevision(plumbing.Revision(tagRef.Hash().String()))
	if err != nil {
		return fmt.Errorf("failed to find the tag commit: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to read the worktree of the profiles repository: %w", err)
	}

	if forced {
		err = worktree.Reset(&git.ResetOptions{
			Mode:   git.HardReset,
			Commit: plumbing.ZeroHash,
		})
		if err != nil {
			return fmt.Errorf("failed to reset the worktree of the profiles repository: %w", err)
		}

		err = worktree.Clean(&git.CleanOptions{
			Dir: true,
		})
		if err != nil {
			return fmt.Errorf("failed to clean the worktree of the profiles repository: %w", err)
		}
	}

	err = worktree.Checkout(&git.CheckoutOptions{
		Hash: *tagCommit,
	})
	if err != nil {
		return fmt.Errorf("failed to checkout the worktree of the profiles repository: %w", err)
	}

	return nil
}
