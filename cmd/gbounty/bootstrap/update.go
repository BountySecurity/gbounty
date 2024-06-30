package bootstrap

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/kit/die"
	"github.com/bountysecurity/gbounty/kit/osext"
	"github.com/bountysecurity/gbounty/kit/selfupdate"
	"github.com/bountysecurity/gbounty/kit/slices"
)

func CheckForUpdates() {
	// Disable checks on CI jobs.
	if _, isCI := os.LookupEnv("CI"); isCI {
		return
	}

	// Ensure the home directory exists.
	die.OnErr(homeDir, "Could not create the $HOME directory (.gbounty)")

	// Fetch current and latest version.
	update := die.OrRet(checkVer, "Could not detect if there are updates available")

	// If no update is needed, return.
	if !(update.app.needed || update.profiles.needed) {
		return
	}

	// Parse CLI arguments to determine if the user wants to update.
	var appUpdate, profUpdate bool
	if slices.In(os.Args, "--update") {
		appUpdate, profUpdate = true, true
	} else {
		appUpdate = slices.In(os.Args, "--update-app")
		profUpdate = slices.In(os.Args, "--update-profiles")
	}

	wg := new(sync.WaitGroup)

	// Update application (if needed)
	if update.app.needed {
		if appUpdate {
			pterm.Info.Println("Self-updating application...")
			wg.Add(1)
			updateApp := func() error { defer wg.Done(); return updateApp(update.app) }
			go die.OnErr(updateApp, "Could not update the application")
		} else {
			pterm.Info.Printf("There is a new app version available: v%s (curr. %s)\n",
				update.app.latest.Version, update.app.current)
			pterm.Info.Println("Use --update or --update-app to update")
		}
	}

	// TODO: Update profiles (if needed)
	if update.profiles.needed {
		if profUpdate {
			// pterm.Info.Println("Updating profiles...")
			// wg.Add(1)
			// updateProfiles := func() error { defer wg.Done(); return updateProfiles(update.profiles) }
			// go die.OnErr(updateProfiles, "Could not update the profiles")
		} else {
			pterm.Info.Printf("There is a new profiles version available: v%s (curr. v%s)\n",
				update.profiles.latest.Version, update.profiles.current)
			pterm.Info.Println("Use --update or --update-profiles to update")
		}
	}

	// Wait till updates finish
	wg.Wait()

	if update.app.needed && appUpdate {
		pterm.Success.Println("Application updated successfully!")
	}

	if update.profiles.needed && profUpdate {
		pterm.Success.Println("Profiles updated successfully!")
	}

	fmt.Println() //nolint:forbidigo
}

func updateApp(info updateNeeds) error {
	// First, we try to get the path of the current executable.
	// Which, later, will be used to replace the binary.
	cmdPath, err := osext.Executable()
	if err != nil {
		return fmt.Errorf("failed to get the executable's path: %s", err) //nolint:err113
	}

	// When on Windows, the executable path might have the '.exe' suffix.
	if runtime.GOOS == "windows" && !strings.HasSuffix(cmdPath, ".exe") {
		cmdPath += ".exe"
	}

	// Check if the binary is a symlink.
	stat, err := os.Lstat(cmdPath)
	if err != nil {
		return fmt.Errorf("failed to stat: %s - file may not exist: %s", cmdPath, err)
	}

	// If it is, we resolve the symlink.
	if stat.Mode()&os.ModeSymlink != 0 {
		p, err := filepath.EvalSymlinks(cmdPath)
		if err != nil {
			return fmt.Errorf("failed to resolve symlink: %s - for executable: %s", cmdPath, err) //nolint:err113
		}
		cmdPath = p
	}

	return selfupdate.UpdateTo(context.Background(), info.latest, cmdPath)
}

func updateProfiles(info updateNeeds) error {
	return nil
}
