package selfupdate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func apply(src io.Reader, cmdPath string) error {
	// Get the directory the executable exists in.
	updateDir := filepath.Dir(cmdPath)
	filename := filepath.Base(cmdPath)

	// Copy the contents of the new binary to a new executable file.
	newPath := filepath.Join(updateDir, fmt.Sprintf(".%s.new", filename))
	fp, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer fp.Close()

	_, err = io.Copy(fp, src)
	if err != nil {
		return err
	}

	// Despite the deferred call, if we don't call fp.Close() now,
	// Windows won't let us move the new executable will still be "in use".
	if err = fp.Close(); err != nil {
		return err
	}

	// Where we'll move the executable to,
	// so that we can swap in the updated replacement.
	oldPath := filepath.Join(updateDir, fmt.Sprintf(".%s.old", filename))

	// Delete any existing file, if any - necessary on Windows for two reasons:
	// 1. After a successful update, Windows can't remove the .old file because the process is still running.
	// 2. Windows rename operations fail if the destination file already exists.
	_ = os.Remove(oldPath)

	// Move the existing executable to a new file in the same directory
	err = os.Rename(cmdPath, oldPath)
	if err != nil {
		return err
	}

	// Move the new executable in to become the new program.
	err = os.Rename(newPath, cmdPath)
	if err != nil {
		// The filesystem is now in a bad state.
		// We have successfully moved the existing binary to a new location,
		// but we couldn't move the new binary to take its place.
		// That means there is no file where the current executable binary used to be!
		// Try to rollback by restoring the old binary to its original path.
		rerr := os.Rename(oldPath, cmdPath)
		if rerr != nil {
			return errors.Join(err, rerr)
		}

		return err
	}

	errRemove := os.Remove(oldPath)
	// Windows has trouble with removing old binaries, so hide it instead.
	if errRemove != nil {
		_ = hideFile(oldPath)
	}

	return nil
}
