package bootstrap

import (
	"os"
	"path/filepath"
)

func homeDir() error {
	dir, err := gbountyDir()
	if err != nil {
		return err
	}

	info, err := os.Stat(dir)
	switch {
	case existsAsDir(err, info):
		return nil
	case existsAsFile(err, info):
		return removeAndRecreate(dir)
	case notExists(err):
		return mkdir(dir)
	default:
		return err
	}
}

func gbountyDir() (string, error) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(homedir, ".gbounty"), nil
}

func existsAsDir(err error, info os.FileInfo) bool {
	return err == nil && info.IsDir()
}

func existsAsFile(err error, info os.FileInfo) bool {
	return err == nil && !info.IsDir()
}

func notExists(err error) bool {
	return os.IsNotExist(err)
}

func removeAndRecreate(dir string) error {
	if err := os.Remove(dir); err != nil {
		return err
	}
	return mkdir(dir)
}

func mkdir(dir string) error {
	return os.Mkdir(dir, 0o700)
}
