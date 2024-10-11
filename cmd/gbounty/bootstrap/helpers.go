package bootstrap

import (
	"os"
	"path/filepath"
	"time"
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

func lastCheckFilePath() (string, error) {
	dir, err := gbountyDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "last_check.txt"), nil
}

func updateLastCheckFile() error {
	filePath, err := lastCheckFilePath()
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(time.Now().Format(time.RFC3339)), 0644)
}

func profilesDir() (string, error) {
	gbountyDir, err := gbountyDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(gbountyDir, profilesDirName), nil
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
	const fullPermUserOnly = 0o700
	return os.Mkdir(dir, fullPermUserOnly)
}
