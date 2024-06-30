package gitconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
)

// ErrNotFound is the error returned when the key is not found in the Git configuration.
type ErrNotFound struct {
	Key string
}

// Error returns the error message.
func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("the key `%s` is not found", e.Key)
}

// GithubToken extracts the GitHub token from the Git configuration.
func GithubToken() (string, error) {
	return execGitConfig("github.token")
}

func execGitConfig(args ...string) (string, error) {
	gitArgs := append([]string{"config", "--get", "--null"}, args...)
	var stdout bytes.Buffer
	cmd := exec.Command("git", gitArgs...)
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard

	err := cmd.Run()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if waitStatus, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if waitStatus.ExitStatus() == 1 {
				return "", &ErrNotFound{Key: args[len(args)-1]}
			}
		}
		return "", err
	}

	return strings.TrimRight(stdout.String(), "\000"), nil
}
