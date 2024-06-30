//go:build linux || netbsd || openbsd || solaris || dragonfly

package osext

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
)

var errExecPathNotImplemented = errors.New("ExecPath not implemented")

func executable() (string, error) {
	switch runtime.GOOS {
	case "linux":
		const deletedTag = " (deleted)"
		execpath, err := os.Readlink("/proc/self/exe")
		if err != nil {
			return execpath, err
		}
		execpath = strings.TrimSuffix(execpath, deletedTag)
		execpath = strings.TrimPrefix(execpath, deletedTag)
		return execpath, nil
	case "netbsd":
		return os.Readlink("/proc/curproc/exe")
	case "openbsd", "dragonfly":
		return os.Readlink("/proc/curproc/file")
	case "solaris":
		return os.Readlink(fmt.Sprintf("/proc/%d/path/a.out", os.Getpid()))
	}
	return "", fmt.Errorf("%w for %s", errExecPathNotImplemented, runtime.GOOS)
}
