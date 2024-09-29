//go:build windows

package bootstrap

import (
	"os"
	"syscall"
)

func listenFor() []os.Signal {
	return []os.Signal{
		syscall.SIGABRT, syscall.SIGHUP, syscall.SIGINT, syscall.SIGKILL,
		syscall.SIGQUIT, syscall.SIGTERM,
	}
}
