package die

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"
)

// OnErr is a helper function to handle errors, that runs the given function and,
// in case of error, it prints the error message and exits (1) the program.
func OnErr(fn func() error, mm ...string) {
	if err := fn(); err != nil {
		die(err, mm...)
	}
}

// OrRet is a helper function to handle errors, that runs the given function and,
// in case of error, it prints the error message and exits (1) the program.
// It is similar to [OnErr], but in case of success it returns the value.
//
//nolint:ireturn
func OrRet[T any](fn func() (T, error), mm ...string) (t T) {
	v, err := fn()
	if err == nil {
		return v
	}

	pterm.Error.WithShowLineNumber(false).
		Printf("%s\n", dieFmt(err, mm...))
	os.Exit(1)
	return
}

func die(err error, mm ...string) {
	pterm.Error.WithShowLineNumber(false).
		Printf("%s\n", dieFmt(err, mm...))
	os.Exit(1)
}

func dieFmt(err error, mm ...string) string {
	var msg string

	if len(mm) > 0 {
		msg = mm[0]
		for _, m := range mm[1:] {
			msg = fmt.Sprintf("%s: %s", msg, m)
		}
	}

	if len(msg) > 0 {
		msg = fmt.Sprintf("%s: %s", msg, err.Error())
	} else {
		msg = err.Error()
	}

	return msg
}
