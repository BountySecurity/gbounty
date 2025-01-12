package progressbar

import "github.com/pterm/pterm"

// Printer is a wrapper around [*pterm.ProgressbarPrinter],
// which is a struct that shows a progress animation in the terminal.
//
// It is used when you want to manage the progress bar lifecycle (start, stop, etc.)
// from different goroutines, which isn't easy because [*pterm.ProgressbarPrinter.Start()]'s
// receiver is a value, and this implicit de-reference prevents the pointer shared across
// all goroutines from being updated.
//
// Instead, you can use the [*Printer] struct, which has a pointer to a [*pterm.ProgressbarPrinter],
// so you can call the methods on the [*pterm.ProgressbarPrinter] through the [*Printer] struct,
// and just update the pointer it holds when needed.
type Printer struct {
	*pterm.ProgressbarPrinter
}

// NewPrinter initializes a new [*Printer] which holds a non-nil pointer to a [*pterm.ProgressbarPrinter],
// concretely to the reference of the [pterm.DefaultProgressbar] variable.
func NewPrinter() *Printer {
	return &Printer{&pterm.DefaultProgressbar}
}
