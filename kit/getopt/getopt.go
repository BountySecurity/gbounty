package getopt

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

type FlagSet struct {
	*flag.FlagSet

	alias         map[string]string
	unalias       map[string]string
	name          string
	errorHandling flag.ErrorHandling
	outw          io.Writer

	count             int
	groups            []string
	byGroup           map[string][]string
	groupDescriptions map[string]string
	usage             string
	examples          string
}

func (f *FlagSet) out() io.Writer {
	if f.outw == nil {
		return os.Stderr
	}

	return f.outw
}

// SetOutput sets the destination for usage and error messages.
// If output is nil, os.Stderr is used.
func (f *FlagSet) SetOutput(output io.Writer) {
	f.FlagSet.SetOutput(output)
	f.outw = output
}

// NewFlagSet creates a new FlagSet with the specified name and error handling behavior.
func NewFlagSet(name string, errorHandling flag.ErrorHandling) *FlagSet {
	f := new(FlagSet)
	f.Init(name, errorHandling)

	return f
}

// Init initializes a FlagSet with the provided name and error handling behavior.
// This method is called by NewFlagSet and can also be called to reset an existing FlagSet.
func (f *FlagSet) Init(name string, errorHandling flag.ErrorHandling) {
	if f.FlagSet == nil {
		f.FlagSet = new(flag.FlagSet)
	}

	f.FlagSet.Init(name, errorHandling)
	f.name = name
	f.errorHandling = errorHandling
	f.FlagSet.Usage = f.defaultUsage

	f.count = 0
	f.groups = []string{""}
	f.byGroup = map[string][]string{"": {}}
	f.groupDescriptions = make(map[string]string)
}

func (f *FlagSet) init() {
	if f.alias == nil {
		f.alias = make(map[string]string)
		f.unalias = make(map[string]string)
	}
}

// Lookup returns the Flag structure of the named command-line flag.
// Returns nil if the flag does not exist.
func (f *FlagSet) Lookup(name string) *flag.Flag {
	if x, ok := f.alias[name]; ok {
		name = x
	}

	return f.FlagSet.Lookup(name)
}

// Alias creates an alias between two flag names.
// Either the short or the long name must be already defined.
// If both flags are defined or neither is defined, it panics.
func (f *FlagSet) Alias(short, long string) {
	f.init()

	flag1 := f.Lookup(short)
	flag2 := f.Lookup(long)

	if flag1 == nil && flag2 == nil {
		panic("Alias: neither -" + short + " nor -" + long + " is a defined flag")
	}

	if flag1 != nil && flag2 != nil {
		panic("Alias: both -" + short + " and -" + long + " are defined flags")
	}

	if flag1 != nil {
		f.alias[long] = short
		f.unalias[short] = long
	} else {
		f.alias[short] = long
		f.unalias[long] = short
	}
}

type boolFlag interface {
	IsBoolFlag() bool
}

func (f *FlagSet) failf(format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...) //nolint:goerr113
	fmt.Fprintln(f.out(), err)
	f.Usage()

	return err
}

func (f *FlagSet) defaultUsage() {
	if f.name == "" {
		fmt.Fprintf(f.out(), "Usage:\n")
	} else {
		fmt.Fprintf(f.out(), "Usage of %s:\n", f.name)
	}

	f.PrintDefaults()
}

// Parse parses command-line arguments from args.
// Must be called after all flags are defined and before flags are accessed by the program.
func (f *FlagSet) Parse(args []string) error { //nolint: funlen,gocognit,cyclop
	for len(args) > 0 {
		arg := args[0]
		if len(arg) < 2 || arg[0] != '-' {
			break
		}

		args = args[1:]

		dash := "-"
		if arg[:2] == "--" {
			dash = "--"
		}

		name := arg[len(dash):]
		var value string
		var haveValue bool

		if before, after, found := strings.Cut(name, "="); found {
			name, value = before, after
			haveValue = found
		}

		fg := f.Lookup(name)
		if fg == nil {
			return f.failf("flag provided but not defined: %s%s", dash, name)
		}

		if b, ok := fg.Value.(boolFlag); ok && b.IsBoolFlag() { //nolint: nestif
			if haveValue {
				if err := fg.Value.Set(value); err != nil {
					return f.failf("invalid boolean value %q for --%s: %v", value, name, err)
				}
			} else {
				if err := fg.Value.Set("true"); err != nil {
					return f.failf("invalid boolean flag %s: %v", name, err)
				}
			}

			continue
		}

		if !haveValue {
			if len(args) == 0 {
				return f.failf("missing argument for --%s", name)
			}

			value, args = args[0], args[1:]
		}

		if err := fg.Value.Set(value); err != nil {
			return f.failf("invalid value %q for flag --%s: %v", value, name, err)
		}

		continue
	}

	err := f.FlagSet.Parse(append([]string{"--"}, args...))
	if err != nil {
		return fmt.Errorf("failed to parse command-line arguments: %v", err) //nolint: err113,errorlint
	}

	return nil
}

// PrintDefaults prints, to the output defined with SetOutput,
// the default values of all defined command-line flags in the FlagSet.
func (f *FlagSet) PrintDefaults() { //nolint: cyclop
	if len(f.usage) > 0 {
		fmt.Fprint(f.out(), f.usage, "\n")
	}

	defaults := make(map[string]string, f.count)

	f.FlagSet.VisitAll(func(fg *flag.Flag) {
		name := fg.Name
		var short, long string
		other := f.unalias[name]
		if utf8.RuneCountInString(name) > 1 {
			long, short = name, other
		} else {
			short, long = name, other
		}
		var s string
		if short != "" {
			s = "  -" + short
			if long != "" {
				s += ", --" + long
			}
		} else {
			s = "  --" + long
		}
		name, usage := flag.UnquoteUsage(fg)
		if len(name) > 0 {
			s += " " + name
		}

		const tiny = 4
		if len(s) <= tiny {
			s += "\t"
		} else {
			s += "\n    \t"
		}
		s += usage

		defaults[fg.Name] = s
	})

	for _, g := range f.groups {
		if description, defined := f.groupDescriptions[g]; defined {
			fmt.Fprint(f.out(), description, "\n")
		}

		for _, name := range f.byGroup[g] {
			fmt.Fprint(f.out(), defaults[name], "\n")
		}

		fmt.Fprint(f.out(), "\n")
	}

	if len(f.examples) > 0 {
		fmt.Fprint(f.out(), f.examples, "\n")
	}
}

// Flag extensions

// BoolVar defines a bool flag with specified name, default value, and usage string.
// The argument p points to a bool variable in which to store the value of the flag.
func (f *FlagSet) BoolVar(group string, p *bool, name string, value bool, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.BoolVar(p, name, value, usage)
}

// IntVar defines an int flag with specified name, default value, and usage string.
// The argument p points to an int variable in which to store the value of the flag.
func (f *FlagSet) IntVar(group string, p *int, name string, value int, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.IntVar(p, name, value, usage)
}

// Int64Var defines an int64 flag with specified name, default value, and usage string.
// The argument p points to an int64 variable in which to store the value of the flag.
func (f *FlagSet) Int64Var(group string, p *int64, name string, value int64, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.Int64Var(p, name, value, usage)
}

// UintVar defines a uint flag with specified name, default value, and usage string.
// The argument p points to a uint variable in which to store the value of the flag.
func (f *FlagSet) UintVar(group string, p *uint, name string, value uint, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.UintVar(p, name, value, usage)
}

// Uint64Var defines a uint64 flag with specified name, default value, and usage string.
// The argument p points to a uint64 variable in which to store the value of the flag.
func (f *FlagSet) Uint64Var(group string, p *uint64, name string, value uint64, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.Uint64Var(p, name, value, usage)
}

// StringVar defines a string flag with specified name, default value, and usage string.
// The argument p points to a string variable in which to store the value of the flag.
func (f *FlagSet) StringVar(group string, p *string, name string, value string, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.StringVar(p, name, value, usage)
}

// Float64Var defines a float64 flag with specified name, default value, and usage string.
// The argument p points to a float64 variable in which to store the value of the flag.
func (f *FlagSet) Float64Var(group string, p *float64, name string, value float64, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.Float64Var(p, name, value, usage)
}

// DurationVar defines a time.Duration flag with specified name, default value, and usage string.
// The argument p points to a time.Duration variable in which to store the value of the flag.
func (f *FlagSet) DurationVar(group string, p *time.Duration, name string, value time.Duration, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.DurationVar(p, name, value, usage)
}

// Var defines a flag with the specified name and usage string.
// The type and value of the flag are represented by the first argument, of type flag.Value.
func (f *FlagSet) Var(group string, value flag.Value, name string, usage string) {
	f.storeGroupedName(group, name)
	f.FlagSet.Var(value, name, usage)
}

// Bool defines a bool flag with specified name, default value, and usage string,
// and returns the address of a bool variable that stores the value of the flag.
func (f *FlagSet) Bool(group string, name string, value bool, usage string) *bool {
	f.storeGroupedName(group, name)
	return f.FlagSet.Bool(name, value, usage)
}

// InitGroup initializes a new group of flags with the given name and description.
// Flags can be added to this group using the various flag definition methods.
func (f *FlagSet) InitGroup(name, description string) {
	f.groups = append(f.groups, name)
	f.byGroup[name] = make([]string, 0)
	f.groupDescriptions[name] = description
}

// SetUsage sets a custom usage message for the FlagSet.
func (f *FlagSet) SetUsage(usage string) {
	f.usage = usage
}

// SetExamples sets a custom examples section for the FlagSet, to be displayed in usage output.
func (f *FlagSet) SetExamples(examples string) {
	f.examples = examples
}

func (f *FlagSet) storeGroupedName(group, name string) {
	f.count++
	f.byGroup[group] = append(f.byGroup[group], name)
}
