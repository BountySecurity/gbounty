package getopt_test

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/getopt"
)

func Test_NewFlagSet(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)
	require.NotNil(t, fs)
	require.Equal(t, "test", fs.Name())
	require.Equal(t, flag.ContinueOnError, fs.ErrorHandling())
}

func Test_FlagSet_BoolVar(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)

	var boolValue bool
	fs.BoolVar("", &boolValue, "boolFlag", false, "a boolean flag")

	err := fs.Parse([]string{"--boolFlag"})
	require.NoError(t, err)
	require.True(t, boolValue)
}

func Test_FlagSet_IntVar(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)

	var intValue int
	fs.IntVar("", &intValue, "intFlag", 42, "an integer flag")

	err := fs.Parse([]string{"--intFlag=100"})
	require.NoError(t, err)
	require.Equal(t, 100, intValue)
}

func Test_FlagSet_Alias(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)

	var stringValue string
	fs.StringVar("", &stringValue, "longFlag", "", "a string flag")
	fs.Alias("s", "longFlag")

	err := fs.Parse([]string{"-s=value"})
	require.NoError(t, err)
	require.Equal(t, "value", stringValue)
}

func Test_FlagSet_Parse_UnknownFlag(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)
	err := fs.Parse([]string{"--unknownFlag"})
	require.ErrorContains(t, err, "flag provided but not defined: --unknownFlag")
}

func Test_FlagSet_Parse_WithEqualSign(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)

	var strValue string
	fs.StringVar("", &strValue, "strFlag", "", "a string flag")

	err := fs.Parse([]string{"--strFlag=value"})
	require.NoError(t, err)
	require.Equal(t, "value", strValue)
}

func Test_FlagSet_GroupedFlags(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)
	fs.InitGroup("group1", "This is group 1")
	var intValue int
	fs.IntVar("group1", &intValue, "intFlag", 42, "an integer flag")
	fs.InitGroup("group2", "This is group 2")
	var boolValue bool
	fs.BoolVar("group2", &boolValue, "boolFlag", false, "a boolean flag")

	var output bytes.Buffer
	fs.SetOutput(&output)
	fs.PrintDefaults()

	defaults := output.String()
	if !strings.Contains(defaults, "This is group 1") {
		t.Errorf("expected defaults to contain 'This is group 1', got '%s'", defaults)
	}
	if !strings.Contains(defaults, "This is group 2") {
		t.Errorf("expected defaults to contain 'This is group 2', got '%s'", defaults)
	}
	if !strings.Contains(defaults, "--intFlag") {
		t.Errorf("expected defaults to contain '--intFlag', got '%s'", defaults)
	}
	if !strings.Contains(defaults, "--boolFlag") {
		t.Errorf("expected defaults to contain '--boolFlag', got '%s'", defaults)
	}
}

func TestFlagSet_SetUsage(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)
	fs.SetUsage("This is a custom usage message")

	var output bytes.Buffer
	fs.SetOutput(&output)

	fs.PrintDefaults()
	require.Contains(t, output.String(), "This is a custom usage message")
}

func Test_FlagSet_SetExamples(t *testing.T) {
	t.Parallel()

	fs := getopt.NewFlagSet("test", flag.ContinueOnError)
	fs.SetExamples("This is an example usage")

	var output bytes.Buffer
	fs.SetOutput(&output)

	fs.PrintDefaults()
	require.Contains(t, output.String(), "This is an example usage")
}
