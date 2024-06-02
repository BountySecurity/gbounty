package semver_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/kit/semver"
)

func Test_Parse(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		expVer semver.Version
		expOk  bool
	}{
		"":      {expVer: semver.Version{}, expOk: false},
		"-":     {expVer: semver.Version{}, expOk: false},
		"abc":   {expVer: semver.Version{}, expOk: false},
		"0.22a": {expVer: semver.Version{}, expOk: false},

		"0.1":   {expVer: semver.Version{Minor: "0", Patch: "1"}, expOk: true},
		"v0.22": {expVer: semver.Version{Minor: "0", Patch: "22"}, expOk: true},

		"1.0":   {expVer: semver.Version{Minor: "1", Patch: "0"}, expOk: true},
		"v22.0": {expVer: semver.Version{Minor: "22", Patch: "0"}, expOk: true},

		"1.1":    {expVer: semver.Version{Minor: "1", Patch: "1"}, expOk: true},
		"v22.22": {expVer: semver.Version{Minor: "22", Patch: "22"}, expOk: true},

		"1.0.0":   {expVer: semver.Version{Major: "1", Minor: "0", Patch: "0"}, expOk: true},
		"v22.0.0": {expVer: semver.Version{Major: "22", Minor: "0", Patch: "0"}, expOk: true},

		"1.1.0":    {expVer: semver.Version{Major: "1", Minor: "1", Patch: "0"}, expOk: true},
		"v22.22.0": {expVer: semver.Version{Major: "22", Minor: "22", Patch: "0"}, expOk: true},

		"1.1.1":     {expVer: semver.Version{Major: "1", Minor: "1", Patch: "1"}, expOk: true},
		"v22.22.22": {expVer: semver.Version{Major: "22", Minor: "22", Patch: "22"}, expOk: true},
	}

	for v, tc := range tcs {
		v := v
		tc := tc
		t.Run(v, func(t *testing.T) {
			t.Parallel()

			gotVer, gotOk := semver.Parse(v)
			assert.Equal(t, tc.expVer.Major, gotVer.Major)
			assert.Equal(t, tc.expVer.Minor, gotVer.Minor)
			assert.Equal(t, tc.expVer.Patch, gotVer.Patch)
			assert.Equal(t, tc.expOk, gotOk)
		})
	}
}

func TestVersion_ShouldUpdate(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		from         semver.Version
		to           semver.Version
		shouldUpdate bool
	}{
		// 0.x -> x.y
		"0.1 -> 0.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "0", Patch: "1"}, shouldUpdate: false},
		"0.1 -> 0.2": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "0", Patch: "2"}, shouldUpdate: true},
		"0.1 -> 1.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "1", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 1.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "1", Patch: "1"}, shouldUpdate: true},
		"0.1 -> 2.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "2", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 2.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Minor: "2", Patch: "1"}, shouldUpdate: true},
		"0.2 -> 0.1": {from: semver.Version{Minor: "0", Patch: "2"}, to: semver.Version{Minor: "0", Patch: "1"}, shouldUpdate: false},

		// x.y -> x.y
		"1.0 -> 1.0": {from: semver.Version{Minor: "1", Patch: "0"}, to: semver.Version{Minor: "1", Patch: "0"}, shouldUpdate: false},
		"1.0 -> 1.1": {from: semver.Version{Minor: "1", Patch: "0"}, to: semver.Version{Minor: "1", Patch: "1"}, shouldUpdate: true},
		"1.0 -> 2.0": {from: semver.Version{Minor: "1", Patch: "0"}, to: semver.Version{Minor: "2", Patch: "0"}, shouldUpdate: true},
		"1.0 -> 2.1": {from: semver.Version{Minor: "1", Patch: "0"}, to: semver.Version{Minor: "2", Patch: "1"}, shouldUpdate: true},
		"1.1 -> 1.0": {from: semver.Version{Minor: "1", Patch: "0"}, to: semver.Version{Minor: "1", Patch: "0"}, shouldUpdate: false},
		"1.1 -> 2.1": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Minor: "2", Patch: "1"}, shouldUpdate: true},
		"2.0 -> 1.0": {from: semver.Version{Minor: "2", Patch: "0"}, to: semver.Version{Minor: "1", Patch: "0"}, shouldUpdate: false},
		"2.1 -> 1.1": {from: semver.Version{Minor: "2", Patch: "1"}, to: semver.Version{Minor: "1", Patch: "1"}, shouldUpdate: false},

		// 0.1 -> x.y.z
		"0.1 -> 1.0.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 1.1.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 2.0.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 2.1.0": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "0"}, shouldUpdate: true},
		"0.1 -> 1.0.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "1"}, shouldUpdate: true},
		"0.1 -> 1.1.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "1"}, shouldUpdate: true},
		"0.1 -> 2.0.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "1"}, shouldUpdate: true},
		"0.1 -> 2.1.1": {from: semver.Version{Minor: "0", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "1"}, shouldUpdate: true},

		// 1.1 -> x.y.z
		"1.1 -> 1.0.0": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "0"}, shouldUpdate: true},
		"1.1 -> 1.1.0": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "0"}, shouldUpdate: true},
		"1.1 -> 2.0.0": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "0"}, shouldUpdate: true},
		"1.1 -> 2.1.0": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "0"}, shouldUpdate: true},
		"1.1 -> 1.0.1": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "1"}, shouldUpdate: true},
		"1.1 -> 1.1.1": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "1"}, shouldUpdate: true},
		"1.1 -> 2.0.1": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "1"}, shouldUpdate: true},
		"1.1 -> 2.1.1": {from: semver.Version{Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "1"}, shouldUpdate: true},

		// 1.1.1 -> x.y.z
		"1.1.1 -> 1.0.0": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "0"}, shouldUpdate: false},
		"1.1.1 -> 1.1.0": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "0"}, shouldUpdate: false},
		"1.1.1 -> 2.0.0": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "0"}, shouldUpdate: true},
		"1.1.1 -> 2.1.0": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "0"}, shouldUpdate: true},
		"1.1.1 -> 1.0.1": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "0", Patch: "1"}, shouldUpdate: false},
		"1.1.1 -> 1.1.1": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "1", Minor: "1", Patch: "1"}, shouldUpdate: false},
		"1.1.1 -> 2.0.1": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "0", Patch: "1"}, shouldUpdate: true},
		"1.1.1 -> 2.1.1": {from: semver.Version{Major: "1", Minor: "1", Patch: "1"}, to: semver.Version{Major: "2", Minor: "1", Patch: "1"}, shouldUpdate: true},
	}

	for v, tc := range tcs {
		tc := tc
		t.Run(v, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.shouldUpdate, tc.from.ShouldUpdate(tc.to))
		})
	}
}
