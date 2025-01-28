package entrypoint //nolint:testpackage

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/profile"
)

func TestFrom(t *testing.T) {
	t.Parallel()

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		entrypoints := From(profile.Step{
			InsertionPoints: []profile.InsertionPointType{
				profile.HeaderNew,
			},
			CustomHeaders: []string{
				"Content-Type",
				"Content-Length",
			},
		})

		assert.Equal(t, []Entrypoint{
			newCustomHeader("Content-Type"),
			newCustomHeader("Content-Length"),
		}, entrypoints)
	})

	t.Run("not enabled", func(t *testing.T) {
		t.Parallel()

		entrypoints := From(profile.Step{
			InsertionPoints: []profile.InsertionPointType{},
			CustomHeaders: []string{
				"Content-Type",
				"Content-Length",
			},
		})

		assert.Equal(t, []Entrypoint{}, entrypoints)
	})
}
