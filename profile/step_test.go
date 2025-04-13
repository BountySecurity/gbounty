package profile_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty/profile"
)

func TestStep_InsertionPointEnabled(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		step     profile.Step
		ipt      profile.InsertionPointType
		method   string
		expected bool
	}{
		"POST to GET, ParamURLName": {
			step: profile.Step{
				InsertionPoints:      []profile.InsertionPointType{profile.ParamURLName},
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangePostToGet,
			},
			ipt:      profile.ParamURLName,
			method:   http.MethodPost,
			expected: false,
		},
		"GET to POST, ParamBodyValue": {
			step: profile.Step{
				InsertionPoints:      []profile.InsertionPointType{profile.ParamBodyValue},
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeGetToPost,
			},
			ipt:      profile.ParamBodyValue,
			method:   http.MethodGet,
			expected: false,
		},
		"SwapGetAndPost, ParamURLName": {
			step: profile.Step{
				InsertionPoints:      []profile.InsertionPointType{profile.ParamURLName},
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeSwapGetAndPost,
			},
			ipt:      profile.ParamURLName,
			method:   http.MethodPost,
			expected: false,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := tc.step.InsertionPointEnabled(tc.ipt, tc.method)
			require.Equal(t, tc.expected, result)
		})
	}
}

func TestStep_PayloadAt(t *testing.T) {
	t.Parallel()

	s := buildStepWithPayloads()

	t.Run("invalid payload index", func(t *testing.T) {
		t.Parallel()
		_, _, err := s.PayloadAt(4)
		assert.Equal(t, err, profile.ErrInvalidPayloadIdx)
	})

	t.Run("invalid payload format", func(t *testing.T) {
		t.Parallel()
		_, _, err := s.PayloadAt(3)
		assert.Equal(t, err, profile.ErrInvalidPayloadFormat)
	})

	t.Run("invalid payload bool", func(t *testing.T) {
		t.Parallel()
		_, _, err := s.PayloadAt(2)
		assert.Equal(t, err, profile.ErrInvalidPayloadBool)
	})

	t.Run("disabled payload", func(t *testing.T) {
		t.Parallel()
		enabled, payload, err := s.PayloadAt(1)
		assert.False(t, enabled)
		assert.Equal(t, "\"><img src=x onerror=prompt(1);>.", payload)
		assert.NoError(t, err)
	})

	t.Run("enabled payload", func(t *testing.T) {
		t.Parallel()
		enabled, payload, err := s.PayloadAt(0)
		assert.True(t, enabled)
		assert.Equal(t, "</script><script>confirm(1)</script>", payload)
		assert.NoError(t, err)
	})
}

func buildStepWithPayloads() profile.Step {
	return profile.Step{Payloads: []string{
		"true,\u003c/script\u003e\u003cscript\u003econfirm(1)\u003c/script\u003e",
		"false,\"\u003e\u003cimg src\u003dx onerror\u003dprompt(1);\u003e.",
		"xxxx,\"\u003e\u003cimg src\u003dx onerror\u003dprompt(1);\u003e.",
		"true\"\u003e\u003cimg src\u003dx onerror\u003dprompt(1);\u003e.",
	}}
}
