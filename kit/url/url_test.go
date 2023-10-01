package url_test

import (
	"errors"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/kit/url"
)

func TestValidURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid URL with protocol",
			input:    "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "Valid URL without protocol",
			input:    "example.com",
			expected: "http://example.com",
		},
		{
			name:     "Valid HTTPS URL",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "Valid URL with path",
			input:    "example.com/path",
			expected: "http://example.com/path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			urlInput := tc.input
			err := url.Validate(&urlInput)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, urlInput)
		})
	}
}

func TestInvalidURL(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Invalid URL with missing host",
			input: "http:///path",
		},
		{
			name:  "Invalid URL with spaces",
			input: "http://exa mple.com",
		},
		{
			name:  "Invalid URL with no scheme and invalid host",
			input: "://",
		},
		{
			name:  "Empty string",
			input: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			urlInput := tc.input
			err := url.Validate(&urlInput)
			require.Error(t, err)
			require.ErrorIs(t, err, url.ErrInvalidURL)
		})
	}
}

func TestURLFallbackProtocol(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL without protocol",
			input:    "example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL with path without protocol",
			input:    "example.com/path",
			expected: "http://example.com/path",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			urlInput := tc.input
			err := url.Validate(&urlInput)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, urlInput)
		})
	}
}

func TestURLWithPort(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL with port",
			input:    "example.com:8080",
			expected: "http://example.com:8080",
		},
		{
			name:     "HTTPS URL with port",
			input:    "https://example.com:8443",
			expected: "https://example.com:8443",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			urlInput := tc.input
			err := url.Validate(&urlInput)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, urlInput)
		})
	}
}

func TestURLWithoutHost(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "URL without host",
			input: "http:///path",
		},
		{
			name:  "URL with only path",
			input: "/path/to/resource",
		},
		{
			name:  "Invalid URL with query only",
			input: "?query=1",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			urlInput := tc.input
			err := url.Validate(&urlInput)
			require.Error(t, err)
			assert.True(t, errors.Is(err, url.ErrInvalidURL), "expected ErrInvalidURL for input: "+tc.input)
		})
	}
}
