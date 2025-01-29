package encode_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/profile/encode"
)

func Test_URL(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "%48%e8%6c%6c%f6%20%57%f3%72%6c%64",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "%22%3e%3c%69%6d%67%20%73%72%63%3d%78%20%6f%6e%65%72%72%6f%72%3d%70%72%6f%6d%70%74%28%31%29%3b%3e%2e",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "%2f%2e%67%69%74%2f%48%45%41%44",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.URL(tc.in))
		})
	}
}

func Test_UnicodeURL(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "%u0048%u00e8%u006c%u006c%u00f6%u0020%u0057%u00f3%u0072%u006c%u0064",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "%u0022%u003e%u003c%u0069%u006d%u0067%u0020%u0073%u0072%u0063%u003d%u0078%u0020%u006f%u006e%u0065%u0072%u0072%u006f%u0072%u003d%u0070%u0072%u006f%u006d%u0070%u0074%u0028%u0031%u0029%u003b%u003e%u002e",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "%u002f%u002e%u0067%u0069%u0074%u002f%u0048%u0045%u0041%u0044",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.UnicodeURL(tc.in))
		})
	}
}

func Test_HTML(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "&#x48;&#xe8;&#x6c;&#x6c;&#xf6;&#x20;&#x57;&#xf3;&#x72;&#x6c;&#x64;",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "&#x22;&#x3e;&#x3c;&#x69;&#x6d;&#x67;&#x20;&#x73;&#x72;&#x63;&#x3d;&#x78;&#x20;&#x6f;&#x6e;&#x65;&#x72;&#x72;&#x6f;&#x72;&#x3d;&#x70;&#x72;&#x6f;&#x6d;&#x70;&#x74;&#x28;&#x31;&#x29;&#x3b;&#x3e;&#x2e;",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "&#x2f;&#x2e;&#x67;&#x69;&#x74;&#x2f;&#x48;&#x45;&#x41;&#x44;",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.HTML(tc.in))
		})
	}
}

func Test_KeyHTML(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "Hèllö&#x20;Wórld",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "\"&#x3e;&#x3c;img&#x20;src&#x3d;x&#x20;onerror&#x3d;prompt&#x28;1&#x29;;&#x3e;&#x2e;",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "/&#x2e;git/HEAD",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.KeyHTML(tc.in))
		})
	}
}

func Test_KeyURL(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "Hèllö%20Wórld",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "\"%3e%3cimg%20src%3dx%20onerror%3dprompt%281%29;%3e%2e",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "/%2egit/HEAD",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.KeyURL(tc.in))
		})
	}
}

func Test_TheseURL(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "Hèllö%20Wórld",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "\"%3e%3cimg%20src%3dx%20onerror%3dprompt%281%29;%3e%2e",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "/%2egit/HEAD",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.TheseURL(tc.in, "\\<\\(\\[\\\\\\^\\-\\=\\$\\!\\|\\]\\)\\?\\*\\+\\.\\>]\\&\\%\\:\\@ "))
		})
	}
}

func Test_Base64(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  string
		out string
	}{
		"empty string": {
			in:  "",
			out: "",
		},
		"Hèllö Wórld": {
			in:  "Hèllö Wórld",
			out: "SMOobGzDtiBXw7NybGQ=",
		},
		"\"><img src=x onerror=prompt(1);>.": {
			in:  "\"><img src=x onerror=prompt(1);>.",
			out: "Ij48aW1nIHNyYz14IG9uZXJyb3I9cHJvbXB0KDEpOz4u",
		},
		"/.git/HEAD": {
			in:  "/.git/HEAD",
			out: "Ly5naXQvSEVBRA==",
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, encode.Base64(tc.in))
		})
	}
}
