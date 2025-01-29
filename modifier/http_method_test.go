package modifier_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/modifier"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestHTTPMethod_Modify(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		tpl  gbounty.Template
		req  request.Request
		step profile.Step

		expMethod string
		expPath   string
		expBody   []byte
	}{
		"disabled change http method does nothing": {
			req: request.Request{
				Method: http.MethodPost,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     false,
				ChangeHTTPMethodType: profile.ChangePostToGet,
			},
			expMethod: http.MethodPost,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"post to get on get does nothing": {
			req: request.Request{
				Method: http.MethodGet,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangePostToGet,
			},
			expMethod: http.MethodGet,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"post to get on put does nothing": {
			req: request.Request{
				Method: http.MethodPut,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangePostToGet,
			},
			expMethod: http.MethodPut,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"post to get on post sets get": {
			req: request.Request{
				Method: http.MethodPost,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangePostToGet,
			},
			expMethod: http.MethodGet,
			expPath:   "search.php?searchFor=bananas&goButton=oooo",
			expBody:   nil,
		},
		"get to post on post does nothing": {
			req: request.Request{
				Method: http.MethodPost,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeGetToPost,
			},
			expMethod: http.MethodPost,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"get to post on put does nothing": {
			req: request.Request{
				Method: http.MethodPut,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeGetToPost,
			},
			expMethod: http.MethodPut,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"get to post on get sets post": {
			req: request.Request{
				Method: http.MethodGet,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeGetToPost,
			},
			expMethod: http.MethodPost,
			expPath:   "search.php",
			expBody:   []byte("test=query"),
		},
		"swap get and post on put does nothing": {
			req: request.Request{
				Method: http.MethodPut,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeSwapGetAndPost,
			},
			expMethod: http.MethodPut,
			expPath:   "search.php?test=query",
			expBody:   []byte("searchFor=bananas&goButton=oooo"),
		},
		"swap get and post on get sets post": {
			req: request.Request{
				Method: http.MethodGet,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeSwapGetAndPost,
			},
			expMethod: http.MethodPost,
			expPath:   "search.php?searchFor=bananas&goButton=oooo",
			expBody:   []byte("test=query"),
		},
		"swap get and post on post sets get": {
			req: request.Request{
				Method: http.MethodPost,
				Path:   "search.php?test=query",
				Body:   []byte("searchFor=bananas&goButton=oooo"),
			},
			step: profile.Step{
				ChangeHTTPMethod:     true,
				ChangeHTTPMethodType: profile.ChangeSwapGetAndPost,
			},
			expMethod: http.MethodGet,
			expPath:   "search.php?searchFor=bananas&goButton=oooo",
			expBody:   []byte("test=query"),
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := modifier.NewHTTPMethod()
			modified := m.Modify(&tc.step, tc.tpl, tc.req)
			assert.Equal(t, tc.expMethod, modified.Method)
			assert.Equal(t, tc.expPath, modified.Path)
			assert.Equal(t, tc.expBody, modified.Body)
		})
	}
}
