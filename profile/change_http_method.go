package profile

const (
	ChangePostToGet      ChangeHTTPMethodType = "post_to_get"
	ChangeGetToPost      ChangeHTTPMethodType = "get_to_post"
	ChangeSwapGetAndPost ChangeHTTPMethodType = "get_post_get"
)

// ChangeHTTPMethodType represents the type of change to be made to the HTTP method
// during the scan. It can be PostToGet, GetToPost, or SwapGetAndPost.
type ChangeHTTPMethodType string

// PostToGet returns true if the change is from POST to GET.
func (t ChangeHTTPMethodType) PostToGet() bool {
	return t == ChangePostToGet
}

// GetToPost returns true if the change is from GET to POST.
func (t ChangeHTTPMethodType) GetToPost() bool {
	return t == ChangeGetToPost
}

// SwapGetAndPost returns true if the change is from GET to POST and vice versa.
func (t ChangeHTTPMethodType) SwapGetAndPost() bool {
	return t == ChangeSwapGetAndPost
}
