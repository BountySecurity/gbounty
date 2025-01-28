package profile

import (
	"context"
	"errors"
	"io"
	"mime/multipart"
)

var ErrMissingProfiles = errors.New("missing profiles")

// NewMultipartFromProvider reads the profiles from a multipart form.
func NewMultipartFromProvider(ctx context.Context, form *multipart.Form) (ZipProvider, error) {
	const key = "profiles"

	fhs := form.File[key]
	if len(fhs) == 0 {
		return ZipProvider{}, ErrMissingProfiles
	}

	f, err := fhs[0].Open()
	if err != nil {
		return ZipProvider{}, errors.Join(ErrMissingProfiles, err)
	}

	zipBytes, err := io.ReadAll(f)
	if err != nil {
		return ZipProvider{}, errors.Join(ErrMissingProfiles, err)
	}

	provider, err := NewZipProvider(ctx, zipBytes)
	if err != nil {
		return ZipProvider{}, errors.Join(ErrMissingProfiles, err)
	}

	return provider, nil
}
