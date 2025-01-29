package profile

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"sort"

	"github.com/BountySecurity/gbounty/kit/logger"
)

// ZipProvider is a profile provider that reads profiles from a zip file.
type ZipProvider struct {
	data
	locations []string
}

// NewZipProvider creates a new ZipProvider from the given zip file contents.
func NewZipProvider(ctx context.Context, contents []byte) (ZipProvider, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return ZipProvider{}, err
	}

	locations := make([]string, 0)
	data := data{
		actives:     make([]*Active, 0),
		passiveReqs: make([]*Request, 0),
		passiveRes:  make([]*Response, 0),
		tags:        make(map[string]struct{}),
	}

	for _, zipFile := range zipReader.File {
		// It only looks for *.bb and *.bb2 files
		info := zipFile.FileInfo()
		ext := filepath.Ext(info.Name())
		if info.IsDir() || ext != FileExtension {
			continue
		}

		// From now on, in case of error, we skip the file and log the error
		file, err := zipFile.Open()
		if err != nil {
			logger.For(ctx).Errorf("Cannot read file(%s) from profiles zip: %s", info.Name(), err.Error())
			continue
		}

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			logger.For(ctx).Errorf("Cannot read file(%s) from profiles zip: %s", info.Name(), err.Error())
			continue
		}

		if ext == FileExtension {
			err = readBB2Profiles(&data, fileBytes)
		}

		if err != nil {
			logger.For(ctx).Errorf("Cannot read file(%s) from profiles zip: %s", info.Name(), err.Error())
			continue
		}

		// At this point we can consider the load was successful.
		// Therefore, we add the current file name to the list of locations.
		locations = append(locations, info.Name())
	}

	return ZipProvider{
		data:      data,
		locations: locations,
	}, nil
}

// Actives returns the active profiles loaded from the zip file.
func (zp ZipProvider) Actives() []*Active {
	return zp.actives
}

// ActivesEnabled returns the active profiles loaded from the zip file that are enabled.
func (zp ZipProvider) ActivesEnabled() []*Active {
	return enabled(zp.actives)
}

// PassiveReqs returns the passive request profiles loaded from the zip file.
func (zp ZipProvider) PassiveReqs() []*Request {
	return zp.passiveReqs
}

// PassiveReqsEnabled returns the passive request profiles loaded from the zip file that are enabled.
func (zp ZipProvider) PassiveReqsEnabled() []*Request {
	return enabled(zp.passiveReqs)
}

// PassiveRes returns the passive response profiles loaded from the zip file.
func (zp ZipProvider) PassiveRes() []*Response {
	return zp.passiveRes
}

// PassiveResEnabled returns the passive response profiles loaded from the zip file that are enabled.
func (zp ZipProvider) PassiveResEnabled() []*Response {
	return enabled(zp.passiveRes)
}

// Tags returns the tags of the profiles loaded from the zip file.
func (zp ZipProvider) Tags() []string {
	tags := make([]string, 0, len(zp.tags))
	for tag := range zp.tags {
		tags = append(tags, tag)
	}

	sort.Strings(tags)

	return tags
}

// From returns the locations of the profiles loaded from the zip file.
func (zp ZipProvider) From() []string {
	return zp.locations
}
