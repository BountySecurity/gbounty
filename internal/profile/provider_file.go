package profile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

const (
	FileExtensionV2 = ".bb2"
)

var (
	ErrProfilePath = errors.New("cannot read profile path")
	ErrUnknownType = errors.New("unknown profile type")
)

// Config is the configuration for the FileProvider.
type Config struct {
	Path string `default:"profiles"`
}

// Never obfuscate the Config type.
var _ = reflect.TypeOf(Config{})

// ProfilesPath returns the path to the profiles' directory.
func (cfg Config) ProfilesPath() string {
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, cfg.Path)
}

// FileProvider is an implementation of the Provider interface
// that reads profiles from one or multiple file system locations.
type FileProvider struct {
	data
	locations []string
}

type data struct {
	actives     []*Active
	passiveReqs []*Request
	passiveRes  []*Response
	tags        map[string]struct{}
}

func returnErr(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%w(%s): %s", ErrProfilePath, pathErr.Path, pathErr.Err.Error())
	}

	return err
}

// NewFileProvider creates a new FileProvider instance.
func NewFileProvider(locations ...string) (FileProvider, error) {
	data := data{
		actives:     make([]*Active, 0),
		passiveReqs: make([]*Request, 0),
		passiveRes:  make([]*Response, 0),
		tags:        make(map[string]struct{}),
	}

	for _, location := range locations {
		err := filepath.Walk(location,
			func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// It only looks for *.bb and *.bb2 files
				ext := filepath.Ext(info.Name())
				if info.IsDir() || ext != FileExtensionV2 {
					return nil
				}

				fileBytes, err := os.ReadFile(path)
				if err != nil {
					return returnErr(err)
				}

				switch ext {
				case FileExtensionV2:
					err = readBB2Profiles(&data, fileBytes)
				}

				if err != nil {
					return fmt.Errorf("%w(%s): %s", ErrProfilePath, path, err.Error())
				}

				return nil
			})
		if err != nil {
			return FileProvider{}, returnErr(err)
		}
	}

	return FileProvider{
		data:      data,
		locations: locations,
	}, nil
}

// readBB2Profiles takes the given fileBytes and tries to unmarshal them into
// either an Active, a Request or a Response profile.
//
// It uses a stupid literal-string-based comparison algorithm to determine the type
// of profile (scanner) it is: active, passive_request or passive_response.
func readBB2Profiles(data *data, fileBytes []byte) error {
	switch {
	case bytes.Contains(fileBytes, []byte("\"scanner\":\"active\"")),
		bytes.Contains(fileBytes, []byte("\"scanner\": \"active\"")):
		var unmarshalled []*Active
		err := json.Unmarshal(fileBytes, &unmarshalled)
		if err != nil {
			return err
		}

		for _, p := range unmarshalled {
			for _, t := range p.Tags {
				data.tags[t] = struct{}{}
			}
			data.actives = append(data.actives, p)
		}
	case bytes.Contains(fileBytes, []byte("\"scanner\":\"passive_request\"")),
		bytes.Contains(fileBytes, []byte("\"scanner\": \"passive_request\"")):
		var unmarshalled []*Request
		err := json.Unmarshal(fileBytes, &unmarshalled)
		if err != nil {
			return err
		}

		for _, p := range unmarshalled {
			for _, t := range p.Tags {
				data.tags[t] = struct{}{}
			}
			data.passiveReqs = append(data.passiveReqs, p)
		}
	case bytes.Contains(fileBytes, []byte("\"scanner\":\"passive_response\"")),
		bytes.Contains(fileBytes, []byte("\"scanner\": \"passive_response\"")):
		var unmarshalled []*Response
		err := json.Unmarshal(fileBytes, &unmarshalled)
		if err != nil {
			return err
		}

		for _, p := range unmarshalled {
			for _, t := range p.Tags {
				data.tags[t] = struct{}{}
			}
			data.passiveRes = append(data.passiveRes, p)
		}
	default:
		return ErrUnknownType
	}
	return nil
}

// Actives returns all the active profiles loaded from file system.
func (fp FileProvider) Actives() []*Active {
	return fp.actives
}

// ActivesEnabled returns all the active profiles loaded from the
// file system that are enabled.
func (fp FileProvider) ActivesEnabled() []*Active {
	return enabled(fp.actives)
}

// PassiveReqs returns all the passive request profiles loaded from file system.
func (fp FileProvider) PassiveReqs() []*Request {
	return fp.passiveReqs
}

// PassiveReqsEnabled returns all the passive request profiles loaded from the
// file system that are enabled.
func (fp FileProvider) PassiveReqsEnabled() []*Request {
	return enabled(fp.passiveReqs)
}

// PassiveRes returns all the passive response profiles loaded from file system.
func (fp FileProvider) PassiveRes() []*Response {
	return fp.passiveRes
}

// PassiveResEnabled returns all the passive response profiles loaded from the
// file system that are enabled.
func (fp FileProvider) PassiveResEnabled() []*Response {
	return enabled(fp.passiveRes)
}

// Tags returns all the tags found in the profiles loaded from the file system.
func (fp FileProvider) Tags() []string {
	tags := make([]string, 0, len(fp.tags))
	for tag := range fp.tags {
		tags = append(tags, tag)
	}

	sort.Strings(tags)

	return tags
}

// From returns the locations from where the profiles were loaded.
func (fp FileProvider) From() []string {
	return fp.locations
}
