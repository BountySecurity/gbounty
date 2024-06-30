package selfupdate

import (
	"fmt"
	"time"

	"github.com/bountysecurity/gbounty/kit/semver"
)

var (
	ErrInvalidSlug        = fmt.Errorf("invalid slug format, it must be owner/name")
	ErrRepositoryNotFound = fmt.Errorf("repository or release not found")
	ErrDownload           = fmt.Errorf("release could not be downloaded")
	ErrChecksumValidation = fmt.Errorf("checksum validation failed")
	ErrChecksumDownload   = fmt.Errorf("checksum could not be downloaded")
	ErrDecompression      = fmt.Errorf("release could not be decompressed")
	ErrReleaseBinary      = fmt.Errorf("release archive does not contain the binary")
)

// Release represents a release asset for current OS and arch.
type Release struct {
	// Version is the version of the release
	Version semver.Version
	// AssetURL is a URL to the uploaded file for the release
	AssetURL string
	// AssetSize represents the size of asset in bytes
	AssetByteSize int
	// AssetID is the ID of the asset on GitHub
	AssetID int64
	// ValidationAssetID is the ID of additional validation asset on GitHub
	ValidationAssetID int64
	// URL is a URL to release page for browsing
	URL string
	// ReleaseNotes is a release notes of the release
	ReleaseNotes string
	// Name represents a name of the release
	Name string
	// PublishedAt is the time when the release was published
	PublishedAt *time.Time
	// RepoOwner is the owner of the repository of the release
	RepoOwner string
	// RepoName is the name of the repository of the release
	RepoName string
}
