package selfupdate

import (
	"errors"
	"time"

	"github.com/BountySecurity/gbounty/kit/semver"
)

var (
	ErrInvalidSlug        = errors.New("invalid slug format, it must be owner/name")
	ErrRepositoryNotFound = errors.New("repository or release not found")
	ErrDownload           = errors.New("release download failed")
	ErrChecksumValidation = errors.New("checksum validation failed")
	ErrChecksumDownload   = errors.New("checksum download failed")
	ErrDecompression      = errors.New("release decompression failed")
	ErrReleaseBinary      = errors.New("release archive does not contain the binary")
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
