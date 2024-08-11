package selfupdate

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/google/go-github/v64/github"

	"github.com/bountysecurity/gbounty/kit/semver"
)

func DetectLatest(ctx context.Context, slug string) (release *Release, found bool, err error) {
	return detectVersion(ctx, slug, semver.Zero())
}

func detectVersion(ctx context.Context, slug string, min semver.Version) (release *Release, found bool, err error) {
	// The slug must be owner/name.
	repo := strings.Split(slug, "/")
	if len(repo) != 2 || repo[0] == "" || repo[1] == "" {
		return nil, false, fmt.Errorf("%w: %s", ErrInvalidSlug, slug)
	}

	// First, we list all the releases from the given repository.
	releases, res, err := githubClient(ctx).Repositories.ListReleases(ctx, repo[0], repo[1], nil)
	if err != nil {
		if res != nil && res.StatusCode == http.StatusNotFound {
			err = fmt.Errorf("%w: %s", ErrRepositoryNotFound, slug)
		}
		return nil, false, err
	}

	// Then, we try to find the release and asset we're looking for.
	// If the given version is [semver.Zero()], the latest version will be fetched.
	rel, asset, version, found := findReleaseAndAsset(releases, min)
	if !found {
		return nil, false, nil
	}

	// If found, we construct the release with all the information gathered.
	publishedAt := rel.GetPublishedAt().Time
	release = &Release{
		Version:       version,
		AssetURL:      asset.GetBrowserDownloadURL(),
		AssetByteSize: asset.GetSize(),
		AssetID:       asset.GetID(),
		URL:           rel.GetHTMLURL(),
		ReleaseNotes:  rel.GetBody(),
		Name:          rel.GetName(),
		PublishedAt:   &publishedAt,
		RepoOwner:     repo[0],
		RepoName:      repo[1],
	}

	// Once we have the release basic information, we try to find the validation asset.
	var validationFound bool
	validationName := asset.GetName() + ".sha256"
	for _, asset := range rel.Assets {
		if asset.GetName() == validationName {
			validationFound = true
			release.ValidationAssetID = asset.GetID()
		}
	}

	// If not found, we return an error. The validation asset is mandatory.
	if !validationFound {
		err := fmt.Errorf("%w: could not find the validation asset: %q", ErrChecksumValidation, validationName)
		return nil, false, err
	}

	return release, true, nil
}

func findReleaseAndAsset(
	releases []*github.RepositoryRelease,
	targetVersion semver.Version,
) (*github.RepositoryRelease, *github.ReleaseAsset, semver.Version, bool) {
	// Generate candidates
	suffixes := make([]string, 0, 2*7*2) //nolint:mnd
	for _, sep := range []rune{'_', '-'} {
		for _, ext := range []string{".zip", ".tar.gz", ".tgz", ".gzip", ".gz", ".tar.xz", ".xz", ""} {
			suffix := fmt.Sprintf("%s%c%s%s", runtime.GOOS, sep, runtime.GOARCH, ext)
			suffixes = append(suffixes, suffix)
			if runtime.GOOS == "windows" {
				suffix = fmt.Sprintf("%s%c%s.exe%s", runtime.GOOS, sep, runtime.GOARCH, ext)
				suffixes = append(suffixes, suffix)
			}
		}
	}

	var ver semver.Version
	var asset *github.ReleaseAsset
	var release *github.RepositoryRelease

	for _, r := range releases {
		if a, v, ok := findAssetFromRelease(r, suffixes, targetVersion); ok {
			if release == nil || v.GreaterThanOrEquals(ver) {
				ver = v
				asset = a
				release = r
			}
		}
	}

	if release == nil {
		return nil, nil, semver.Version{}, false
	}

	return release, asset, ver, true
}

func findAssetFromRelease(
	release *github.RepositoryRelease,
	suffixes []string, targetVersion semver.Version,
) (*github.ReleaseAsset, semver.Version, bool) {
	// If [semver.Parse] cannot parse the version text, it means that the text is not adopting
	// the semantic versioning. So it should be skipped.
	ver, err := semver.ShouldParse(release.GetTagName())
	if err != nil {
		return nil, semver.Version{}, false
	}

	// If it doesn't match, is Draft or Pre-release, skip
	if (targetVersion != semver.Zero() && targetVersion.NotEquals(ver)) ||
		(targetVersion == semver.Zero() && (release.GetDraft() || release.GetPrerelease())) {
		return nil, semver.Version{}, false
	}

	for _, asset := range release.Assets {
		name := asset.GetName()

		for _, s := range suffixes {
			if strings.HasSuffix(name, s) { // require version, arch etc
				// default: assume single artifact
				return asset, ver, true
			}
		}
	}

	return nil, semver.Version{}, false
}