package selfupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
)

func UpdateTo(ctx context.Context, r *Release, path string) error {
	// First, we download the release asset.
	src, _, err := githubClient(ctx).Repositories.DownloadReleaseAsset(
		ctx, r.RepoOwner, r.RepoName, r.AssetID, http.DefaultClient,
	)
	if err != nil {
		return errors.Join(ErrDownload, fmt.Errorf("(%s/%s): %w", r.Version.String(), r.AssetURL, err))
	}
	defer src.Close()

	data, err := io.ReadAll(src)
	if err != nil {
		return errors.Join(ErrDownload, fmt.Errorf("(%s/%s): %w", r.Version.String(), r.AssetURL, err))
	}

	// Then, we download the validation asset.
	vSrc, _, err := githubClient(ctx).Repositories.DownloadReleaseAsset(
		ctx, r.RepoOwner, r.RepoName, r.ValidationAssetID, http.DefaultClient,
	)
	if err != nil {
		return errors.Join(
			ErrChecksumDownload,
			fmt.Errorf("(%s/%s): %w", r.Version.String(), r.AssetURL, err),
		)
	}
	defer vSrc.Close()

	validationData, err := io.ReadAll(vSrc)
	if err != nil {
		return errors.Join(ErrChecksumValidation, fmt.Errorf("error reading validation asset body: %w", err))
	}

	// Once ready, we perform the validation (SHA256 checksum).
	calculatedHash := fmt.Sprintf("%x", sha256.Sum256(data))
	hash := string(validationData[:sha256.BlockSize])
	if calculatedHash != hash {
		return fmt.Errorf("%w: sha256 mismatch: exp=%q, got=%q", ErrChecksumValidation, calculatedHash, hash)
	}

	// If successful, we decompress the downloaded asset (if needed).
	// _, cmd := filepath.Split(path)
	const cmd = "gbounty"
	asset, err := decompress(bytes.NewReader(data), r.AssetURL, cmd)
	if err != nil {
		return err
	}

	// And finally, we apply the update.
	return apply(asset, path)
}
