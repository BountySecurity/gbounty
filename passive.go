package gbounty

import (
	"context"

	"github.com/BountySecurity/gbounty/kit/logger"
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
	"github.com/BountySecurity/gbounty/match"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

func passiveRequestScan(
	ctx context.Context,
	profiles []*profile.Request,
	req *request.Request,
	notifyMatch func(prof *profile.Request, occ []occurrence.Occurrence),
	customTokens CustomTokens,
) {
	logger.For(ctx).Debug("Performing passive request scan...")

	for _, prof := range profiles {
		if ok, occ := match.Match(ctx, match.Data{Profile: prof, Request: req, CustomTokens: customTokens}); ok {
			notifyMatch(prof, occ)
			logger.For(ctx).Infof("Passive request profile(%s) matched", prof.Name)
		}
	}

	logger.For(ctx).Debug("Passive request scan finished")
}

func passiveResponseScan(
	ctx context.Context,
	profiles []*profile.Response,
	req *request.Request,
	res *response.Response,
	notifyMatch func(prof *profile.Response, occ []occurrence.Occurrence),
	customTokens CustomTokens,
) {
	logger.For(ctx).Debug("Performing passive response scan...")

	for _, prof := range profiles {
		if ok, occ := match.Match(ctx, match.Data{Profile: prof, Original: req, Request: req, Response: res, CustomTokens: customTokens}); ok {
			notifyMatch(prof, occ)
			logger.For(ctx).Infof("Passive response profile(%s) matched", prof.Name)
		}
	}

	logger.For(ctx).Debug("Passive response scan finished")
}
