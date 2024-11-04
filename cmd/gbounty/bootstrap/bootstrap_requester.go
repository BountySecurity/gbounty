package bootstrap

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"time"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/platform/cli"
	internalhttp "github.com/bountysecurity/gbounty/internal/platform/http"
	"github.com/bountysecurity/gbounty/internal/platform/http/client"
	"github.com/bountysecurity/gbounty/internal/platform/http/stdclient"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/kit/logger"
)

func setupScanRequester(ctx context.Context, cfg cli.Config) func(*request.Request) (scan.Requester, error) {
	var (
		baseOpts []client.Opt
		stdOpts  = []stdclient.Opt{
			stdclient.WithClient(
				&http.Client{
					Timeout:   20 * time.Second,
					Transport: stdclient.DefaultTransport.Clone(),
				},
			),
		}
	)

	if len(cfg.ProxyAddress) > 0 {
		baseOpts = append(baseOpts, client.WithProxyAddr(cfg.ProxyAddress))
		stdOpts = append(stdOpts, stdclient.WithProxyAddr(cfg.ProxyAddress))
		logger.For(ctx).Debugf("The HTTP client is using a proxy address: %s", cfg.ProxyAddress)
	}

	// Note: The ProxyAuth is not supported by `stdclient` yet.
	// Try to use the address instead: "http(s)://username:password@host:port".
	if len(cfg.ProxyAuth) > 0 {
		baseOpts = append(baseOpts, client.WithProxyAuth(cfg.ProxyAuth))
		logger.For(ctx).Debugf("The HTTP client is using a proxy auth: %s", cfg.ProxyAuth)
	}

	maxConcurrentRequests := 1_000
	if stringVal, defined := os.LookupEnv("GBOUNTY_MAX_CONCURRENT_REQUESTS"); defined {
		if n, err := strconv.ParseInt(stringVal, 10, 32); err == nil {
			maxConcurrentRequests = int(n)
		}
	}

	basePool := internalhttp.NewClientPool(
		ctx,
		func() scan.Requester {
			return client.New(baseOpts...)
		},
		uint32(maxConcurrentRequests), // Technically, we can have up to [maxConcurrentRequests] clients.
	)

	stdPool := internalhttp.NewClientPool(
		ctx,
		func() scan.Requester {
			return stdclient.New(stdOpts...)
		},
		uint32(maxConcurrentRequests), // Technically, we can have up to [maxConcurrentRequests] clients.
	)

	return scan.NewReqBuilderPool(
		ctx,
		func(r *request.Request) (scan.Requester, error) {
			// If it looks like an HTTP/2 request:
			if r.Proto == "HTTP/2.0" {
				return stdPool(r)
			}
			// Otherwise, we use our own client.
			return basePool(r)

		},
		uint32(maxConcurrentRequests),
	)
}
