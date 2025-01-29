package bootstrap

import (
	"context"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/internal/platform/cli"
	"github.com/BountySecurity/gbounty/kit/logger"
	internalhttp "github.com/BountySecurity/gbounty/platform/http"
	"github.com/BountySecurity/gbounty/platform/http/client"
	"github.com/BountySecurity/gbounty/platform/http/stdclient"
	"github.com/BountySecurity/gbounty/request"
)

func setupScanRequester(ctx context.Context, cfg cli.Config) func(*request.Request) (gbounty.Requester, error) {
	const timeout = 20 * time.Second

	var (
		baseOpts []client.Opt
		stdOpts  = []stdclient.Opt{
			stdclient.WithClient(
				&http.Client{
					Timeout:   timeout,
					Transport: stdclient.DefaultTransport().Clone(),
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
		func() gbounty.Requester {
			return client.New(baseOpts...)
		},
		uint32(maxConcurrentRequests), // Technically, we can have up to [maxConcurrentRequests] clients.
	)

	stdPool := internalhttp.NewClientPool(
		ctx,
		func() gbounty.Requester {
			return stdclient.New(stdOpts...)
		},
		uint32(maxConcurrentRequests), // Technically, we can have up to [maxConcurrentRequests] clients.
	)

	return gbounty.NewReqBuilderPool(
		ctx,
		func(r *request.Request) (gbounty.Requester, error) {
			// If it looks like an HTTP/2 request:
			if strings.Contains(r.Proto, "HTTP/2") {
				return stdPool(r)
			}
			// Otherwise, we use our own client.
			return basePool(r)
		},
		uint32(maxConcurrentRequests),
	)
}
