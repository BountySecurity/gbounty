package selfupdate

import (
	"context"
	"net/http"
	"os"

	"github.com/google/go-github/v64/github"
	"golang.org/x/oauth2"

	"github.com/bountysecurity/gbounty/kit/gitconfig"
)

func githubClient() *github.Client {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		// We ignore the error, because it's not a big deal if we can't get the token.
		// In the worst case, the token will remain empty and the user will be rate limited.
		token, _ = gitconfig.GithubToken()
	}

	client := httpClient(context.Background(), token)
	return github.NewClient(client)
}

func httpClient(ctx context.Context, token string) *http.Client {
	if token == "" {
		return http.DefaultClient
	}

	src := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	return oauth2.NewClient(ctx, src)
}
