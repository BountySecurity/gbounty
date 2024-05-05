package modifier

import (
	"net/url"
	"strings"

	"github.com/google/uuid"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/kit/blindhost"
)

// InteractionHost must implement the [scan.Modifier] interface.
var _ scan.Modifier = InteractionHost{}

// InteractionHost is a [scan.Modifier] implementation that replaces the interaction host
// placeholders (e.g. {IH}, {BH} and {BC}) of a [request.Request] with unique
// request urls.
type InteractionHost struct {
	scheme string
	base   string
	hid    blindhost.HostIdentifier
}

const (
	// {IH} is the label used by GBounty for interaction host.
	ihLabel = "{IH}"

	// {BH} is the label used by GBounty for blind host.
	bhLabel = "{BH}"

	// {BC} is the legacy label used for interaction host,
	// inherited from (B)urp (C)ollaborator (by Burp Suite).
	legacyLabel = "{BC}"
)

// NewInteractionHost is a constructor function that creates a new instance of
// the [InteractionHost] modifier with the given base url and host identifier.
func NewInteractionHost(base string, hid blindhost.HostIdentifier) InteractionHost {
	hidDot := hid.ID() + "."
	if strings.Contains(base, hidDot) {
		base = strings.Replace(base, hidDot, "", 1)
	}

	return InteractionHost{
		scheme: urlScheme(base),
		base:   base,
		hid:    hid,
	}
}

// Modify modifies the request by replacing the interaction host placeholders.
func (ih InteractionHost) Modify(_ *profile.Step, _ scan.Template, req request.Request) request.Request {
	req.UID = uuid.New().String()[:8]
	bh := ih.hid.HostReqURL(ih.scheme, ih.base, req.UID)
	return replace(req, map[string]string{bhLabel: bh, ihLabel: bh, legacyLabel: bh})
}

func urlScheme(addr string) string {
	u, err := url.Parse(addr)
	if err != nil || u == nil || u.Scheme == "" {
		// Error must always be nil at this point,
		// but let's be cautious.
		return "http"
	}
	return u.Scheme
}
