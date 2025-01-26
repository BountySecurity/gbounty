package modifier

import (
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/bountysecurity/gbounty"
	"github.com/bountysecurity/gbounty/kit/blindhost"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

// InteractionHost must implement the [scan.Modifier] interface.
var _ gbounty.Modifier = InteractionHost{}

// InteractionHost is a [scan.Modifier] implementation that replaces the blind host
// placeholders (e.g. {BH}) of a [request.Request] with unique
// request urls.
type InteractionHost struct {
	scheme string
	base   string
	hid    blindhost.HostIdentifier
}

const (
	// {BH} is the label used by GBounty for blind host.
	bhLabel = "{BH}"
)

// NewInteractionHost is a constructor function that creates a new instance of
// the [InteractionHost] modifier with the given base url and host identifier.
func NewInteractionHost(base string, hid blindhost.HostIdentifier) InteractionHost {
	base = strings.Replace(base, hid.ID()+".", "", 1)
	return InteractionHost{
		scheme: urlScheme(base),
		base:   base,
		hid:    hid,
	}
}

// Modify modifies the request by replacing the interaction host placeholders.
func (ih InteractionHost) Modify(_ *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	req.UID = uuid.New().String()[:8]
	bh := ih.hid.HostReqURL(ih.scheme, ih.base, req.UID)
	return replace(req, map[string]string{bhLabel: bh})
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
