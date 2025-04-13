package blindhost

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/BountySecurity/gbounty/kit/logger"
)

const (
	// DefaultPollerInterval is the default interval at which
	// the poller will poll the server.
	DefaultPollerInterval = 1 * time.Second
)

// Poller is a poller that polls the server for new interactions
// every [DefaultPollerInterval] and keeps them in memory.
type Poller struct {
	c   *Client
	dur time.Duration
	hid HostIdentifier

	ctx context.Context
	cnl context.CancelCauseFunc
	wg  *sync.WaitGroup
	mtx *sync.RWMutex

	its []Interaction
}

// PollerOpt is a function that can be used to change the
// default behaviour of a poller.
type PollerOpt func(*Poller)

// WithContext sets the context of the poller.
func WithContext(ctx context.Context) PollerOpt {
	return func(p *Poller) {
		p.ctx = ctx
	}
}

// NewPoller creates a new poller. It is recommended to use
// this function instead of creating a poller manually.
//
// The poller will poll the server every DefaultPollerInterval
// by default.
//
// Use the PollerOpt functions to change the default behaviour.
func NewPoller(ctx context.Context, c *Client, opts ...PollerOpt) (*Poller, error) {
	hid, err := c.GenerateHost(ctx)
	if err != nil {
		logger.For(ctx).Errorf("Could not register new blind host: %s", err.Error())
		return nil, err
	}

	// Default poller
	p := &Poller{
		c:   c,
		ctx: context.Background(),
		dur: DefaultPollerInterval,
		hid: hid,
		its: make([]Interaction, 0),
		wg:  &sync.WaitGroup{},
		mtx: &sync.RWMutex{},
	}

	for _, opt := range opts {
		opt(p)
	}

	// Set up context...
	p.ctx, p.cnl = context.WithCancelCause(p.ctx)

	// ...and run!
	p.run()

	return p, nil
}

// HostIdentifier returns the host identifier of the poller.
func (p *Poller) HostIdentifier() HostIdentifier {
	return p.hid
}

// Search searches for any interaction that contains
// the given [substr] in the interaction's request.
// E.g. in headers, like: Host: [substr]-[id].bh.com.
func (p *Poller) Search(substr string) *Interaction {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	return p.search(p.its, substr)
}

// BruteSearch is like [Search], but searches in all
// interactions, not just the ones that were polled
// and kept in memory.
func (p *Poller) BruteSearch(substr string) *Interaction {
	interactions, err := p.c.GetAllInteractions(p.ctx, p.hid)
	if err != nil {
		logger.For(p.ctx).Errorf("Could not fetch all blind host interactions: %s", err.Error())
		return nil
	}

	return p.search(interactions, substr)
}

// Close stops the poller. Either use this function
// or manage a cancellable context yourself.
func (p *Poller) Close() {
	p.cnl(errors.New("poller closed")) //nolint:goerr113
	p.wg.Wait()
}

func (p *Poller) run() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		t := time.NewTicker(p.dur)
		defer t.Stop()

		for {
			select {
			case <-p.ctx.Done():
				p.cnl(context.Cause(p.ctx))
				return
			case <-t.C:
				all, err := p.c.GetAllInteractions(p.ctx, p.hid)
				if err == nil {
					p.mtx.Lock()
					p.its = append(p.its, all[len(p.its):]...)
					p.mtx.Unlock()
				} else {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						logger.For(p.ctx).Warn("Retrieval of all blind host interactions timed out")
					} else {
						logger.For(p.ctx).Errorf("Could not fetch all blind host interactions: %s", err.Error())
					}
				}
			}
		}
	}()
}

func (p *Poller) search(its []Interaction, substr string) *Interaction {
	for _, it := range its {
		if strings.Contains(strings.ToLower(it.RawRequest), substr) {
			return &it
		}
	}
	return nil
}
