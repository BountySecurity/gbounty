package blindhost

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bountysecurity/gbounty/kit/logger"
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

	registrationDisabled bool

	ctx context.Context
	cnl context.CancelCauseFunc
	wg  *sync.WaitGroup
	mtx *sync.RWMutex

	its    []Interaction
	its2nd []Interaction
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

// WithInterval sets the interval at which the poller will
// poll the server.
func WithInterval(dur time.Duration) PollerOpt {
	return func(p *Poller) {
		p.dur = dur
	}
}

// WithHostIdentifier sets the host identifier of the poller.
func WithHostIdentifier(hid HostIdentifier) PollerOpt {
	return func(p *Poller) {
		p.hid = hid
	}
}

// WithRegistrationDisabled disables the poller's host registration.
func WithRegistrationDisabled() PollerOpt {
	return func(p *Poller) {
		p.registrationDisabled = true
	}
}

// NewPoller creates a new poller. It is recommended to use
// this function instead of creating a poller manually.
//
// The poller will poll the server every DefaultPollerInterval
// by default.
//
// Use the PollerOpt functions to change the default behaviour.
func NewPoller(c *Client, opts ...PollerOpt) (*Poller, error) {
	// Default poller
	p := &Poller{
		c:      c,
		ctx:    context.Background(),
		dur:    DefaultPollerInterval,
		hid:    HostIdentifier(uuid.New()),
		its:    make([]Interaction, 0),
		its2nd: make([]Interaction, 0),
		wg:     &sync.WaitGroup{},
		mtx:    &sync.RWMutex{},
	}

	for _, opt := range opts {
		opt(p)
	}

	// Set up context...
	p.ctx, p.cnl = context.WithCancelCause(p.ctx)

	// ...and run!
	if err := p.run(); err != nil {
		return nil, err
	}

	return p, nil
}

// Search searches for any interaction that contains
// the given [substr] in the interaction's request.
// E.g. in headers, like: Host: [substr]-[id].bh.com.
func (p *Poller) Search(substr string) *Interaction {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	// First, we try luck with the hot storage
	if it := p.search(p.its, substr); it != nil {
		return it
	}

	// Otherwise, we try luck with the cold storage
	return p.search(p.its2nd, substr)
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

func (p *Poller) run() error {
	if !p.registrationDisabled {
		err := p.c.AddHost(p.ctx, p.hid)
		if err != nil {
			logger.For(p.ctx).Errorf("Could not register new blind host: %s", err.Error())
			return err
		}
	}

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
				// First, we populate the "hot storage".
				its, err := p.c.GetInteractions(p.ctx, p.hid)
				if err == nil {
					p.mtx.Lock()
					p.its = append(p.its, its...)
					p.mtx.Unlock()
				} else {
					// In case of "timeout", we just log the error and try again with
					// the "cold storage". Otherwise, (other error), we skip the iteration.
					// In the future, we might want to add more resilience for such cases.
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						logger.For(p.ctx).Warn("Retrieval of blind host interactions timed out")
					} else {
						logger.For(p.ctx).Errorf("Could not fetch new blind host interactions: %s", err.Error())
						continue
					}
				}

				// Then, we populate the "cold storage", using the same heuristics.
				all, err := p.c.GetAllInteractions(p.ctx, p.hid)
				if err == nil {
					p.mtx.Lock()
					p.its2nd = append(p.its2nd, all[len(p.its2nd):]...)
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
	return nil
}

func (p *Poller) search(its []Interaction, substr string) *Interaction {
	for _, it := range its {
		if strings.Contains(strings.ToLower(it.RawRequest), substr) {
			return &it
		}
	}
	return nil
}
