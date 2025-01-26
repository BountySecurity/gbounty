package syncutil_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/kit/syncutil"
)

func TestWaitOrForget(t *testing.T) {
	t.Parallel()

	t.Run("on time", func(t *testing.T) {
		t.Parallel()

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			time.Sleep(5 * time.Millisecond)
			wg.Done()
		}()

		assert.True(t, syncutil.WaitOrForget(&wg))
	})

	t.Run("off time", func(t *testing.T) {
		t.Parallel()

		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			time.Sleep(50 * time.Millisecond)
			wg.Done()
		}()

		assert.False(t, syncutil.WaitOrForget(&wg))
	})
}
