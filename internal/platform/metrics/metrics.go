//nolint:gochecknoglobals
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// OngoingRequests is a gauge metric that represents the total amount of ongoing HTTP requests.
var OngoingRequests = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "http_client_ongoing_requests",
	Help: "Total amount of ongoing requests",
})
