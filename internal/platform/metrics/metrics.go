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

// ConcurrentTemplates is a gauge metric that represents the total amount of template requests being processed
// concurrently. See [gbounty.Template] for more details about what a template is.
var ConcurrentTemplates = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "scan_concurrent_templates",
	Help: "Total amount of template requests being processed concurrently",
})

// OngoingTasks is a gauge metric that represents the total amount of ongoing tasks.
// See [scan.Task] for more details about what a task is.
var OngoingTasks = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "scan_tasks_ongoing",
	Help: "Total amount of ongoing tasks",
})
