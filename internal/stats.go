package scan

import (
	"sync"
	"time"
)

// Stats is a structure that holds multiple stats about the [scan] process,
// such as the number of requests, the number of performed requests, etc.
type Stats struct {
	NumOfTotalRequests     int
	NumOfPerformedRequests int
	NumOfSucceedRequests   int
	NumOfFailedRequests    int
	NumOfSkippedRequests   int

	NumOfRequestsToAnalyze  int
	NumOfResponsesToAnalyze int

	TemplatesEnded map[int]struct{}

	NumOfEntrypoints int
	NumOfMatches     int

	StartedAt time.Time

	sync.Mutex
}

// NewStats creates a new instance of Stats.
func NewStats() *Stats {
	return &Stats{
		StartedAt:      time.Now(),
		TemplatesEnded: make(map[int]struct{}),
	}
}

func (s *Stats) incrementTotalRequests(n int) {
	s.Lock()
	s.NumOfTotalRequests += n
	s.Unlock()
}

func (s *Stats) incrementSucceedRequests(n int) {
	s.Lock()
	s.NumOfPerformedRequests += n
	s.NumOfSucceedRequests += n
	s.Unlock()
}

func (s *Stats) incrementFailedRequests(n int) {
	s.Lock()
	s.NumOfPerformedRequests += n
	s.NumOfFailedRequests += n
	s.Unlock()
}

func (s *Stats) incrementSkippedRequests(n int) {
	s.Lock()
	s.NumOfSkippedRequests += n
	s.Unlock()
}

func (s *Stats) markTemplateAsEnded(i int) {
	s.Lock()
	s.TemplatesEnded[i] = struct{}{}
	s.Unlock()
}

func (s *Stats) isTemplateEnded(tpl Template) bool {
	s.Lock()
	defer s.Unlock()

	_, ok := s.TemplatesEnded[tpl.Idx]

	return ok
}

func (s *Stats) incrementEntrypoints(n int) {
	s.Lock()
	s.NumOfEntrypoints += n
	s.Unlock()
}

func (s *Stats) incrementMatches(n int) {
	s.Lock()
	s.NumOfMatches += n
	s.Unlock()
}

func (s *Stats) incrementRequestsToAnalyze(n int) {
	s.Lock()
	s.NumOfRequestsToAnalyze += n
	s.Unlock()
}

func (s *Stats) incrementResponsesToAnalyze(n int) {
	s.Lock()
	s.NumOfResponsesToAnalyze += n
	s.Unlock()
}
