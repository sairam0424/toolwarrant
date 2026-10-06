package processor

import "github.com/sairam0424/toolwarrant/internal/catalog"

// observe remembers the digest of the definition the upstream served for a
// catalog tool in a tools/list response. It reports false when the table is
// full and the name is new; updating a name that is already tracked always
// succeeds because it does not grow the table.
//
// Callers must only pass names that are in the current snapshot. That, plus
// pruneObserved, is what keeps the table bounded by the catalog rather than
// by what a hostile upstream chooses to send.
func (s *Server) observe(name, digest string) bool {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	if _, tracked := s.observed[name]; !tracked && len(s.observed) >= s.maxTracked {
		return false
	}
	s.observed[name] = digest
	return true
}

// observedDigest returns the digest from the most recent tools/list that
// included the named tool, if any list did since the processor started.
func (s *Server) observedDigest(name string) (string, bool) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	d, ok := s.observed[name]
	return d, ok
}

// pruneObserved forgets tools that are no longer in the catalog, so a tool
// that is deleted and re-created starts with no stale evidence and the table
// cannot accumulate names over the life of the process.
func (s *Server) pruneObserved(tools map[string]catalog.ToolPolicy) {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	for name := range s.observed {
		if _, ok := tools[name]; !ok {
			delete(s.observed, name)
		}
	}
}

// trackedCount is the number of remembered digests; tests use it to check the
// MaxTracked bound.
func (s *Server) trackedCount() int {
	s.obsMu.Lock()
	defer s.obsMu.Unlock()
	return len(s.observed)
}
