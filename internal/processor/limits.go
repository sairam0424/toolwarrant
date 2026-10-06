package processor

import "errors"

// errPayloadSize means a hook payload was too large to inspect safely. The
// hook is then denied rather than passed through uninspected.
var errPayloadSize = errors.New("processor: payload exceeds the size limit")
