package serve

// TSA handler is used directly via s.tsaH.ServeHTTP in mux.go.
// No additional adapter needed — the tsa.Handler already handles
// POST-only with application/timestamp-query content type.
