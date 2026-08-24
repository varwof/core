package serve

// OCSP handler is used directly via s.ocspH.ServeHTTP in mux.go.
// No additional adapter needed — the ocsp.Handler already handles
// both POST and GET methods with proper content types.
