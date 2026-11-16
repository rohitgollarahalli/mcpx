// Package httperr provides consistent JSON error responses for all
// gateway-generated HTTP errors. Edge errors (auth, routing, rate limits)
// use a plain envelope; errors for requests that carried a parseable
// JSON-RPC message use the JSON-RPC error format so MCP clients can
// surface them natively.
package httperr

import (
	"encoding/json"
	"net/http"

	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

// Stable machine-readable error codes for the plain envelope.
const (
	CodeUnauthorized        = "unauthorized"
	CodeRateLimited         = "rate_limited"
	CodeBadRequest          = "bad_request"
	CodeUnknownServer       = "unknown_server"
	CodeUpstreamError       = "upstream_error"
	CodeUpstreamUnavailable = "upstream_unavailable"
	CodeMisconfigured       = "gateway_misconfigured"
)

type envelope struct {
	Error errBody `json:"error"`
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Write emits {"error":{"code":...,"message":...}} with the given HTTP
// status. Callers set response headers (WWW-Authenticate, Retry-After)
// before calling.
func Write(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(envelope{Error: errBody{Code: code, Message: msg}})
}

// WriteRPC emits a JSON-RPC error envelope with the given HTTP status.
// Used when the request carried a parseable JSON-RPC message so the
// error can echo its id.
func WriteRPC(w http.ResponseWriter, status int, id any, rpcCode int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(mcp.NewErrorResponse(id, rpcCode, msg))
}
