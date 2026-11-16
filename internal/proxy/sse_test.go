package proxy_test

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/integrity"
)

// TestGateway_StreamsSSEIncrementally proves the gateway forwards SSE events
// as they are produced instead of buffering the response: the client must
// receive the first event while the backend is still blocked before sending
// the second.
func TestGateway_StreamsSSEIncrementally(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: two\n\n")
	}))
	t.Cleanup(backend.Close)

	// Inspection on so ModifyResponse is installed — the streaming
	// early-return is what's under test.
	gw := newGateway(t, backend.URL, nil, &config.InspectionConfig{FilterToolsList: true}, integrity.ModeOff)
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"watch"}}`))
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	// The first event must arrive while the backend is still holding the
	// second one back. Read with a deadline so a buffering regression fails
	// fast instead of deadlocking the test.
	type line struct {
		s   string
		err error
	}
	lines := make(chan line, 1)
	br := bufio.NewReader(resp.Body)
	go func() {
		s, err := br.ReadString('\n')
		lines <- line{s, err}
	}()
	select {
	case l := <-lines:
		if l.err != nil || !strings.Contains(l.s, "one") {
			t.Fatalf("first event read = %q, err %v", l.s, l.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first SSE event was not delivered before backend finished (response is being buffered)")
	}

	close(release)
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("reading remainder: %v", err)
	}
	if !strings.Contains(string(rest), "data: two") {
		t.Fatalf("second event missing from stream remainder: %q", rest)
	}
}

// TestGateway_ToolsListForcedToJSON verifies that when inspection is enabled,
// the gateway rewrites the Accept header on tools/list requests so a
// Streamable HTTP backend answers in JSON (which integrity pinning and list
// filtering can inspect) rather than SSE.
func TestGateway_ToolsListForcedToJSON(t *testing.T) {
	var gotAccept string
	body := toolsList("read_file")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(backend.Close)

	gw := newGateway(t, backend.URL, nil, &config.InspectionConfig{FilterToolsList: true}, integrity.ModeOff)

	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Accept", "text/event-stream, application/json")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotAccept != "application/json" {
		t.Errorf("backend saw Accept = %q, want application/json", gotAccept)
	}
}

// TestGateway_SSETransportAlias verifies transport: "sse" backends are routable.
func TestGateway_SSETransportAlias(t *testing.T) {
	body := toolsList("read_file")
	up := upstream(t, &body)
	cfg := &config.Config{
		Servers: []config.ServerConfig{{Name: "up", URL: up.URL, Transport: "sse"}},
	}
	gw := newGatewayFromConfig(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mcp/up/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 via sse-transport backend, got %d", rec.Code)
	}
}
