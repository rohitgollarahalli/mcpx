package openapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream is a fake REST API that records what it received.
type upstream struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []*http.Request
	// bodies holds request bodies in the same order as got.
	bodies []string
	// respond, when set, writes the response; default 200 {"ok":true}.
	respond func(w http.ResponseWriter, r *http.Request)
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.got = append(u.got, r)
		u.bodies = append(u.bodies, string(b))
		fn := u.respond
		u.mu.Unlock()
		if fn != nil {
			fn(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) last(t *testing.T) (*http.Request, string) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.got) == 0 {
		t.Fatal("upstream received no request")
	}
	return u.got[len(u.got)-1], u.bodies[len(u.bodies)-1]
}

func (u *upstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.got)
}

func newServer(t *testing.T, up *upstream, mutate func(*Options)) *Server {
	t.Helper()
	opts := Options{
		Name:    "pets",
		BaseURL: up.srv.URL + "/v1",
		Headers: map[string]string{"X-Api-Key": "secret-key"},
		Version: "test",
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(loadPetstore(t), opts)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func rpc(t *testing.T, h http.Handler, body string) (int, rpcResp) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
	var r rpcResp
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("invalid JSON response %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code, r
}

func callTool(t *testing.T, h http.Handler, name string, args map[string]any) (int, rpcResp, callResult) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args}})
	code, r := rpc(t, h, string(b))
	var cr callResult
	if len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, &cr); err != nil {
			t.Fatal(err)
		}
	}
	return code, r, cr
}

func TestInitializeAndToolsList(t *testing.T) {
	s := newServer(t, newUpstream(t), nil)

	code, r := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if code != 200 || r.Error != nil {
		t.Fatalf("initialize: %d %v", code, r.Error)
	}
	var init struct {
		ProtocolVersion string         `json:"protocolVersion"`
		Capabilities    map[string]any `json:"capabilities"`
		ServerInfo      struct{ Name string }
	}
	json.Unmarshal(r.Result, &init)
	if init.ProtocolVersion != "2025-03-26" || init.Capabilities["tools"] == nil || init.ServerInfo.Name != "mcpx-openapi/pets" {
		t.Errorf("initialize result = %s", r.Result)
	}
	_, r = rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	json.Unmarshal(r.Result, &init)
	if init.ProtocolVersion != latestProtocol {
		t.Errorf("unknown protocol should negotiate latest, got %q", init.ProtocolVersion)
	}

	_, r = rpc(t, s, `{"jsonrpc":"2.0","id":"abc","method":"tools/list"}`)
	if string(r.ID) != `"abc"` {
		t.Errorf("id not echoed: %s", r.ID)
	}
	var list struct {
		Tools []struct {
			Name        string         `json:"name"`
			InputSchema map[string]any `json:"inputSchema"`
			Annotations map[string]any `json:"annotations"`
		} `json:"tools"`
	}
	json.Unmarshal(r.Result, &list)
	if len(list.Tools) != 8 || list.Tools[0].InputSchema["type"] != "object" {
		t.Errorf("tools/list = %s", r.Result)
	}
}

func TestProtocolEdges(t *testing.T) {
	s := newServer(t, newUpstream(t), nil)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)))
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("notification: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", rec.Code)
	}
	if code, _ := rpc(t, s, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`); code != http.StatusBadRequest {
		t.Errorf("batch: %d", code)
	}
	if code, _ := rpc(t, s, `not json`); code != http.StatusBadRequest {
		t.Errorf("garbage: %d", code)
	}
	if _, r := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage"}`); r.Error == nil || r.Error.Code != -32601 {
		t.Errorf("unknown method: %+v", r.Error)
	}
	if _, r := rpc(t, s, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); r.Error != nil || string(r.Result) != "{}" {
		t.Errorf("ping: %s %v", r.Result, r.Error)
	}
	if _, r, _ := callTool(t, s, "nope", nil); r.Error == nil || r.Error.Code != -32602 {
		t.Errorf("unknown tool: %+v", r.Error)
	}
}

func TestCallMapsPathQueryAndHeaders(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)

	code, r, res := callTool(t, s, "listPets", map[string]any{
		"limit":            10,
		"tags":             []any{"good", "small dog"},
		"ids":              []any{1, 2.5},
		"X-Request-Source": "claude",
	})
	if code != 200 || r.Error != nil || res.IsError {
		t.Fatalf("call failed: %d %+v %+v", code, r.Error, res)
	}
	if res.Content[0].Text != `{"ok":true}` {
		t.Errorf("result text = %q", res.Content[0].Text)
	}
	req, _ := up.last(t)
	if req.Method != http.MethodGet || req.URL.Path != "/v1/pets" {
		t.Errorf("request = %s %s", req.Method, req.URL.Path)
	}
	q := req.URL.Query()
	if q.Get("limit") != "10" || strings.Join(q["tags"], "|") != "good|small dog" || q.Get("ids") != "1,2.5" {
		t.Errorf("query = %v", q)
	}
	if req.Header.Get("X-Request-Source") != "claude" || req.Header.Get("X-Api-Key") != "secret-key" {
		t.Errorf("headers = %v", req.Header)
	}
}

func TestPathParameterCannotEscapeItsSegment(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)

	_, _, res := callTool(t, s, "getPet", map[string]any{"petId": "a/../../admin?x=1"})
	if res.IsError {
		t.Fatalf("unexpected tool error: %v", res.Content)
	}
	req, _ := up.last(t)
	if req.URL.EscapedPath() != "/v1/pets/a%2F..%2F..%2Fadmin%3Fx=1" || req.URL.RawQuery != "" {
		t.Errorf("path escaped wrongly: %s ? %s", req.URL.EscapedPath(), req.URL.RawQuery)
	}

	for _, bad := range []string{"..", ".", ""} {
		before := up.count()
		_, _, res := callTool(t, s, "getPet", map[string]any{"petId": bad})
		if !res.IsError || up.count() != before {
			t.Errorf("petId %q should be rejected without calling upstream", bad)
		}
	}
}

func TestInjectedHeadersWinOverArguments(t *testing.T) {
	up := newUpstream(t)
	doc := `{"openapi":"3.1.0","paths":{"/x":{"get":{"operationId":"x","parameters":[
	  {"name":"X-Api-Key","in":"header","schema":{"type":"string"}}]}}}}`
	spec, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(spec, Options{BaseURL: up.srv.URL, Headers: map[string]string{"X-Api-Key": "real"}})
	if err != nil {
		t.Fatal(err)
	}
	callTool(t, s, "x", map[string]any{"X-Api-Key": "attacker"})
	if req, _ := up.last(t); req.Header.Get("X-Api-Key") != "real" {
		t.Errorf("argument overrode injected credential: %q", req.Header.Get("X-Api-Key"))
	}
	if _, _, res := callTool(t, s, "x", map[string]any{"X-Api-Key": "a\r\nEvil: 1"}); !res.IsError {
		t.Error("CRLF in a header argument must be rejected")
	}
}

func TestFlatBodyAndBodyArgument(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)

	_, _, res := callTool(t, s, "createPet", map[string]any{"name": "Rex", "species": "dog"})
	if res.IsError {
		t.Fatalf("createPet: %v", res.Content)
	}
	req, body := up.last(t)
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("request = %s %s", req.Method, req.Header.Get("Content-Type"))
	}
	var got map[string]any
	json.Unmarshal([]byte(body), &got)
	if got["name"] != "Rex" || got["species"] != "dog" || len(got) != 2 {
		t.Errorf("body = %s", body)
	}

	_, _, res = callTool(t, s, "replacePets", map[string]any{"body": []any{map[string]any{"name": "A"}}})
	if res.IsError {
		t.Fatalf("replacePets: %v", res.Content)
	}
	req, body = up.last(t)
	if req.Method != http.MethodPut || body != `[{"name":"A"}]` {
		t.Errorf("replacePets sent %s %s", req.Method, body)
	}

	_, _, res = callTool(t, s, "patch_pets_petId", map[string]any{"petId": "7", "name": "B"})
	req, _ = up.last(t)
	if res.IsError || req.Header.Get("Content-Type") != "application/merge-patch+json" {
		t.Errorf("patch content type = %q (%v)", req.Header.Get("Content-Type"), res.Content)
	}
}

func TestArgumentValidation(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)
	cases := map[string]struct {
		tool string
		args map[string]any
		want string
	}{
		"missing path param":  {"getPet", map[string]any{}, `missing required argument "petId"`},
		"missing body":        {"replacePets", map[string]any{}, `missing required argument "body"`},
		"unknown arg":         {"getPet", map[string]any{"petId": "1", "colour": "red"}, "unknown argument(s): colour"},
		"object in path":      {"getPet", map[string]any{"petId": map[string]any{}}, "expected a string"},
		"nested array query":  {"listPets", map[string]any{"tags": []any{[]any{"x"}}}, "expected a string"},
		"cookie not an input": {"listPets", map[string]any{"session": "s"}, "unknown argument(s): session"},
	}
	before := up.count()
	for name, c := range cases {
		code, r, res := callTool(t, s, c.tool, c.args)
		if code != 200 || r.Error != nil || !res.IsError || !strings.Contains(res.Content[0].Text, c.want) {
			t.Errorf("%s: code=%d err=%+v result=%+v", name, code, r.Error, res)
		}
	}
	if up.count() != before {
		t.Error("invalid calls must not reach the upstream API")
	}
}

func TestUpstreamErrors(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)

	// 4xx: a tool error the model can act on.
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"no such pet"}`))
	}
	code, r, res := callTool(t, s, "getPet", map[string]any{"petId": "9"})
	if code != 200 || r.Error != nil || !res.IsError || !strings.Contains(res.Content[0].Text, "HTTP 404") || !strings.Contains(res.Content[0].Text, "no such pet") {
		t.Errorf("404 handling: %d %+v %+v", code, r.Error, res)
	}

	// 5xx: a backend failure, surfaced as 502 so the circuit breaker sees it.
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("down for maintenance"))
	}
	code, r, _ = callTool(t, s, "getPet", map[string]any{"petId": "9"})
	if code != http.StatusBadGateway || r.Error == nil || !strings.Contains(r.Error.Message, "HTTP 503") {
		t.Errorf("503 handling: %d %+v", code, r.Error)
	}

	// Unreachable API.
	dead := newServer(t, up, func(o *Options) { o.BaseURL = "http://127.0.0.1:1/v1" })
	code, r, _ = callTool(t, dead, "listPets", nil)
	if code != http.StatusBadGateway || r.Error == nil || !strings.Contains(r.Error.Message, "upstream API request failed") {
		t.Errorf("unreachable: %d %+v", code, r.Error)
	}
	if strings.Contains(r.Error.Message, "127.0.0.1:1/v1/pets") {
		t.Errorf("error leaks the request URL: %q", r.Error.Message)
	}
}

func TestTimeout(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}
	s := newServer(t, up, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	code, r, _ := callTool(t, s, "listPets", nil)
	if code != http.StatusBadGateway || r.Error == nil {
		t.Errorf("timeout: %d %+v", code, r.Error)
	}
}

func TestResponseTruncation(t *testing.T) {
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 100))) }
	s := newServer(t, up, func(o *Options) { o.MaxResponseBytes = 10 })
	_, _, res := callTool(t, s, "listPets", nil)
	text := res.Content[0].Text
	if !strings.HasPrefix(text, strings.Repeat("x", 10)+"\n\n[mcpx: response truncated to 10 bytes]") {
		t.Errorf("truncation: %q", text)
	}
}

func TestCrossHostRedirectNotFollowed(t *testing.T) {
	var leaked sync.Map
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Store("key", r.Header.Get("X-Api-Key"))
	}))
	defer evil.Close()
	up := newUpstream(t)
	up.respond = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pets" {
			http.Redirect(w, r, "/v1/pets/moved", http.StatusFound) // same host: followed
			return
		}
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound) // other host: not followed
	}
	s := newServer(t, up, nil)
	_, _, res := callTool(t, s, "listPets", nil)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "HTTP 302") {
		t.Errorf("cross-host redirect should come back as a 302 tool error: %+v", res)
	}
	if req, _ := up.last(t); req.URL.Path != "/v1/pets/moved" {
		t.Errorf("same-host redirect not followed: %s", req.URL.Path)
	}
	if _, ok := leaked.Load("key"); ok {
		t.Error("credentials were sent to a redirect target on another host")
	}
}

func TestNewValidatesBaseURL(t *testing.T) {
	spec := loadPetstore(t)
	for _, bad := range []string{"", "/relative", "ftp://x.example.com", "://"} {
		if _, err := New(spec, Options{BaseURL: bad}); err == nil {
			t.Errorf("base url %q should be rejected", bad)
		}
	}
}

func TestProbe(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)
	up.respond = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	if err := s.Probe(context.Background()); err != nil {
		t.Errorf("a 404 still proves the API is up: %v", err)
	}
	up.respond = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }
	if err := s.Probe(context.Background()); err == nil {
		t.Error("5xx should fail the probe")
	}
	dead := newServer(t, up, func(o *Options) { o.BaseURL = "http://127.0.0.1:1" })
	if err := dead.Probe(context.Background()); err == nil {
		t.Error("unreachable API should fail the probe")
	}
}

// TestHandlerTransportBehindReverseProxy mirrors how the gateway mounts the
// server: an httputil.ReverseProxy whose transport invokes it in-process.
func TestHandlerTransportBehindReverseProxy(t *testing.T) {
	up := newUpstream(t)
	s := newServer(t, up, nil)
	target, _ := url.Parse("http://openapi.internal")
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = HandlerTransport{Handler: s}

	code, r, res := callTool(t, rp, "getPet", map[string]any{"petId": "42"})
	if code != 200 || r.Error != nil || res.IsError {
		t.Fatalf("via reverse proxy: %d %+v %+v", code, r.Error, res)
	}
	if req, _ := up.last(t); req.URL.Path != "/v1/pets/42" {
		t.Errorf("upstream path = %s", req.URL.Path)
	}

	up.respond = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) }
	if code, _, _ := callTool(t, rp, "getPet", map[string]any{"petId": "42"}); code != http.StatusBadGateway {
		t.Errorf("upstream failure status not propagated through the proxy: %d", code)
	}
}
