package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rohitgs28/mcpx/internal/mcp"
	"github.com/rohitgs28/mcpx/internal/stdio"
)

// protocolVersion is the MCP revision the scanner announces.
const protocolVersion = "2025-06-18"

// maxPages bounds tools/list pagination so a misbehaving server cannot keep
// the scanner busy forever.
const maxPages = 100

// maxBody bounds a single HTTP response read from a server.
const maxBody = 16 << 20

// Inventory is what a server advertised to the scanner.
type Inventory struct {
	ServerName   string            `json:"serverName,omitempty"`
	Version      string            `json:"serverVersion,omitempty"`
	Instructions string            `json:"instructions,omitempty"`
	Tools        []json.RawMessage `json:"-"`
}

// rpcFunc sends one JSON-RPC request and returns its result.
type rpcFunc func(ctx context.Context, method string, params any) (json.RawMessage, error)

// notifyFunc sends one JSON-RPC notification.
type notifyFunc func(ctx context.Context, method string) error

// Fetch connects to s, performs the MCP handshake, and lists its tools
// (following pagination). For stdio servers this starts the server process,
// exactly as an MCP client would, and stops it afterwards.
func Fetch(ctx context.Context, s Server, timeout time.Duration, clientVersion string) (*Inventory, error) {
	switch s.Transport {
	case "stdio":
		c := stdio.NewClient(s.Name, stdio.Config{
			Command:        s.Command,
			Args:           s.Args,
			Env:            s.Env,
			Dir:            s.Dir,
			RequestTimeout: timeout,
		})
		defer func() { _ = c.Close() }()
		var seq int
		call := func(ctx context.Context, method string, params any) (json.RawMessage, error) {
			seq++
			body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": seq, "method": method, "params": params})
			if err != nil {
				return nil, err
			}
			resp, err := c.Call(ctx, body)
			if err != nil {
				return nil, err
			}
			return decodeResult(resp)
		}
		notify := func(_ context.Context, method string) error {
			return c.Notify([]byte(`{"jsonrpc":"2.0","method":"` + method + `"}`))
		}
		return handshakeAndList(ctx, call, notify, clientVersion)
	case "http":
		h := &httpSession{url: s.URL, headers: s.Headers, client: &http.Client{Timeout: timeout}}
		defer h.close()
		return handshakeAndList(ctx, h.call, h.notify, clientVersion)
	default:
		return nil, fmt.Errorf("unsupported transport %q", s.Transport)
	}
}

func handshakeAndList(ctx context.Context, call rpcFunc, notify notifyFunc, clientVersion string) (*Inventory, error) {
	initRes, err := call(ctx, mcp.MethodInitialize, map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpx-scan", "version": clientVersion},
	})
	if err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	var init struct {
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Instructions string `json:"instructions"`
	}
	_ = json.Unmarshal(initRes, &init)
	inv := &Inventory{ServerName: init.ServerInfo.Name, Version: init.ServerInfo.Version, Instructions: init.Instructions}

	if err := notify(ctx, mcp.MethodInitialized); err != nil {
		return nil, fmt.Errorf("initialized notification: %w", err)
	}

	cursor := ""
	for page := 0; page < maxPages; page++ {
		var params any = map[string]any{}
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		res, err := call(ctx, mcp.MethodToolsList, params)
		if err != nil {
			return inv, fmt.Errorf("tools/list: %w", err)
		}
		list, err := mcp.ParseToolsListResult(res)
		if err != nil {
			return inv, fmt.Errorf("tools/list: %w", err)
		}
		inv.Tools = append(inv.Tools, list.Tools...)
		if list.NextCursor == "" || list.NextCursor == cursor {
			break
		}
		cursor = list.NextCursor
	}
	return inv, nil
}

// decodeResult unwraps a JSON-RPC response into its result or error.
func decodeResult(data []byte) (json.RawMessage, error) {
	var resp mcp.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("server error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp.Result, nil
}

// httpSession speaks the MCP Streamable HTTP transport: JSON-RPC over POST,
// with replies as plain JSON or as a text/event-stream.
type httpSession struct {
	url       string
	headers   map[string]string
	client    *http.Client
	sessionID string
	version   string
	seq       int
}

func (h *httpSession) newRequest(ctx context.Context, method string, body []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if h.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", h.sessionID)
	}
	if h.version != "" {
		req.Header.Set("MCP-Protocol-Version", h.version)
	}
	return req, nil
}

func (h *httpSession) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	h.seq++
	id := h.seq
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	req, err := h.newRequest(ctx, http.MethodPost, body)
	if err != nil {
		return nil, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("HTTP %d: server requires authentication (add headers to its config)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		h.sessionID = sid
	}

	var msg []byte
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		msg, err = readSSEResponse(resp.Body, id)
	} else {
		msg, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
	}
	if err != nil {
		return nil, err
	}
	res, err := decodeResult(msg)
	if err != nil {
		return nil, err
	}
	if method == mcp.MethodInitialize {
		var init struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(res, &init)
		h.version = init.ProtocolVersion
	}
	return res, nil
}

func (h *httpSession) notify(ctx context.Context, method string) error {
	req, err := h.newRequest(ctx, http.MethodPost, []byte(`{"jsonrpc":"2.0","method":"`+method+`"}`))
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	resp.Body.Close()
	return nil
}

// close ends the server-side session, if one was created. Best effort.
func (h *httpSession) close() {
	if h.sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := h.newRequest(ctx, http.MethodDelete, nil)
	if err != nil {
		return
	}
	if resp, err := h.client.Do(req); err == nil {
		resp.Body.Close()
	}
}

// readSSEResponse reads server-sent events until it finds the JSON-RPC
// response whose id matches want. Notifications and server requests that
// arrive first on the stream are skipped.
func readSSEResponse(r io.Reader, want int) ([]byte, error) {
	sc := bufio.NewScanner(io.LimitReader(r, maxBody))
	sc.Buffer(make([]byte, 64*1024), maxBody)
	var data strings.Builder
	flush := func() []byte {
		defer data.Reset()
		if data.Len() == 0 {
			return nil
		}
		raw := []byte(data.String())
		var m struct {
			ID     json.RawMessage `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(raw, &m) != nil || (m.Result == nil && m.Error == nil) {
			return nil
		}
		if strings.Trim(string(m.ID), `"`) != fmt.Sprint(want) {
			return nil
		}
		return raw
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if msg := flush(); msg != nil {
				return msg, nil
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(v, " "))
		}
	}
	if msg := flush(); msg != nil {
		return msg, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("event stream ended without a response")
}
