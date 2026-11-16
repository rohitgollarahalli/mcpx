// Package stdio bridges HTTP JSON-RPC requests onto local MCP servers that
// speak the stdio transport (newline-delimited JSON-RPC over stdin/stdout).
//
// Each configured stdio server gets one shared child process, spawned lazily
// on first use and respawned on demand if it exits. Because many gateway
// clients funnel into a single child, the MCP initialize handshake is
// performed once and cached: later initialize requests are answered from the
// cache, and the handshake is replayed automatically when a crashed child is
// respawned so existing client sessions keep working.
//
// Request IDs are rewritten to gateway-internal sequence numbers on the way
// in and restored on the way out, so concurrent clients can never collide.
// Server-initiated messages (sampling requests, log notifications) have no
// addressable client on a shared HTTP gateway and are dropped with a log
// line.
package stdio

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rohitgollarahalli/mcpx/internal/config"
	"github.com/rohitgollarahalli/mcpx/internal/mcp"
)

const (
	defaultRequestTimeout = 30 * time.Second
	// respawnBackoff is the minimum gap between spawn attempts, so a child
	// that dies instantly cannot trigger a spawn storm.
	respawnBackoff = time.Second
	// maxLineBytes bounds a single JSON-RPC message read from the child.
	maxLineBytes = 16 << 20
	// initReplayTimeout bounds the re-handshake performed after a respawn.
	initReplayTimeout = 10 * time.Second
	// shutdownGrace is how long Close waits for a child to exit after its
	// stdin closes before killing it.
	shutdownGrace = 3 * time.Second
)

// Config describes how to spawn and talk to a stdio MCP server.
type Config struct {
	Command        string
	Args           []string
	Env            map[string]string // appended to the parent environment
	Dir            string
	RequestTimeout time.Duration // per-request reply deadline (default 30s)
}

// FromServerConfig maps a stdio server's YAML config onto a spawn Config.
func FromServerConfig(sc config.ServerConfig) Config {
	return Config{
		Command:        sc.Command,
		Args:           sc.Args,
		Env:            sc.Env,
		Dir:            sc.WorkDir,
		RequestTimeout: time.Duration(sc.RequestTimeout),
	}
}

// wireMsg is a JSON-RPC message in either direction. IDs stay raw so the
// caller's exact ID (string, number, fraction) survives the round trip.
type wireMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

type callResult struct {
	msg wireMsg
	err error
}

// pendingCall ties an in-flight request to the process generation that
// received it, so an exiting child fails only its own callers and never
// those already talking to its replacement.
type pendingCall struct {
	gen uint64
	ch  chan callResult
}

// Client manages one stdio MCP server child process.
type Client struct {
	name string
	cfg  Config

	seq atomic.Uint64 // internal JSON-RPC ID sequence

	// mu guards process lifecycle, stdin writes, and the handshake cache.
	mu        sync.Mutex
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	exited    chan struct{} // closed when the current process exits
	gen       uint64        // bumped on every spawn
	running   bool
	closed    bool
	lastSpawn time.Time
	lastErr   error

	// Cached MCP handshake: replayed to respawned children, served to
	// late-joining clients.
	initParams json.RawMessage
	initResult json.RawMessage
	initNote   []byte // compact notifications/initialized line

	pmu     sync.Mutex
	pending map[uint64]pendingCall
}

// NewClient creates a client for one stdio server. The child process is
// spawned lazily on first use.
func NewClient(name string, cfg Config) *Client {
	return &Client{name: name, cfg: cfg, pending: make(map[uint64]pendingCall)}
}

// Call forwards one JSON-RPC request (the body must carry an id) to the
// child and returns the raw JSON-RPC response with the caller's id restored.
func (c *Client) Call(ctx context.Context, body []byte) ([]byte, error) {
	var req wireMsg
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC request: %w", err)
	}

	// Serve repeat initialize requests from the cached handshake so any
	// number of gateway clients can share the single child process.
	if req.Method == mcp.MethodInitialize {
		c.mu.Lock()
		cached := c.initResult
		c.mu.Unlock()
		if cached != nil {
			return json.Marshal(wireMsg{JSONRPC: "2.0", ID: req.ID, Result: cached})
		}
	}

	id := c.seq.Add(1)
	origID := req.ID
	req.ID, _ = json.Marshal(id)

	ch, err := c.sendCall(req, id)
	if err != nil {
		return nil, err
	}
	defer func() {
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
	}()

	timeout := c.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		resp := res.msg
		resp.ID = origID
		if req.Method == mcp.MethodInitialize && resp.Error == nil && resp.Result != nil {
			c.mu.Lock()
			c.initParams = req.Params
			c.initResult = resp.Result
			c.mu.Unlock()
		}
		return json.Marshal(resp)
	case <-timer.C:
		return nil, fmt.Errorf("no reply from %q within %s", c.cfg.Command, timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Notify forwards a JSON-RPC notification (no id, no reply). Duplicate
// notifications/initialized are swallowed: the shared child has already
// completed its handshake with an earlier client.
func (c *Client) Notify(body []byte) error {
	var msg wireMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return fmt.Errorf("invalid JSON-RPC notification: %w", err)
	}
	// Re-marshaling compacts the message: client bodies may be
	// pretty-printed, and an embedded newline would break stdio framing.
	line, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if msg.Method == mcp.MethodInitialized {
		if c.initNote != nil {
			return nil
		}
		c.initNote = line
	}
	if err := c.ensureStartedLocked(); err != nil {
		return err
	}
	return c.writeLocked(line)
}

// sendCall registers the pending reply slot and writes the request, both
// under mu so the registration is tied to the process generation that
// actually received the bytes.
func (c *Client) sendCall(req wireMsg, id uint64) (chan callResult, error) {
	line, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureStartedLocked(); err != nil {
		return nil, err
	}
	ch := make(chan callResult, 1)
	c.pmu.Lock()
	c.pending[id] = pendingCall{gen: c.gen, ch: ch}
	c.pmu.Unlock()
	if err := c.writeLocked(line); err != nil {
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
		return nil, err
	}
	return ch, nil
}

func (c *Client) writeLocked(line []byte) error {
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		c.lastErr = err
		return fmt.Errorf("writing to %q: %w", c.cfg.Command, err)
	}
	return nil
}

func (c *Client) ensureStartedLocked() error {
	if c.closed {
		return errors.New("stdio client closed")
	}
	if c.running {
		return nil
	}
	if time.Since(c.lastSpawn) < respawnBackoff {
		if c.lastErr != nil {
			return fmt.Errorf("backend %q restarting: %w", c.name, c.lastErr)
		}
		return fmt.Errorf("backend %q restarting", c.name)
	}
	c.lastSpawn = time.Now()

	cmd := exec.Command(c.cfg.Command, c.cfg.Args...)
	cmd.Dir = c.cfg.Dir
	cmd.Env = os.Environ()
	for k, v := range c.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		c.lastErr = err
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		c.lastErr = err
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		c.lastErr = err
		return err
	}
	if err := cmd.Start(); err != nil {
		c.lastErr = err
		return fmt.Errorf("starting %q: %w", c.cfg.Command, err)
	}

	c.cmd = cmd
	c.stdin = stdin
	c.exited = make(chan struct{})
	c.gen++
	c.running = true
	c.lastErr = nil
	slog.Info("stdio backend started", "server", c.name, "command", c.cfg.Command, "pid", cmd.Process.Pid)

	go c.drainStderr(stderr)
	go c.readLoop(cmd, stdout, c.gen, c.exited)

	// A respawned child has lost the handshake the clients already
	// performed; replay it so their sessions keep working.
	if c.initParams != nil {
		if err := c.replayInitLocked(); err != nil {
			slog.Warn("stdio handshake replay failed", "server", c.name, "error", err)
		}
	}
	return nil
}

// replayInitLocked re-runs the cached initialize handshake against a fresh
// child. It holds mu for the duration on purpose: nothing else may talk to a
// half-initialized process. Replies arrive via the read loop, which only
// touches pmu, so waiting here cannot deadlock.
func (c *Client) replayInitLocked() error {
	id := c.seq.Add(1)
	rawID, _ := json.Marshal(id)
	line, err := json.Marshal(wireMsg{JSONRPC: "2.0", ID: rawID, Method: mcp.MethodInitialize, Params: c.initParams})
	if err != nil {
		return err
	}
	ch := make(chan callResult, 1)
	c.pmu.Lock()
	c.pending[id] = pendingCall{gen: c.gen, ch: ch}
	c.pmu.Unlock()
	defer func() {
		c.pmu.Lock()
		delete(c.pending, id)
		c.pmu.Unlock()
	}()
	if err := c.writeLocked(line); err != nil {
		return err
	}
	timer := time.NewTimer(initReplayTimeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		if res.err != nil {
			return res.err
		}
		if res.msg.Error != nil {
			return fmt.Errorf("initialize rejected: %s", res.msg.Error)
		}
		c.initResult = res.msg.Result
	case <-timer.C:
		return errors.New("initialize replay timed out")
	}
	if c.initNote != nil {
		return c.writeLocked(c.initNote)
	}
	return nil
}

// readLoop delivers child responses to their waiting callers until the
// child's stdout closes, then reaps the process and fails its stragglers.
func (c *Client) readLoop(cmd *exec.Cmd, stdout io.Reader, gen uint64, exited chan struct{}) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var msg wireMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			slog.Warn("stdio backend sent invalid JSON", "server", c.name, "error", err)
			continue
		}
		if msg.Method != "" {
			// Server-initiated requests and notifications (sampling,
			// progress, logging) have no addressable client here.
			slog.Debug("dropping server-initiated stdio message", "server", c.name, "method", msg.Method)
			continue
		}
		var id uint64
		if err := json.Unmarshal(msg.ID, &id); err != nil {
			slog.Warn("stdio backend reply has unknown id", "server", c.name, "id", string(msg.ID))
			continue
		}
		c.pmu.Lock()
		pc, ok := c.pending[id]
		if ok {
			delete(c.pending, id)
		}
		c.pmu.Unlock()
		if ok {
			pc.ch <- callResult{msg: msg}
		}
	}
	err := cmd.Wait()

	c.mu.Lock()
	if c.cmd == cmd {
		c.running = false
		c.stdin = nil
		if err != nil {
			c.lastErr = err
		} else {
			c.lastErr = errors.New("process exited")
		}
	}
	closed := c.closed
	c.mu.Unlock()
	close(exited)

	if !closed {
		slog.Warn("stdio backend exited", "server", c.name, "command", c.cfg.Command, "error", err)
	}
	// Fail callers still waiting on this generation; newer generations'
	// callers are untouched.
	c.pmu.Lock()
	for id, pc := range c.pending {
		if pc.gen == gen {
			delete(c.pending, id)
			pc.ch <- callResult{err: errors.New("backend process exited before replying")}
		}
	}
	c.pmu.Unlock()
}

func (c *Client) drainStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		slog.Info("stdio backend stderr", "server", c.name, "line", sc.Text())
	}
}

// Probe reports backend health for /health: a running child is healthy and
// so is an idle one that was never needed; only a child that failed to spawn
// or died reports its error (until the next request respawns it).
func (c *Client) Probe(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running || c.lastErr == nil {
		return nil
	}
	return c.lastErr
}

// Close shuts the child down: closing stdin asks a well-behaved MCP server
// to exit; one that lingers past the grace period is killed.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	cmd, stdin, exited, running := c.cmd, c.stdin, c.exited, c.running
	c.mu.Unlock()
	if !running || cmd == nil {
		return nil
	}
	if stdin != nil {
		_ = stdin.Close()
	}
	select {
	case <-exited:
	case <-time.After(shutdownGrace):
		slog.Warn("stdio backend ignored stdin close, killing", "server", c.name, "pid", cmd.Process.Pid)
		if err := cmd.Process.Kill(); err != nil {
			return err
		}
		<-exited
	}
	return nil
}

// Manager owns the stdio clients for all configured servers. It is created
// once at startup and survives config hot-reloads, so unchanged children
// keep running across a SIGHUP.
type Manager struct {
	mu      sync.Mutex
	clients map[string]*Client
}

func NewManager() *Manager {
	return &Manager{clients: make(map[string]*Client)}
}

// Ensure returns the client for name, reusing the running one when the spawn
// config is unchanged and replacing it (retiring the old child) when it is.
func (m *Manager) Ensure(name string, cfg Config) *Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.clients[name]; ok {
		if reflect.DeepEqual(c.cfg, cfg) {
			return c
		}
		go func(old *Client) { _ = old.Close() }(c)
	}
	c := NewClient(name, cfg)
	m.clients[name] = c
	return c
}

// Prune closes clients whose servers vanished from the config.
func (m *Manager) Prune(active map[string]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, c := range m.clients {
		if !active[name] {
			go func(old *Client) { _ = old.Close() }(c)
			delete(m.clients, name)
		}
	}
}

// CloseAll shuts down every child process, concurrently, and waits.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	clients := make([]*Client, 0, len(m.clients))
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	m.clients = make(map[string]*Client)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, c := range clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			_ = c.Close()
		}(c)
	}
	wg.Wait()
}
