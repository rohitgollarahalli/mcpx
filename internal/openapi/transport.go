package openapi

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
)

// HandlerTransport serves HTTP requests in-process by invoking an
// http.Handler, so a reverse proxy can front a backend that lives inside the
// gateway (no listener, no network hop). The handler must write a bounded,
// non-streaming response; it is buffered in full.
type HandlerTransport struct {
	Handler http.Handler
}

// RoundTrip implements http.RoundTripper.
func (t HandlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &recorder{header: http.Header{}, status: http.StatusOK}
	// The handler sees a server-side request: drop the client-only fields a
	// reverse proxy fills in and give it a readable body.
	in := req.Clone(req.Context())
	in.RequestURI = in.URL.RequestURI()
	if in.Body == nil {
		in.Body = http.NoBody
	}
	t.Handler.ServeHTTP(rec, in)
	if req.Body != nil {
		req.Body.Close()
	}
	body := rec.buf.Bytes()
	resp := &http.Response{
		Status:        strconv.Itoa(rec.status) + " " + http.StatusText(rec.status),
		StatusCode:    rec.status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        rec.header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
	return resp, nil
}

// recorder is a minimal buffering http.ResponseWriter.
type recorder struct {
	header      http.Header
	status      int
	wroteHeader bool
	buf         bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
}

func (r *recorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.buf.Write(p)
}
