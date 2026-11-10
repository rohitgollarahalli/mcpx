// Command mock-rest is a tiny, dependency-free REST API for trying out the
// openapi transport: an in-memory notes service described by
// examples/openapi/notes.openapi.yaml.
//
// It requires "Authorization: Bearer demo-token", so you can see the
// gateway inject the credential: MCP clients never hold it.
//
//	go run ./examples/mock-rest            # listens on :3002
//	go run ./examples/mock-rest -addr :3006
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type note struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type store struct {
	mu    sync.Mutex
	next  int
	notes map[string]*note
}

func main() {
	addr := flag.String("addr", ":3002", "listen address")
	flag.Parse()

	s := &store{notes: map[string]*note{}}
	s.add(note{Title: "Welcome", Body: "This note lives in the mock REST API.", Tags: []string{"demo"}})
	s.add(note{Title: "Groceries", Body: "eggs, coffee", Tags: []string{"todo"}})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /notes", s.list)
	mux.HandleFunc("POST /notes", s.create)
	mux.HandleFunc("GET /notes/{id}", s.get)
	mux.HandleFunc("PATCH /notes/{id}", s.update)
	mux.HandleFunc("DELETE /notes/{id}", s.remove)

	log.Printf("mock REST API listening on %s (token: demo-token)", *addr)
	log.Fatal(http.ListenAndServe(*addr, requireToken(mux)))
}

func requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer demo-token" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid bearer token"})
			return
		}
		log.Printf("%s %s", r.Method, r.URL.RequestURI())
		next.ServeHTTP(w, r)
	})
}

func (s *store) add(n note) *note {
	s.next++
	n.ID = strconv.Itoa(s.next)
	n.CreatedAt = time.Now().UTC()
	s.notes[n.ID] = &n
	return &n
}

func (s *store) list(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	tag := r.URL.Query().Get("tag")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	s.mu.Lock()
	out := []*note{}
	for _, n := range s.notes {
		if q != "" && !strings.Contains(strings.ToLower(n.Title+" "+n.Body), q) {
			continue
		}
		if tag != "" && !contains(n.Tags, tag) {
			continue
		}
		out = append(out, n)
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *store) create(w http.ResponseWriter, r *http.Request) {
	var in note
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Title == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "title is required"})
		return
	}
	s.mu.Lock()
	n := s.add(note{Title: in.Title, Body: in.Body, Tags: in.Tags})
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, n)
}

func (s *store) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	n, ok := s.notes[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "note not found"})
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *store) update(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Title *string  `json:"title"`
		Body  *string  `json:"body"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.notes[r.PathValue("id")]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "note not found"})
		return
	}
	if in.Title != nil {
		n.Title = *in.Title
	}
	if in.Body != nil {
		n.Body = *in.Body
	}
	if in.Tags != nil {
		n.Tags = in.Tags
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *store) remove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.notes[r.PathValue("id")]; !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "note not found"})
		return
	}
	delete(s.notes, r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
