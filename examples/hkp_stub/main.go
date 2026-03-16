// Package main implements a minimal HKP (HTTP Keyserver Protocol) stub server
// for Dead PGP local/dev testing.
//
// Endpoints:
//   GET  /pks/lookup  — look up or index PGP keys
//   POST /pks/add     — submit a PGP public key
//
// Keys are stored in memory only and are lost on restart.
// This server is intentionally unauthenticated and is not suitable for
// production use.
//
// Usage:
//
//	go run .
//	PORT=11371 go run .
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// keyEntry holds the in-memory representation of a stored PGP public key.
type keyEntry struct {
	armored   string
	uids      []string
	keyID     string // random stub ID; a real implementation would derive this from the key fingerprint
	createdAt time.Time
}

// keyStore is a thread-safe in-memory key store.
type keyStore struct {
	mu   sync.RWMutex
	keys []keyEntry
}

var store = &keyStore{}

// add appends a new key to the store.
func (s *keyStore) add(entry keyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = append(s.keys, entry)
}

// search returns all keys whose UIDs or keyID contain the query string.
// Only metadata fields are searched — the raw armored block is never scanned
// to avoid false positives from base64-encoded key material.
func (s *keyStore) search(query string) []keyEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query = strings.ToLower(strings.TrimPrefix(query, "0x"))
	var results []keyEntry
	for _, k := range s.keys {
		if strings.Contains(strings.ToLower(k.keyID), query) {
			results = append(results, k)
			continue
		}
		for _, uid := range k.uids {
			if strings.Contains(strings.ToLower(uid), query) {
				results = append(results, k)
				break
			}
		}
	}
	return results
}

// parseUIDs extracts UID strings from an ASCII-armored key block.
// This is a best-effort heuristic for stub purposes only.
// A production implementation should use a proper PGP library to parse
// the binary packet structure and extract UID packets reliably.
func parseUIDs(armored string) []string {
	var uids []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(armored, "\n") {
		line = strings.TrimSpace(line)
		// Skip PGP armor headers, blank lines, and base64 lines.
		if line == "" || strings.HasPrefix(line, "-----") ||
			strings.HasPrefix(line, "Version:") || strings.HasPrefix(line, "Comment:") ||
			strings.HasPrefix(line, "Hash:") || strings.HasPrefix(line, "=") {
			continue
		}
		// Heuristic: lines that look like "Name <email@domain>" are likely UIDs
		// passed in the armored text for stub testing purposes.
		if strings.Contains(line, "@") && strings.Contains(line, "<") && strings.Contains(line, ">") {
			if !seen[line] {
				uids = append(uids, line)
				seen[line] = true
			}
		}
	}
	if len(uids) == 0 {
		uids = []string{"(unknown)"}
	}
	return uids
}

// randomKeyID returns a random 16-character uppercase hex string used as a
// stub key ID. A real implementation derives this from the PGP key fingerprint.
func randomKeyID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use nanosecond timestamp if crypto/rand fails.
		return fmt.Sprintf("%016X", uint64(time.Now().UnixNano()))
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// handleLookup serves GET /pks/lookup.
func handleLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	op := q.Get("op")
	search := q.Get("search")
	options := q.Get("options")
	format := q.Get("format")

	if search == "" {
		http.Error(w, "Missing required parameter: search", http.StatusBadRequest)
		return
	}
	if op == "" {
		http.Error(w, "Missing required parameter: op", http.StatusBadRequest)
		return
	}

	mr := options == "mr" || format == "mr"

	switch op {
	case "get":
		results := store.search(search)
		if len(results) == 0 {
			http.Error(w, "No keys found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, k := range results {
			fmt.Fprintln(w, k.armored)
		}

	case "index", "vindex":
		results := store.search(search)
		if len(results) == 0 {
			http.Error(w, "No keys found", http.StatusNotFound)
			return
		}
		if mr {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "info:1:%d\n", len(results))
			for _, k := range results {
				ts := k.createdAt.Unix()
				fmt.Fprintf(w, "pub:%s:1:0:%d::\n", k.keyID, ts)
				for _, uid := range k.uids {
					fmt.Fprintf(w, "uid:%s:%d::\n", uid, ts)
				}
			}
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, "<html><body><pre>")
			for _, k := range results {
				fmt.Fprintf(w, "pub   %s  %s\n", k.keyID, k.createdAt.Format("2006-01-02"))
				for _, uid := range k.uids {
					fmt.Fprintf(w, "uid   %s\n", uid)
				}
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, "</pre></body></html>")
		}

	default:
		http.Error(w, "Operation not supported", http.StatusNotImplemented)
	}
}

// handleAdd serves POST /pks/add.
func handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	keytext := r.FormValue("keytext")
	if keytext == "" {
		http.Error(w, "Missing keytext parameter", http.StatusBadRequest)
		return
	}

	if !strings.Contains(keytext, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		http.Error(w, "keytext does not appear to be an ASCII-armored PGP public key", http.StatusBadRequest)
		return
	}

	entry := keyEntry{
		armored:   strings.TrimSpace(keytext),
		uids:      parseUIDs(keytext),
		keyID:     randomKeyID(),
		createdAt: time.Now().UTC(),
	}
	store.add(entry)

	log.Printf("Key imported: keyID=%s uids=%v", entry.keyID, entry.uids)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "Key imported successfully")
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port

	mux := http.NewServeMux()
	mux.HandleFunc("/pks/lookup", handleLookup)
	mux.HandleFunc("/pks/add", handleAdd)

	// Health check endpoint (non-HKP convenience endpoint)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Dead PGP HKP stub server — listening on %s\n", addr)
		fmt.Fprintln(w, "Endpoints: GET /pks/lookup, POST /pks/add")
	})

	log.Printf("Dead PGP HKP stub server starting on http://localhost%s", addr)
	log.Printf("Endpoints: GET /pks/lookup  POST /pks/add")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
