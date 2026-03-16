// Package main provides a minimal HKP-compatible stub keyserver for local
// testing of Dead PGP mode.
//
// It implements the two standard HKP endpoints:
//
//	GET  /pks/lookup  — search for or retrieve an OpenPGP public key
//	POST /pks/add     — upload / import an OpenPGP public key
//
// Keys are stored in memory only. This server is intentionally unauthenticated
// and is NOT suitable for production use.
//
// Usage:
//
//	go run main.go               # listen on :11371 (default HKP port)
//	go run main.go -addr :8080   # custom address
package main

import (
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// keyStore is an in-memory store mapping lowercase fingerprint/key-ID to
// the raw ASCII-armored public key block submitted by the client.
type keyStore struct {
	mu   sync.RWMutex
	keys map[string]string // fingerprint → armored key
	uids map[string]string // fingerprint → first UID line (for display)
}

func newKeyStore() *keyStore {
	return &keyStore{
		keys: make(map[string]string),
		uids: make(map[string]string),
	}
}

// add inserts or replaces the key identified by fp.
func (ks *keyStore) add(fp, armored, uid string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	key := strings.ToUpper(fp)
	ks.keys[key] = armored
	ks.uids[key] = uid
}

// get returns the armored key for fp, or ("", false) if not found.
func (ks *keyStore) get(fp string) (string, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	v, ok := ks.keys[strings.ToUpper(fp)]
	return v, ok
}

// search returns all (fingerprint, uid, armored) triples whose fingerprint or
// UID contains the query string (case-insensitive).
func (ks *keyStore) search(query string) []keyRecord {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	q := strings.ToUpper(strings.TrimPrefix(query, "0x"))
	qUID := strings.ToUpper(query)
	var results []keyRecord
	for fp, armored := range ks.keys {
		uid := ks.uids[fp]
		if strings.Contains(fp, q) || strings.Contains(strings.ToUpper(uid), qUID) {
			results = append(results, keyRecord{FP: fp, UID: uid, Armored: armored})
		}
	}
	return results
}

type keyRecord struct {
	FP      string
	UID     string
	Armored string
}

// server holds the keystore and HTTP mux.
type server struct {
	store *keyStore
}

func newServer() *server {
	return &server{store: newKeyStore()}
}

// handleLookup serves GET /pks/lookup.
func (s *server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	op := q.Get("op")
	search := q.Get("search")
	options := q.Get("options")
	mr := strings.Contains(options, "mr")

	if op == "" || search == "" {
		http.Error(w, `{"error":"missing required parameters: op and search","code":400}`, http.StatusBadRequest)
		return
	}

	switch op {
	case "get":
		s.opGet(w, search)
	case "index":
		s.opIndex(w, search, mr)
	case "search":
		s.opSearch(w, search, mr)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprintf(w, `{"error":"op %q not implemented","code":501}`, op)
	}
}

// opGet returns the armored key block for the requested search term.
func (s *server) opGet(w http.ResponseWriter, search string) {
	fp := strings.ToUpper(strings.TrimPrefix(search, "0x"))
	armored, ok := s.store.get(fp)
	if !ok {
		// Fall back to substring search
		records := s.store.search(search)
		if len(records) == 0 {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body><h1>404 Not Found</h1><p>No keys found matching: "+html.EscapeString(search)+"</p></body></html>")
			return
		}
		armored = records[0].Armored
	}
	w.Header().Set("Content-Type", "application/pgp-keys")
	fmt.Fprint(w, armored)
}

// opIndex returns a machine-readable or HTML key index.
func (s *server) opIndex(w http.ResponseWriter, search string, mr bool) {
	records := s.store.search(search)
	if len(records) == 0 {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<html><body><h1>404 Not Found</h1><p>No keys found.</p></body></html>")
		return
	}
	if mr {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "info:1:%d\n", len(records))
		for _, rec := range records {
			// pub:<fingerprint>:<algo>:<keylen>:<created>:<expires>:<flags>
			fmt.Fprintf(w, "pub:%s:0:0:0::\n", rec.FP)
			// uid:<percent-encoded-uid>:<created>:<expires>:<flags>
			fmt.Fprintf(w, "uid:%s:0::\n", url.QueryEscape(rec.UID))
		}
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Key Index</h1><ul>")
	for _, rec := range records {
		fmt.Fprintf(w, "<li><tt>%s</tt> — %s</li>", html.EscapeString(rec.FP), html.EscapeString(rec.UID))
	}
	fmt.Fprint(w, "</ul></body></html>")
}

// opSearch returns an HTML search results page.
func (s *server) opSearch(w http.ResponseWriter, search string, mr bool) {
	// For the stub, search is equivalent to index.
	s.opIndex(w, search, mr)
}

// handleAdd serves POST /pks/add.
func (s *server) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"could not parse form body","code":400}`)
		return
	}
	keytext := r.FormValue("keytext")
	if keytext == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"missing required field: keytext","code":400}`)
		return
	}
	if !strings.Contains(keytext, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"keytext does not appear to be an armored OpenPGP public key","code":400}`)
		return
	}

	// Extract a pseudo-fingerprint from the armored block (first 40 non-whitespace
	// chars of the base64 payload) for demo purposes. A real implementation would
	// parse the OpenPGP packet and compute SHA-1 of the public key material.
	fp, uid := extractStubFP(keytext)

	s.store.add(fp, keytext, uid)
	log.Printf("imported key fp=%s uid=%q", fp, uid)

	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<html><body><h1>Key imported successfully.</h1><p>Fingerprint: <tt>%s</tt></p></body></html>", html.EscapeString(fp))
}

// extractStubFP returns a stub fingerprint and UID extracted from the armored
// key text. This is not a real OpenPGP fingerprint — it is used only for
// in-memory keying in the stub server.
func extractStubFP(armored string) (fp, uid string) {
	lines := strings.Split(armored, "\n")
	var b64 strings.Builder
	inBody := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") || strings.HasPrefix(line, "Version:") || strings.HasPrefix(line, "Comment:") || strings.HasPrefix(line, "Hash:") {
			if strings.Contains(line, "BEGIN PGP") {
				inBody = true
			}
			continue
		}
		if strings.HasPrefix(line, "=") {
			break // checksum line
		}
		if inBody {
			b64.WriteString(line)
		}
		if b64.Len() >= 40 {
			break
		}
	}
	raw := b64.String()
	if len(raw) > 40 {
		raw = raw[:40]
	}
	// Pad to 40 chars if shorter
	for len(raw) < 40 {
		raw += "0"
	}
	fp = strings.ToUpper(raw)

	// Try to extract a UID comment if present
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Comment: ") {
			uid = strings.TrimPrefix(line, "Comment: ")
			return
		}
	}
	uid = "(unknown UID — stub server)"
	return
}

func main() {
	addr := flag.String("addr", ":11371", "address to listen on (default HKP port)")
	flag.Parse()

	s := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/pks/lookup", s.handleLookup)
	mux.HandleFunc("/pks/add", s.handleAdd)

	log.Printf("Dead PGP HKP stub server listening on %s", *addr)
	log.Printf("  GET  http://localhost%s/pks/lookup?op=get&search=0x<KEYID>", *addr)
	log.Printf("  POST http://localhost%s/pks/add  (keytext=<armored>)", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
