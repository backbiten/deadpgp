// Package main implements a minimal HKP (HTTP Keyserver Protocol) stub server
// for local Dead PGP development and testing.
//
// Usage:
//
//	go run . [-addr <host:port>]
//
// Default listen address: :11371 (the IANA-registered HKP port).
//
// Endpoints:
//
//	GET  /pks/lookup               — op=get|index|vindex, search=<term>
//	POST /pks/add                  — keytext=<armored key> (form-encoded)
//	GET  /pks/lookup/{fingerprint} — convenience alias for op=get
//
// Keys are stored in memory only; they are lost on restart.
// This server is intentionally unauthenticated — do NOT expose it publicly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// keyEntry holds a stored OpenPGP public key together with metadata extracted
// from the armored block header comment (if present).
type keyEntry struct {
	Armored     string
	Fingerprint string
	UIDs        []string
	CreatedAt   time.Time
}

// keyStore is a thread-safe in-memory key store.
type keyStore struct {
	mu   sync.RWMutex
	keys map[string]*keyEntry // fingerprint (upper-case) → entry
}

func newKeyStore() *keyStore {
	return &keyStore{keys: make(map[string]*keyEntry)}
}

// add stores a key. Returns (entry, false) on success or (existing, true) if
// an entry with the same fingerprint already exists.
func (s *keyStore) add(entry *keyEntry) (*keyEntry, bool) {
	fp := strings.ToUpper(entry.Fingerprint)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.keys[fp]; ok {
		return existing, true
	}
	s.keys[fp] = entry
	return entry, false
}

// findByFingerprint looks up a key by its fingerprint (case-insensitive).
func (s *keyStore) findByFingerprint(fp string) (*keyEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.keys[strings.ToUpper(fp)]
	return entry, ok
}

// search returns all entries whose fingerprint or UIDs contain term (case-insensitive).
func (s *keyStore) search(term string) []*keyEntry {
	lower := strings.ToLower(term)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var results []*keyEntry
	for _, e := range s.keys {
		if strings.Contains(strings.ToLower(e.Fingerprint), lower) {
			results = append(results, e)
			continue
		}
		for _, uid := range e.UIDs {
			if strings.Contains(strings.ToLower(uid), lower) {
				results = append(results, e)
				break
			}
		}
	}
	return results
}

// parseArmored extracts a minimal set of metadata from an ASCII-armored key
// block. It does not perform full OpenPGP parsing — it only looks for the
// delimiters and any "Comment:" header lines that tools like gpg emit.
func parseArmored(armored string) (*keyEntry, error) {
	const begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	const end = "-----END PGP PUBLIC KEY BLOCK-----"

	if !strings.Contains(armored, begin) || !strings.Contains(armored, end) {
		return nil, fmt.Errorf("input does not appear to be an ASCII-armored OpenPGP public key")
	}

	entry := &keyEntry{
		Armored:   armored,
		CreatedAt: time.Now().UTC(),
	}

	// Try to extract UID / fingerprint hints from armored header comments.
	// gpg --armor --export emits lines like:
	//   Comment: <name> (<email>)
	//   Comment: <fingerprint>
	for _, line := range strings.Split(armored, "\n") {
		line = strings.TrimSpace(line)
		if after, ok := strings.CutPrefix(line, "Comment:"); ok {
			val := strings.TrimSpace(after)
			// Heuristic: 40 hex chars → fingerprint; otherwise treat as UID.
			if isHex40(val) {
				entry.Fingerprint = strings.ToUpper(val)
			} else if val != "" {
				entry.UIDs = append(entry.UIDs, val)
			}
		}
	}

	// Assign a synthetic fingerprint if none was found in the headers so that
	// the entry can still be stored and retrieved.
	if entry.Fingerprint == "" {
		entry.Fingerprint = syntheticFingerprint(armored)
	}

	return entry, nil
}

// isHex40 reports whether s is exactly 40 hexadecimal characters.
func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// syntheticFingerprint derives a placeholder fingerprint from the first 40
// printable characters of the base64 body of the armored block.
func syntheticFingerprint(armored string) string {
	const hexChars = "0123456789ABCDEF"
	var out []byte
	for _, c := range armored {
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			out = append(out, byte(c))
			if len(out) == 40 {
				break
			}
		}
	}
	for len(out) < 40 {
		out = append(out, hexChars[len(out)%16])
	}
	return string(out)
}

// writeJSON writes a JSON error body with the given HTTP status code.
func writeJSON(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body, _ := json.Marshal(map[string]interface{}{"error": msg, "code": status})
	_, _ = w.Write(body)
}

// handleLookup implements GET /pks/lookup.
func handleLookup(store *keyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		op := r.URL.Query().Get("op")
		search := r.URL.Query().Get("search")
		options := r.URL.Query().Get("options")
		mr := strings.Contains(options, "mr")

		if op == "" {
			writeJSON(w, http.StatusBadRequest, "missing required query parameter: op")
			return
		}
		if search == "" {
			writeJSON(w, http.StatusBadRequest, "missing required query parameter: search")
			return
		}

		switch op {
		case "get":
			// Strip leading "0x" fingerprint prefix used by HKP clients.
			fp := strings.TrimPrefix(search, "0x")
			fp = strings.TrimPrefix(fp, "0X")

			var entries []*keyEntry
			if entry, ok := store.findByFingerprint(fp); ok {
				entries = []*keyEntry{entry}
			} else {
				entries = store.search(fp)
			}
			if len(entries) == 0 {
				http.Error(w, "No keys found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/pgp-keys")
			for _, e := range entries {
				_, _ = fmt.Fprintln(w, strings.TrimSpace(e.Armored))
			}

		case "index", "vindex":
			entries := store.search(strings.TrimPrefix(strings.TrimPrefix(search, "0x"), "0X"))
			if len(entries) == 0 {
				http.Error(w, "No keys found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			if mr || op == "vindex" {
				// Machine-readable format (draft-shaw-openpgp-hkp-00 §5)
				_, _ = fmt.Fprintf(w, "info:1:%d\n", len(entries))
				for _, e := range entries {
					ts := e.CreatedAt.Unix()
					_, _ = fmt.Fprintf(w, "pub:%s:1:4096:%d::\n", e.Fingerprint, ts)
					for _, uid := range e.UIDs {
						_, _ = fmt.Fprintf(w, "uid:%s:%d::\n", uid, ts)
					}
				}
			} else {
				// Human-readable format
				for _, e := range entries {
					shortID := e.Fingerprint
				if len(shortID) > 8 {
					shortID = shortID[len(shortID)-8:]
				}
				_, _ = fmt.Fprintf(w, "pub  4096R/%s  %s\n",
					shortID,
					e.CreatedAt.Format("2006-01-02"),
				)
					for _, uid := range e.UIDs {
						_, _ = fmt.Fprintf(w, "uid  %s\n", uid)
					}
					_, _ = fmt.Fprintln(w)
				}
			}

		default:
			writeJSON(w, http.StatusNotImplemented, fmt.Sprintf("op %q is not supported in dead mode", op))
		}
	}
}

// handleAdd implements POST /pks/add.
func handleAdd(store *keyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, "could not parse form body: "+err.Error())
			return
		}
		keytext := r.FormValue("keytext")
		if keytext == "" {
			writeJSON(w, http.StatusBadRequest, "missing required form field: keytext")
			return
		}

		entry, err := parseArmored(keytext)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, "invalid key: "+err.Error())
			return
		}

		if _, exists := store.add(entry); exists {
			writeJSON(w, http.StatusConflict, "key already exists: "+entry.Fingerprint)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "Key imported successfully (fingerprint: %s)\n", entry.Fingerprint)
		log.Printf("ADD  fingerprint=%s uids=%v", entry.Fingerprint, entry.UIDs)
	}
}

// handleLookupByFingerprint implements GET /pks/lookup/{fingerprint} as a
// convenience alias for op=get.
func handleLookupByFingerprint(store *keyStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract the fingerprint from the path: /pks/lookup/<fp>
		fp := strings.TrimPrefix(r.URL.Path, "/pks/lookup/")
		if fp == "" || fp == r.URL.Path {
			writeJSON(w, http.StatusBadRequest, "fingerprint missing from path")
			return
		}
		entry, ok := store.findByFingerprint(fp)
		if !ok {
			writeJSON(w, http.StatusNotFound, "key not found: "+fp)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		_, _ = fmt.Fprintln(w, strings.TrimSpace(entry.Armored))
	}
}

func main() {
	addr := flag.String("addr", ":11371", "TCP address to listen on (default HKP port)")
	flag.Parse()

	store := newKeyStore()
	mux := http.NewServeMux()

	// HKP routes
	mux.HandleFunc("/pks/lookup", func(w http.ResponseWriter, r *http.Request) {
		// Dispatch: anything after "/pks/lookup/" → fingerprint convenience route.
		suffix := strings.TrimPrefix(r.URL.Path, "/pks/lookup")
		if suffix != "" && suffix != "/" {
			handleLookupByFingerprint(store)(w, r)
			return
		}
		handleLookup(store)(w, r)
	})
	mux.HandleFunc("/pks/add", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, "only POST is allowed on /pks/add")
			return
		}
		handleAdd(store)(w, r)
	})

	// Root health check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"status":"ok","mode":"dead","server":"deadpgp-hkp-stub"}`)
	})

	log.Printf("Dead PGP HKP stub listening on %s (dead mode — unauthenticated)", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
