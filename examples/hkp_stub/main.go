// Package main implements a minimal HKP (HTTP Keyserver Protocol) stub server
// for local Dead PGP development and testing.
//
// Endpoints:
//
//	GET  /pks/lookup  — search for / retrieve a key
//	POST /pks/add     — submit a new key
//
// The server stores all keys in memory; data is lost when the process exits.
// This is intentional: the stub is designed for dead (local/dev) mode only.
//
// Usage:
//
//	go run .
//	# Server listens on http://localhost:11371 by default.
//	# Override with -addr flag: go run . -addr :8080
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// keyStore is a simple in-memory store of ASCII-armored OpenPGP public keys.
// Keys are indexed by a normalised search token (lower-cased email / key ID).
type keyStore struct {
	mu   sync.RWMutex
	keys []storedKey
}

type storedKey struct {
	armor      string    // ASCII-armored key block
	uid        string    // primary User ID string
	keyID      string    // 16-char hex key ID (synthetic, derived from submission order)
	created    time.Time // import timestamp (stand-in for actual key creation time)
}

// add inserts a new key into the store.
func (s *keyStore) add(armor string) error {
	armor = strings.TrimSpace(armor)
	if armor == "" {
		return fmt.Errorf("empty key material")
	}
	if !strings.Contains(armor, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		return fmt.Errorf("does not look like an ASCII-armored OpenPGP public key")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicates (naïve check: identical armored text).
	for _, k := range s.keys {
		if k.armor == armor {
			return fmt.Errorf("key already present")
		}
	}

	// Extract a pseudo User ID from the armored block comment line, if present.
	uid := extractUID(armor)
	keyID := syntheticKeyID(len(s.keys) + 1)

	s.keys = append(s.keys, storedKey{
		armor:   armor,
		uid:     uid,
		keyID:   keyID,
		created: time.Now().UTC(),
	})
	return nil
}

// search returns all keys whose UID or keyID contains the (lower-cased) term.
func (s *keyStore) search(term string) []storedKey {
	term = strings.ToLower(strings.TrimPrefix(term, "0x"))
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []storedKey
	for _, k := range s.keys {
		if strings.Contains(strings.ToLower(k.uid), term) ||
			strings.Contains(strings.ToLower(k.keyID), term) {
			results = append(results, k)
		}
	}
	return results
}

// ---- helpers ----------------------------------------------------------------

// extractUID tries to pull a human-readable UID from an armored block.
// Real implementations parse the binary packet; this stub uses a heuristic.
func extractUID(armor string) string {
	for _, line := range strings.Split(armor, "\n") {
		line = strings.TrimSpace(line)
		// Comment: headers sometimes carry the uid in GnuPG exports.
		if strings.HasPrefix(line, "Comment:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Comment:"))
		}
	}
	return "Unknown UID"
}

// syntheticKeyID returns a deterministic 16-hex-char fake key ID for display.
func syntheticKeyID(n int) string {
	return fmt.Sprintf("DEADPGP%09d", n)
}

// ---- HTTP handlers ----------------------------------------------------------

var store = &keyStore{}

// handleLookup serves GET /pks/lookup
func handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	op := q.Get("op")
	search := q.Get("search")
	options := q.Get("options")
	mr := strings.Contains(options, "mr")

	if search == "" {
		http.Error(w, "Error: no search string provided", http.StatusBadRequest)
		return
	}

	switch op {
	case "get":
		results := store.search(search)
		if len(results) == 0 {
			http.Error(w, "Error: no keys found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/pgp-keys")
		for _, k := range results {
			fmt.Fprintln(w, k.armor)
		}

	case "index", "vindex":
		results := store.search(search)
		if len(results) == 0 {
			http.Error(w, "Error: no keys found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if mr {
			// Machine-readable HKP index format.
			fmt.Fprintf(w, "info:1:%d\n", len(results))
			for _, k := range results {
				ts := k.created.Unix()
				// algo=1 (RSA), keyLen=4096 — synthetic placeholders for the stub.
			fmt.Fprintf(w, "pub:%s:1:4096:%d::\n", k.keyID, ts)
				uid := url.QueryEscape(k.uid)
				fmt.Fprintf(w, "uid:%s:%d::\n", uid, ts)
			}
		} else {
			// Human-readable index.
			fmt.Fprintf(w, "Dead PGP HKP stub — %d key(s) found for %q\n\n", len(results), search)
			for i, k := range results {
				fmt.Fprintf(w, "%d. Key ID : %s\n   UID    : %s\n   Added  : %s\n\n",
					i+1, k.keyID, k.uid, k.created.Format(time.RFC3339))
			}
		}

	default:
		if op == "" {
			http.Error(w, "Error: op parameter required", http.StatusBadRequest)
		} else {
			http.Error(w, "Error: operation not implemented", http.StatusNotImplemented)
		}
	}
}

// handleAdd serves POST /pks/add
func handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error: could not parse form body", http.StatusBadRequest)
		return
	}

	keytext := r.FormValue("keytext")
	if keytext == "" {
		http.Error(w, "Error: no keytext provided", http.StatusBadRequest)
		return
	}

	if err := store.add(keytext); err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already present"):
			http.Error(w, "Error: "+msg, http.StatusConflict)
		case strings.Contains(msg, "does not look like"):
			http.Error(w, "Error: invalid key material — "+msg, http.StatusUnprocessableEntity)
		default:
			http.Error(w, "Error: "+msg, http.StatusBadRequest)
		}
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Key imported successfully.")
}

// handleHashquery serves POST /pks/hashquery (stub — always returns 501)
func handleHashquery(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Error: hashquery not implemented in dead mode", http.StatusNotImplemented)
}

// ---- main -------------------------------------------------------------------

func main() {
	addr := flag.String("addr", ":11371", "listen address (default :11371, the standard HKP port)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/pks/lookup", handleLookup)
	mux.HandleFunc("/pks/add", handleAdd)
	mux.HandleFunc("/pks/hashquery", handleHashquery)

	// Catch-all: redirect root to a brief usage message.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "Dead PGP HKP stub server (dead mode — local only)")
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "Endpoints:")
		fmt.Fprintln(w, "  GET  /pks/lookup?op=get&search=<term>")
		fmt.Fprintln(w, "  GET  /pks/lookup?op=index&search=<term>")
		fmt.Fprintln(w, "  POST /pks/add  (form field: keytext=<armored key>)")
	})

	log.Printf("Dead PGP HKP stub listening on %s (dead mode — local only)\n", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
