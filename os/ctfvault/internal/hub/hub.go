package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	maxWebhookBytes    = 256 << 10
	maxDropBytes       = 64 << 20
	maxVaultBytes      = 512 << 20
	maxTokenLength     = 64
	maxEntriesPerToken = 200
	maxTotalEntries    = 2000
)

type Server struct {
	Listen  string
	DataDir string

	mu              sync.Mutex
	running         bool
	srv             *http.Server
	tokenCounts     map[string]int
	totalEntries    int
	maxTokenEntries int
	maxTotalEntries int
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return fmt.Errorf("hub already running")
	}
	if s.Listen == "" {
		s.Listen = "127.0.0.1:8080"
	}
	if s.tokenCounts == nil {
		s.tokenCounts = make(map[string]int)
	}
	if s.maxTokenEntries <= 0 {
		s.maxTokenEntries = maxEntriesPerToken
	}
	if s.maxTotalEntries <= 0 {
		s.maxTotalEntries = maxTotalEntries
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/webhook/", s.handleWebhook)
	mux.HandleFunc("/drop/", s.handleDrop)
	mux.HandleFunc("/vault", s.handleVault)
	mux.HandleFunc("/inbox/", s.handleInbox)

	s.srv = &http.Server{
		Addr:              s.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	s.running = true
	go func() {
		_ = s.srv.ListenAndServe()
	}()
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.srv == nil {
		return nil
	}
	s.running = false
	return s.srv.Close()
}

func (s *Server) Status() (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, s.Listen
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, "<h1>Gargoyle Resource Hub</h1><ul>"+
		"<li>/webhook/&lt;token&gt;</li>"+
		"<li>/drop/&lt;token&gt;</li>"+
		"<li>/vault (POST file)</li>"+
		"<li>/inbox/&lt;address&gt;</li>"+
		"</ul>")
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	token, err := sanitizeToken(strings.TrimPrefix(r.URL.Path, "/webhook/"))
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if isTooLarge(err) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entry := map[string]interface{}{
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
		"method": r.Method,
		"path":   r.URL.Path,
		"header": r.Header,
		"body":   string(body),
	}
	if !s.acquireEntry(token) {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
		return
	}
	committed := false
	defer func() {
		if !committed {
			s.releaseEntry(token)
		}
	}()
	if err := s.writeJSON(filepath.Join("webhook", token), entry); err != nil {
		s.logf("webhook write: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	committed = true
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	token, err := sanitizeToken(strings.TrimPrefix(r.URL.Path, "/drop/"))
	if err != nil {
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<form method='post' enctype='multipart/form-data'>"+
			"<input type='file' name='file'/>"+
			"<button type='submit'>upload</button></form>")
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxDropBytes)
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			if isTooLarge(err) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		if !s.acquireEntry(token) {
			http.Error(w, "quota exceeded", http.StatusTooManyRequests)
			return
		}
		committed := false
		defer func() {
			if !committed {
				s.releaseEntry(token)
			}
		}()
		dir := s.pathJoin("drop", token)
		if err := os.MkdirAll(dir, 0700); err != nil {
			s.logf("drop mkdir: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		out, dst, err := createUniqueFile(dir, header.Filename)
		if err != nil {
			s.logf("drop create: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		_, err = io.Copy(out, file)
		if err != nil {
			_ = out.Close()
			_ = os.Remove(dst)
			s.logf("drop write: %v", err)
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		if err := out.Close(); err != nil {
			_ = os.Remove(dst)
			s.logf("drop close: %v", err)
			http.Error(w, "upload failed", http.StatusInternalServerError)
			return
		}
		committed = true
		_, _ = w.Write([]byte("uploaded"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("POST file to /vault"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxVaultBytes)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if isTooLarge(err) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if !s.acquireEntry("vault") {
		http.Error(w, "quota exceeded", http.StatusTooManyRequests)
		return
	}
	committed := false
	defer func() {
		if !committed {
			s.releaseEntry("vault")
		}
	}()
	dir := s.pathJoin("vault")
	if err := os.MkdirAll(dir, 0700); err != nil {
		s.logf("vault mkdir: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tmp, err := os.CreateTemp(dir, "vault-*.bin")
	if err != nil {
		s.logf("vault temp: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(hasher, tmp), file)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		s.logf("vault write: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		s.logf("vault close: %v", err)
		http.Error(w, "upload failed", http.StatusInternalServerError)
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	path := filepath.Join(dir, sum)
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(tmp.Name())
	} else if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		s.logf("vault rename: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	meta := map[string]interface{}{
		"hash":     sum,
		"name":     safeFilename(header.Filename),
		"size":     n,
		"received": time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = s.writeJSON(filepath.Join("vault", "index"), meta)
	committed = true
	_, _ = w.Write([]byte(sum))
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	addr, err := sanitizeInbox(strings.TrimPrefix(r.URL.Path, "/inbox/"))
	if err != nil {
		http.Error(w, "address required", http.StatusBadRequest)
		return
	}
	dir := s.pathJoin("mail", "inbox", addr)
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "no messages", http.StatusNotFound)
		return
	}
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Name())
		b.WriteString("\n")
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) writeJSON(subdir string, entry map[string]interface{}) error {
	dir := s.pathJoin(subdir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	name := time.Now().UTC().Format("20060102-150405.000000000") + ".json"
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (s *Server) pathJoin(parts ...string) string {
	base := s.DataDir
	if base == "" {
		base = "."
	}
	return filepath.Join(append([]string{base}, parts...)...)
}

func (s *Server) logf(format string, args ...interface{}) {
	log.Printf("hub: "+format, args...)
}

func (s *Server) acquireEntry(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxTotalEntries > 0 && s.totalEntries >= s.maxTotalEntries {
		return false
	}
	if s.maxTokenEntries > 0 {
		if s.tokenCounts[token] >= s.maxTokenEntries {
			return false
		}
	}
	s.totalEntries++
	s.tokenCounts[token]++
	return true
}

func (s *Server) releaseEntry(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenCounts[token] > 0 {
		s.tokenCounts[token]--
	}
	if s.totalEntries > 0 {
		s.totalEntries--
	}
}

func sanitizeToken(token string) (string, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxTokenLength {
		return "", errors.New("invalid token")
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return "", errors.New("invalid token")
	}
	return token, nil
}

func sanitizeInbox(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" || len(addr) > 128 {
		return "", errors.New("invalid address")
	}
	for _, r := range addr {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '@' || r == '.' || r == '-' || r == '_':
		default:
			return "", errors.New("invalid address")
		}
	}
	return addr, nil
}

func safeFilename(name string) string {
	base := filepath.Base(name)
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return ""
	}
	return out
}

func createUniqueFile(dir, name string) (*os.File, string, error) {
	safe := safeFilename(name)
	if safe == "" {
		safe = "file_" + randHex(6)
	}
	ext := filepath.Ext(safe)
	stem := strings.TrimSuffix(safe, ext)
	for i := 0; i < 100; i++ {
		candidate := stem
		if i > 0 {
			candidate = fmt.Sprintf("%s_%d", stem, i)
		}
		filename := candidate + ext
		path := filepath.Join(dir, filename)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			return f, path, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("unable to allocate file name")
}

func randHex(n int) string {
	if n <= 0 {
		n = 6
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func isTooLarge(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, http.ErrBodyReadAfterClose) {
		return true
	}
	if strings.Contains(err.Error(), "http: request body too large") {
		return true
	}
	return false
}
