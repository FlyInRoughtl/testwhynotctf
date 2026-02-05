package hub

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Listen  string
	DataDir string

	mu      sync.Mutex
	running bool
	srv     *http.Server
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
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/webhook/", s.handleWebhook)
	mux.HandleFunc("/drop/", s.handleDrop)
	mux.HandleFunc("/vault", s.handleVault)
	mux.HandleFunc("/inbox/", s.handleInbox)

	s.srv = &http.Server{
		Addr:    s.Listen,
		Handler: mux,
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
	token := strings.TrimPrefix(r.URL.Path, "/webhook/")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	body, _ := io.ReadAll(r.Body)
	entry := map[string]interface{}{
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
		"method": r.Method,
		"path":   r.URL.Path,
		"header": r.Header,
		"body":   string(body),
	}
	if err := s.writeJSON(filepath.Join("webhook", token), entry); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleDrop(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/drop/")
	if token == "" {
		http.Error(w, "token required", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, "<form method='post' enctype='multipart/form-data'>"+
			"<input type='file' name='file'/>"+
			"<button type='submit'>upload</button></form>")
	case http.MethodPost:
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		dir := s.pathJoin("drop", token)
		if err := os.MkdirAll(dir, 0700); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dst := filepath.Join(dir, header.Filename)
		out, err := os.Create(dst)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer out.Close()
		_, _ = io.Copy(out, file)
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
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file required", http.StatusBadRequest)
		return
	}
	defer file.Close()
	data, _ := io.ReadAll(file)
	hash := sha256.Sum256(data)
	sum := hex.EncodeToString(hash[:])
	dir := s.pathJoin("vault")
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	path := filepath.Join(dir, sum)
	_ = os.WriteFile(path, data, 0600)
	meta := map[string]interface{}{
		"hash":     sum,
		"name":     header.Filename,
		"received": time.Now().UTC().Format(time.RFC3339Nano),
	}
	_ = s.writeJSON(filepath.Join("vault", "index"), meta)
	_, _ = w.Write([]byte(sum))
}

func (s *Server) handleInbox(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimPrefix(r.URL.Path, "/inbox/")
	if addr == "" {
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
