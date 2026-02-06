package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"gargoyle/internal/wss"

	"encoding/pem"
	"math/big"
)

type WSServer struct {
	Listen  string
	Public  string
	Service string
	Token   string
	Cert    string
	Key     string
}

type WSSClient struct {
	Server  string
	Service string
	Token   string
	Local   string
}

type controlMsg struct {
	Op string `json:"op"`
	ID string `json:"id"`
}

func RunWSSServer(ctx context.Context, cfg WSServer) error {
	if cfg.Listen == "" {
		return errors.New("listen is empty")
	}
	if cfg.Public == "" {
		return errors.New("public listen is empty")
	}
	if cfg.Service == "" {
		cfg.Service = "service"
	}
	if cfg.Token == "" {
		return errors.New("token is empty")
	}

	state := &wssState{
		service: cfg.Service,
		token:   cfg.Token,
		pending: map[string]chan *wss.Conn{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/control", func(w http.ResponseWriter, r *http.Request) {
		if !checkToken(r, cfg.Token, cfg.Service) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := wss.Accept(w, r)
		if err != nil {
			return
		}
		state.setControl(conn)
	})
	mux.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		if !checkToken(r, cfg.Token, cfg.Service) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		conn, err := wss.Accept(w, r)
		if err != nil {
			return
		}
		state.bindData(id, conn)
	})

	tlsCfg, err := loadOrSelfSigned(cfg.Cert, cfg.Key)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:      cfg.Listen,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	tlsLn, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer tlsLn.Close()

	ln, err := net.Listen("tcp", cfg.Public)
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- server.Serve(tls.NewListener(tlsLn, tlsCfg))
	}()
	go func() {
		errCh <- servePublic(ctx, ln, state)
	}()

	select {
	case <-ctx.Done():
		_ = server.Close()
		_ = ln.Close()
		return ctx.Err()
	case err := <-errCh:
		_ = server.Close()
		return err
	}
}

func RunWSSClient(ctx context.Context, cfg WSSClient) error {
	if cfg.Server == "" {
		return errors.New("server is empty")
	}
	if cfg.Service == "" {
		cfg.Service = "service"
	}
	if cfg.Token == "" {
		return errors.New("token is empty")
	}
	if cfg.Local == "" {
		return errors.New("local target is empty")
	}
	controlURL := buildURL(cfg.Server, "/control", cfg.Service, cfg.Token, "")
	controlConn, err := wss.Dial(controlURL)
	if err != nil {
		return err
	}
	defer controlConn.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		payload, err := controlConn.ReadMessage()
		if err != nil {
			return err
		}
		var msg controlMsg
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue
		}
		if msg.Op != "dial" || msg.ID == "" {
			continue
		}
		go func(id string) {
			localConn, err := net.Dial("tcp", cfg.Local)
			if err != nil {
				return
			}
			dataURL := buildURL(cfg.Server, "/data", cfg.Service, cfg.Token, id)
			dataConn, err := wss.Dial(dataURL)
			if err != nil {
				_ = localConn.Close()
				return
			}
			bridge(localConn, dataConn)
		}(msg.ID)
	}
}

type wssState struct {
	mu      sync.Mutex
	service string
	token   string
	control *wss.Conn
	pending map[string]chan *wss.Conn
}

func (s *wssState) setControl(conn *wss.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.control != nil {
		_ = s.control.Close()
	}
	s.control = conn
}

func (s *wssState) bindData(id string, conn *wss.Conn) {
	s.mu.Lock()
	ch, ok := s.pending[id]
	if ok {
		delete(s.pending, id)
	}
	s.mu.Unlock()
	if ok {
		ch <- conn
		return
	}
	_ = conn.Close()
}

func servePublic(ctx context.Context, ln net.Listener, state *wssState) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			ctrl := state.getControl()
			if ctrl == nil {
				return
			}
			id, err := randID()
			if err != nil {
				return
			}
			ch := make(chan *wss.Conn, 1)
			state.storePending(id, ch)
			msg := controlMsg{Op: "dial", ID: id}
			data, _ := json.Marshal(msg)
			_ = ctrl.WriteMessageText(data)
			select {
			case dataConn := <-ch:
				bridge(c, dataConn)
			case <-time.After(10 * time.Second):
				state.clearPending(id)
			case <-ctx.Done():
			}
		}(conn)
	}
}

func (s *wssState) getControl() *wss.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.control
}

func (s *wssState) storePending(id string, ch chan *wss.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id] = ch
}

func (s *wssState) clearPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
}

func bridge(a net.Conn, b io.ReadWriteCloser) {
	defer a.Close()
	defer b.Close()
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
	}()
	<-errCh
}

func buildURL(base, path, service, token, id string) string {
	u, _ := url.Parse(base)
	u.Path = path
	q := u.Query()
	if service != "" {
		q.Set("service", service)
	}
	if token != "" {
		q.Set("token", token)
	}
	if id != "" {
		q.Set("id", id)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func checkToken(r *http.Request, token string, service string) bool {
	q := r.URL.Query()
	if q.Get("token") != token {
		return false
	}
	if service != "" && q.Get("service") != service {
		return false
	}
	return true
}

func randID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func loadOrSelfSigned(certPath, keyPath string) (*tls.Config, error) {
	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"Gargoyle Tunnel"},
			CommonName:   "gargoyle.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pemEncode("CERTIFICATE", derBytes)
	keyPEM := pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv))
	return tls.X509KeyPair(certPEM, keyPEM)
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
