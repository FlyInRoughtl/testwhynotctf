package mesh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

func dialTransport(addr, transport string) (net.Conn, error) {
	return dialTransportContext(context.Background(), addr, transport)
}

func dialTransportContext(ctx context.Context, addr, transport string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	switch transport {
	case "", "tcp":
		return dialer.DialContext(ctx, "tcp", addr)
	case "tls":
		cfg := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		}
		return tls.DialWithDialer(dialer, "tcp", addr, cfg)
	default:
		return nil, errors.New("unknown transport: " + transport)
	}
}

func listenTransport(addr, transport string) (net.Listener, error) {
	switch transport {
	case "", "tcp":
		return net.Listen("tcp", addr)
	case "tls":
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		return tls.Listen("tcp", addr, cfg)
	default:
		return nil, errors.New("unknown transport: " + transport)
	}
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
			Organization: []string{"Gargoyle Mesh"},
			CommonName:   "gargoyle.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return tls.X509KeyPair(certPEM, keyPEM)
}
