package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GetOrGenerateCert returns cert paths. If no cert is provided via environment,
// a self-signed cert is generated and saved to temporary files.
func GetOrGenerateCert(cfg *config) (bool, error) {
	if cfg.certFile != "" && cfg.keyFile != "" {
		return false, nil
	}
	// Generate self-signed certificate.
	certPEM, keyPEM, err := generateSelfSignedCert()
	if err != nil {
		return false, err
	}
	tmpDir := os.TempDir()
	cfg.certFile = filepath.Join(tmpDir, "beachhead-cert.pem")
	cfg.keyFile = filepath.Join(tmpDir, "beachhead-key.pem")
	if err := os.WriteFile(cfg.certFile, certPEM, 0644); err != nil {
		return false, err
	}
	if err := os.WriteFile(cfg.keyFile, keyPEM, 0600); err != nil {
		return false, err
	}
	return true, nil
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Beachhead"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	return certPEM, keyPEM, nil
}

// TLSConfig returns a basic TLS config.
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}, nil
}
