package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

func generateSelfSignedCertificate(domain string) (*tls.Certificate, error) {
	rsaPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsaPrivatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaPrivKey)})

	tempCertPEM, err := generatePemCert(rsaPrivKey, domain)
	if err != nil {
		return nil, err
	}

	certificate, err := tls.X509KeyPair(tempCertPEM, rsaPrivatePEM)
	if err != nil {
		return nil, err
	}

	return &certificate, nil
}
func generatePemCert(privateKey *rsa.PrivateKey, domain string) ([]byte, error) {
	derBytes, err := generateDerCert(privateKey, time.Time{}, domain)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}), nil
}

// ref to https://golang.org/src/crypto/tls/generate_cert.go
func generateDerCert(privateKey *rsa.PrivateKey, expiration time.Time, domain string) ([]byte, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	if expiration.IsZero() {
		// add a year
		expiration = time.Now().Add(time.Hour * 24 * 365)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  expiration,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	return x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
}
