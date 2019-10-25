package types

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/go-acme/lego/v3/certcrypto"
	"strings"

	"github.com/go-acme/lego/v3/registration"
	"github.com/jtblin/go-logger"
)

// Account is used to store lets encrypt registration info
// and implements the acme.User interface.
type Account struct {
	KeyType            string
	Email              string
	DomainsCertificate *DomainCertificate
	Logger      	   logger.Interface	  `json:"-"`
	PrivateKey         []byte
	Registration       *registration.Resource
}

// GetEmail returns email.
func (a *Account) GetEmail() string {
	return a.Email
}

// GetRegistration returns lets encrypt registration resource.
func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

// GetPrivateKey returns private key.
func (a *Account) GetPrivateKey() crypto.PrivateKey {
	if privateKey, err := x509.ParsePKCS1PrivateKey(a.PrivateKey); err == nil {
		return privateKey
	}
	a.Logger.Printf("Cannot unmarshall private key %+v\n", a.PrivateKey)
	return nil
}

// GetKeyType the type from which private keys should be generated
func (a *Account) GetKeyType() certcrypto.KeyType {
	switch strings.ToUpper(a.KeyType) {
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	case "RSA8192":
		return certcrypto.RSA8192
	case "EC256":
		return certcrypto.EC256
	case "EC384":
		return certcrypto.EC384
	default:
		return certcrypto.EC256
	}
}

// NewAccount creates a new account for the specified email and domain.
func NewAccount(email string, domain *Domain, keyType string, logger logger.Interface) (*Account, error) {
	// Create a user. New accounts need an email and private key to start
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	account := &Account{
		Email:      email,
		Logger:     logger,
		KeyType:    keyType,
		PrivateKey: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	account.DomainsCertificate = &DomainCertificate{
		Certificate: &Resource{},
		Domain:      domain,
	}
	return account, nil
}
