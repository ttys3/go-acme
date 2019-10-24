package types

import (
	"crypto/tls"
	"errors"
	"github.com/go-acme/lego/v3/certificate"
	"reflect"
)

// Certificate is used to store certificate info.
// copy struct from github.com/go-acme/lego/v3/certificate.Resource but allow save PrivateKey and Certificate field etc ...
// Resource represents a CA issued certificate.
// PrivateKey, Certificate and IssuerCertificate are all
// already PEM encoded and can be directly written to disk.
// Certificate may be a certificate bundle,
// depending on the options supplied to create it.
type Resource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"privateKey"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuerCertificate"`
	CSR               []byte `json:"CSR"`
}

// DomainCertificate contains a certificate for a domain and SANs.
type DomainCertificate struct {
	Certificate *Resource
	Domain      *Domain
	TLSCert     *tls.Certificate `json:"-"`
}

// Domain holds a domain name with SANs.
type Domain struct {
	Main string
	SANs []string
}

func (dc *DomainCertificate) tlsCert() (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair(dc.Certificate.Certificate, dc.Certificate.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// Init initialises the tls certificate.
func (dc *DomainCertificate) Init() error {
	tlsCert, err := dc.tlsCert()
	if err != nil {
		return err
	}
	dc.TLSCert = tlsCert
	return nil
}

// RenewCertificate renew the certificate for the domain.
func (dc *DomainCertificate) RenewCertificate(acmeCert *certificate.Resource, domain *Domain) error {
	if reflect.DeepEqual(domain, dc.Domain) {
		dc.Certificate = (*Resource)(acmeCert)
		if err := dc.Init(); err != nil {
			return err
		}
		return nil
	}
	return errors.New("Certificate to renew not found for domain " + domain.Main)
}

// AddCertificate add the certificate for the domain.
func (dc *DomainCertificate) AddCertificate(acmeCert *certificate.Resource, domain *Domain) error {
	dc.Domain = domain
	dc.Certificate = (*Resource)(acmeCert)
	return dc.Init()
}
