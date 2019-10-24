package acme
// see https://go-acme.github.io/lego/usage/library/

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/go-acme/lego/v3/challenge"
	"log"
	"os"
	"time"

	"github.com/go-acme/lego/v3/certcrypto"
	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/jtblin/go-logger"

	"github.com/jtblin/go-acme/backend"
	_ "github.com/jtblin/go-acme/backend/backends" // import all backends.
	"github.com/jtblin/go-acme/types"
)

const (
	// #2 - important set to true to bundle CA with certificate and
	// avoid "transport: x509: certificate signed by unknown authority" error
	bundleCA        = true
	defaultCAServer = "https://acme-v02.api.letsencrypt.org/directory"
)

// ACME allows to connect to lets encrypt and retrieve certs.
type ACME struct {
	backend     backend.Interface
	Domain      *types.Domain
	Logger      logger.Interface
	BackendName string
	CAServer    string
	DNSProvider string
	Email       string
	SelfSigned  bool
}

func (a *ACME) retrieveCertificate(client *lego.Client, account *types.Account) (*tls.Certificate, error) {
	a.Logger.Println("Retrieving ACME certificate...")
	domain := []string{}
	domain = append(domain, a.Domain.Main)
	domain = append(domain, a.Domain.SANs...)
	certificates, err := a.getDomainCertificate(client, domain)
	if err != nil {
		return nil, fmt.Errorf("Error getting ACME certificate for domain %s: %s", domain, err.Error())
	}
	if err = account.DomainsCertificate.AddCertificate(certificates, a.Domain); err != nil {
		return nil, fmt.Errorf("Error adding ACME certificate for domain %s: %s", domain, err.Error())
	}
	if err = a.backend.SaveAccount(account); err != nil {
		return nil, fmt.Errorf("Error Saving ACME account %+v: %s", account, err.Error())
	}
	a.Logger.Println("Retrieved ACME certificate")
	return account.DomainsCertificate.TLSCert, nil
}

func needsUpdate(cert *tls.Certificate) bool {
	// Leaf will be nil because the parsed form of the certificate is not retained
	// so we need to parse the certificate manually.
	for _, c := range cert.Certificate {
		crt, err := x509.ParseCertificate(c)
		// If there's an error, we assume the cert is broken, and needs update.
		// <= 7 days left, renew certificate.
		if err != nil || crt.NotAfter.Before(time.Now().Add(24*7*time.Hour)) {
			return true
		}
	}
	return false
}

func (a *ACME) renewCertificate(client *lego.Client, account *types.Account) error {
	dc := account.DomainsCertificate
	if needsUpdate(dc.TLSCert) {
		mustStaple := false
		renewedCert, err := client.Certificate.Renew(*dc.Certificate, bundleCA, mustStaple)
		if err != nil {
			return err
		}
		err = dc.RenewCertificate(renewedCert, dc.Domain)
		if err != nil {
			return err
		}
		if err = a.backend.SaveAccount(account); err != nil {
			return err
		}
	}
	return nil
}

func (a *ACME) buildACMEClient(Account *types.Account) (*lego.Client, error) {
	caServer := defaultCAServer
	if len(a.CAServer) > 0 {
		caServer = a.CAServer
	}
	config := lego.NewConfig(Account)
	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = caServer
	config.Certificate.KeyType = certcrypto.RSA2048
	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (a *ACME) getDomainCertificate(client *lego.Client, domains []string) (*certificate.Resource, error) {
	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  bundleCA,
	}
	certificates, err := client.Certificate.Obtain(request)
	if err != nil  {
		return nil, fmt.Errorf("Cannot obtain certificates %s+v", err)
	}
	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	//fmt.Printf("%#v\n", certificates)
	a.Logger.Printf("Loaded ACME certificates %s\n", domains)
	return certificates, nil
}

// CreateConfig creates a tls.config from using ACME configuration
func (a *ACME) CreateConfig(tlsConfig *tls.Config) error {
	if a.Logger == nil {
		a.Logger = log.New(os.Stdout, "[go-acme] ", log.Ldate|log.Ltime|log.Lshortfile)
	}
	if a.Domain == nil || a.Domain.Main == "" {
		a.Logger.Panic("The main domain name must be provided")
	}
	if a.SelfSigned {
		a.Logger.Println("Generating self signed certificate...")
		cert, err := generateSelfSignedCertificate(a.Domain.Main)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{*cert}
		return nil
	}

	//lego.Logger = log.New(ioutil.Discard, "", 0)

	if a.BackendName == "" {
		a.BackendName = "fs"
	}
	b, err := backend.InitBackend(a.BackendName)
	if err != nil {
		return err
	}
	a.backend = b

	var account *types.Account
	var needRegister bool

	a.Logger.Println("Loading ACME certificate...")
	account, err = a.backend.LoadAccount(a.Domain.Main)
	if err != nil {
		return fmt.Errorf("[go-acme] LoadAccount() err: %w", err)
	}
	if account != nil {
		a.Logger.Printf("Loaded ACME config from storage %q\n", a.backend.Name())
		if err = account.DomainsCertificate.Init(); err != nil {
			return fmt.Errorf("[go-acme] account.DomainsCertificate.Init() err: %w", err)
		}
	} else {
		a.Logger.Println("Generating ACME Account...")
		account, err = types.NewAccount(a.Email, a.Domain, a.Logger)
		if err != nil {
			return fmt.Errorf("[go-acme] NewAccount err: %w", err)
		}
		needRegister = true
	}

	client, err := a.buildACMEClient(account)
	if err != nil {
		return fmt.Errorf("[go-acme] buildACMEClient err: %w", err)
	}
	provider, err := newDNSProvider(a.DNSProvider)
	if err != nil {
		return fmt.Errorf("[go-acme] newDNSProvider err: %w", err)
	}

	// silent acme: Could not find solver for: tls-alpn-01
	client.Challenge.Remove(challenge.TLSALPN01)
	// silent acme: Could not find solver for: http-01
	client.Challenge.Remove(challenge.HTTP01)

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return fmt.Errorf("[go-acme] SetDNS01Provider err: %w", err)
	}

	if needRegister {
		// New users need to register.
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("[go-acme] client.Registration.Register err: %w", err)
		}
		account.Registration = reg
	}

	dc := account.DomainsCertificate
	if len(dc.Certificate.Certificate) > 0 && len(dc.Certificate.PrivateKey) > 0 {
		go func() {
			if err := a.renewCertificate(client, account); err != nil {
				a.Logger.Printf("Error renewing ACME certificate for %q: %s\n",
					account.DomainsCertificate.Domain.Main, err.Error())
			}
		}()
	} else {
		if _, err := a.retrieveCertificate(client, account); err != nil {
			return err
		}
	}
	tlsConfig.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if clientHello.ServerName != a.Domain.Main {
			return nil, errors.New("Unknown server name")
		}
		return dc.TLSCert, nil
	}
	a.Logger.Println("Loaded certificate...")

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			if err := a.renewCertificate(client, account); err != nil {
				a.Logger.Printf("Error renewing ACME certificate %q: %s\n",
					account.DomainsCertificate.Domain.Main, err.Error())
			}
		}
	}()
	return nil
}
