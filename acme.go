package acme
// see https://go-acme.github.io/lego/usage/library/

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/go-acme/lego/v3/challenge"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/certificate"
	"github.com/go-acme/lego/v3/lego"
	"github.com/go-acme/lego/v3/registration"
	"github.com/jtblin/go-logger"

	"github.com/ttys3/go-acme/backend"
	_ "github.com/ttys3/go-acme/backend/backends" // import all backends.
	"github.com/ttys3/go-acme/types"
)

const (
	// #2 - important set to true to bundle CA with certificate and
	// avoid "transport: x509: certificate signed by unknown authority" error
	bundleCA        = true
	defaultCAServer = "https://acme-v02.api.letsencrypt.org/directory"
)

// HostPolicy borrowed from golang.org/x/crypto/acme/autocert
// HostPolicy specifies which host names the Manager is allowed to respond to.
// It returns a non-nil error if the host should be rejected.
// The returned error is accessible via tls.Conn.Handshake and its callers.
// See Manager's HostPolicy field and GetCertificate method docs for more details.
type HostPolicy func(host string) error

// ACME allows to connect to lets encrypt and retrieve certs.
type ACME struct {
	backend     backend.Interface
	Domain      *types.Domain
	Logger      logger.Interface

	// HostPolicy controls which domains the Manager will attempt
	// to retrieve new certificates for. It does not affect cached certs.
	//
	// If non-nil, HostPolicy is called before requesting a new cert.
	// If nil, all hosts are currently allowed. This is not recommended,
	// as it opens a potential attack where clients connect to a server
	// by IP address and pretend to be asking for an incorrect host name.
	// Manager will attempt to obtain a certificate for that host, incorrectly,
	// eventually reaching the CA's rate limit for certificate requests
	// and making it impossible to obtain actual certificates.
	//
	// See GetCertificate for more details.
	HostPolicy  HostPolicy

	BackendName string
	CAServer    string
	DNSProvider string
	Email       string
	KeyType     string
	KeyPath				string
	CertPath			string
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
		renewedCert, err := client.Certificate.Renew(certificate.Resource(*dc.Certificate), bundleCA, mustStaple)
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
	config.Certificate.KeyType = Account.GetKeyType()
	config.Certificate.Timeout = time.Second * 60
	config.HTTPClient.Timeout = time.Second * 60
	
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
func (a *ACME) CreateConfig(ctx context.Context, tlsConfig *tls.Config) error {
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
		account, err = types.NewAccount(a.Email, a.Domain, a.KeyType, a.KeyPath, a.CertPath, a.Logger)
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
		// it may be a wildcard domain certificate or SANs certificate, so we can not simply use equal to validate
		//if clientHello.ServerName != a.Domain.Main {
		//	return nil, fmt.Errorf("[go-acme] Unknown server name: %s", clientHello.ServerName)
		//}
		// skip ServerName validation for loopback request
		if rhost, _, err := net.SplitHostPort(clientHello.Conn.RemoteAddr().String()); err == nil {
			if rip := net.ParseIP(rhost); rip != nil && rip.IsLoopback() {
				return dc.TLSCert, nil
			}
		}
		if err := a.hostPolicy()(clientHello.ServerName); err != nil {
			return nil, fmt.Errorf("[go-acme] Unknown server name: %s, err: %w", clientHello.ServerName, err)
		}
		return dc.TLSCert, nil
	}
	a.Logger.Println("Loaded certificate...")

	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-ctx.Done():
				a.Logger.Println("ACME exited successfully")
				return // returning not to leak the goroutine
			case <-ticker.C:
				if err := a.renewCertificate(client, account); err != nil {
					a.Logger.Printf("Error renewing ACME certificate %q: %s\n",
						account.DomainsCertificate.Domain.Main, err.Error())
				}
			}
		}
	}()
	a.Logger.Println("ACME timer setup done")
	return nil
}

// defaultHostPolicy is used when Manager.HostPolicy is not set.
func defaultHostPolicy(string) error {
	return nil
}

// HostWhitelist returns a policy where only the specified host names are allowed.
// Only exact matches are currently supported. Subdomains, regexp or wildcard
// will not match.
// waring: in here, we do not convert hosts to Punycode via idna.Lookup.ToASCII like golang.org/x/crypto/acme/autocert
// but only convert to lower case, since idna.Lookup.ToASCII("TEST-UPPER-CASE.com") will result in "test-upper-case.com"
// Invalid hosts will be silently ignored.
func HostWhitelist(hosts ...string) HostPolicy {
	whitelist := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			whitelist[h] = true
		}
	}
	return func(host string) error {
		if !whitelist[host] {
			return fmt.Errorf("host %q not configured in HostWhitelist", host)
		}
		return nil
	}
}

func (a *ACME) hostPolicy() HostPolicy {
	if a.HostPolicy != nil {
		return a.HostPolicy
	}
	return defaultHostPolicy
}