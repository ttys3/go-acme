package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	acme "github.com/ttys3/go-acme"
	"github.com/ttys3/go-acme/types"
	"go.uber.org/zap"
	"syscall"
	"time"
)

var appVersion = "dev"

const (
	keyPathEnv = "GO_ACME_KEY_PATH"
	certPathEnv = "GO_ACME_CERT_PATH"
)

func main() {
	// show version
	if len(os.Args) == 2 && os.Args[1] == "-v" {
		printVersion(os.Stdout)
		os.Exit(0)
	}

	fmt.Printf("======== auto-acme %s ========\n", appVersion)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	if _, err := autocertManager(ctx); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func(){
		for sig:= range c {
			// sig is a ^C, handle it
			zap.S().Infof("captured %v, stopping and exiting..", sig)
			cancel()
			time.Sleep(time.Millisecond * 300)
			os.Exit(0)
		}
	}()

	for {
		time.Sleep(time.Hour * 24)
	}
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "auto-acme %s"+
		"\nAvailable at http://github.com/ttys3/auto-acme \n\n"+
		"Copyright © 2020 荒野無燈 <https://ttys3.net>\n"+
		"Distributed under the Simplified BSD License\n\n", appVersion)
}

func autocertManager(ctx context.Context) (tlsConfig *tls.Config, err error) {
	email := os.Getenv("AUTOCERT_EMAIL")
	if email == "" {
		email = "NanoDM@gmail.com"
	}
	keyType := os.Getenv("AUTOCERT_KEYTYPE")
	domainWhitelist := os.Getenv("AUTOCERT_DOMAIN_WHITELIST")
	// required param
	dnsprovider := os.Getenv("AUTOCERT_DNS_PROVIDER")
	dnsprovider = strings.TrimSpace(dnsprovider)
	tlsDomain := os.Getenv("AUTOCERT_DOMAIN")
	tlsDomain = strings.TrimSpace(tlsDomain)
	if tlsDomain != "" && dnsprovider != "" {
		// enable SelfSigned if is it localhost or IP addr
		useAcme := false
		var providedDomains []string
		var validDomains []string
		if strings.Contains(tlsDomain, ",") {
			providedDomains = strings.Split(tlsDomain, ",")
		} else {
			providedDomains = []string{tlsDomain}
		}
		for _, name := range providedDomains {
			nameToCheck := name
			// make wildcard name valid
			if nameToCheck[:2] == "*." {
				nameToCheck = nameToCheck[2:]
			}
			if IsDNSName(nameToCheck) {
				validDomains = append(validDomains, name)
			}
		}
		theDomain := &types.Domain{Main: "nodomain.localhost"}
		if len(validDomains) > 0 {
			useAcme = true
			theDomain = &types.Domain{Main: validDomains[0], SANs:validDomains[1:]}
		} else {
			zap.S().Errorf("autocertManager(): ACME is disabled for reason: no valid domain provided")
			zap.S().Infof("autocertManager(): fallback to selfsigned cert")
		}
		ACME := &acme.ACME{
			BackendName: "fs", //cache path set by GO_ACME_STORAGE_DIR env
			Email:       email,
			KeyType:     keyType,
			DNSProvider: dnsprovider,
			SelfSigned:  !useAcme,
			Domain:      theDomain,
			KeyPath: os.Getenv(keyPathEnv),
			CertPath: os.Getenv(certPathEnv),
		}

		zap.S().Infof("autocertManager(): auto ACME begin, use ACME: %v, dns provider: %s, key type: %s", useAcme, dnsprovider, keyType)
		zap.S().Infof("autocertManager(): email: %s, domains: %+v", email, validDomains)

		domainWhitelist := strings.TrimSpace(domainWhitelist)
		if domainWhitelist != "" {
			hostWhitelist := strings.Split(domainWhitelist, ",")
			if len(hostWhitelist) > 0 {
				ACME.HostPolicy =  acme.HostWhitelist(hostWhitelist...)
				zap.S().Infof("autocertManager(): host whitelist: %+v", hostWhitelist)
			}
		}
		tlsConfig := &tls.Config{}
		if err := ACME.CreateConfig(ctx, tlsConfig); err != nil {
			panic(err)
		}
		zap.S().Infof("autocertManager(): auto ACME done")
		return tlsConfig, nil
	} else {
		return nil, fmt.Errorf("autocertManager(): env var AUTOCERT_DNS_PROVIDER and AUTOCERT_DOMAIN must not be empty")
	}
}
