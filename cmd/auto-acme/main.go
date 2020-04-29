package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	acme "github.com/ttys3/go-acme"
	"github.com/ttys3/go-acme/types"
	"go.uber.org/zap"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var appVersion = "dev"

const (
	keyPathEnv  = "GO_ACME_KEY_PATH"
	certPathEnv = "GO_ACME_CERT_PATH"
	caServerEnv = "GO_ACME_CA_SERVER"
)

var interval int
var successRunCmd string
var testing bool

var logger *zap.Logger

func main() {
	flushLog := initLogger()
	defer flushLog()
	// show version
	if len(os.Args) == 2 && os.Args[1] == "-v" {
		printVersion(os.Stdout)
		os.Exit(0)
	}

	flag.StringVar(&successRunCmd, "cmd", "", "command to run after success")
	flag.IntVar(&interval, "interval", 24, "hours to wait between updates check")
	flag.BoolVar(&testing, "test", false, "set waiting interval unit to seconds instead of hours for testing")
	flag.Parse()
	successRunCmd = strings.TrimSpace(successRunCmd)

	fmt.Printf("======== auto-acme %s ========\n", appVersion)

	succCh := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // cancel when we are finished consuming integers

	it := time.Hour * time.Duration(interval)
	if testing {
		it = time.Second * time.Duration(interval)
		zap.S().Infof("testing mode: set waiting interval unit to second. current value: %d seconds", interval)
	}
	if _, updated, err := autocertManager(ctx, succCh, it); err != nil {
		// just print the error message, do not exit, friendly to container
		zap.S().Warn(err)
	} else {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			for {
				select {
					case sig := <-c:
						// sig is a ^C, handle it
						zap.S().Infof("captured %v, stopping and exiting...", sig)
						cancel()
						time.Sleep(time.Millisecond * 300)
						os.Exit(0)
					case msg := <-succCh:
						zap.S().Infof("got success notify: %v, try run hook again...", msg)
						runHook(successRunCmd)
				}
			}
		}()
		// run hook command
		if updated {
			runHook(successRunCmd)
		} else if testing {
			zap.S().Infof("certificate is valid and no need to run the hook")
		}
	}

	//endless loop
	for {
		time.Sleep(time.Hour * 24)
	}
}

func runHook(runCmd string) {
	if runCmd != "" {
		zap.S().Infof("try runHook, cmd: [%s]", runCmd)
		ctx := context.Background()
		ctx, cancel := context.WithTimeout(ctx, time.Second*3)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", "-c", runCmd)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			zap.S().Errorf("runHook err : %s, cmd: [%s]", err, runCmd)
		} else {
			zap.S().Infof("runHook successfully, cmd: [%s]", runCmd)
		}
	}
}

func printVersion(w io.Writer) {
	fmt.Fprintf(w, "auto-acme %s"+
		"\nAvailable at http://github.com/ttys3/go-acme \n\n"+
		"Copyright © 2020 荒野無燈 <https://ttys3.net>\n"+
		"Distributed under the Simplified BSD License\n\n", appVersion)
}

func autocertManager(ctx context.Context, outSuccCh chan<- struct{}, it time.Duration) (tlsConfig *tls.Config, updated bool, err error) {
	updated = false
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

	if tlsDomain == "" || dnsprovider == "" {
		return nil, updated, fmt.Errorf("autocertManager(): env var AUTOCERT_DNS_PROVIDER and AUTOCERT_DOMAIN must not be empty")
	}

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
		theDomain = &types.Domain{Main: validDomains[0], SANs: validDomains[1:]}
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
		KeyPath:     os.Getenv(keyPathEnv),
		CertPath:    os.Getenv(certPathEnv),
		CAServer:	 os.Getenv(caServerEnv),
		Logger: 	 zap.NewStdLog(logger),
	}

	zap.S().Infof("autocertManager(): auto ACME begin, use ACME: %v, dns provider: %s, key type: %s",
		useAcme, dnsprovider, keyType)
	zap.S().Infof("autocertManager(): email: %s, domains: %+v", email, validDomains)

	domainWhitelist = strings.TrimSpace(domainWhitelist)
	if domainWhitelist != "" {
		hostWhitelist := strings.Split(domainWhitelist, ",")
		if len(hostWhitelist) > 0 {
			ACME.HostPolicy = acme.HostWhitelist(hostWhitelist...)
			zap.S().Infof("autocertManager(): host whitelist: %+v", hostWhitelist)
		}
	}
	tlsConfig = &tls.Config{}
	if isUpdated, err := ACME.CreateConfig(ctx, outSuccCh, it, tlsConfig); err != nil {
		panic(err)
	} else {
		updated = isUpdated
	}
	zap.S().Infof("autocertManager(): auto ACME done")
	return tlsConfig, updated, nil
}

func initLogger() func() {
	zapCfg := zap.NewDevelopmentConfig()
	zapCfg.DisableCaller = true
	// if Development, stackLevel = WarnLevel, else ErrorLevel
	zapCfg.Development = false
	tmpLogger, _ := zapCfg.Build()
	logger = tmpLogger.Named("[auto-acme]")
	//The default global logger used by zap.L() and zap.S() is a no-op logger.
	//To configure the global loggers, you must use ReplaceGlobals.
	zap.ReplaceGlobals(logger)
	return func() {
		logger.Sync() // flushes buffer, if any
	}
}