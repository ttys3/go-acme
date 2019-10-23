package acme

import (
	"github.com/go-acme/lego/v3/challenge"
	"github.com/go-acme/lego/v3/providers/dns/acmedns"
	"github.com/go-acme/lego/v3/providers/dns/alidns"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
	"github.com/go-acme/lego/v3/providers/dns/cloudxns"
	"github.com/go-acme/lego/v3/providers/dns/digitalocean"
	"github.com/go-acme/lego/v3/providers/dns/dnspod"
	"github.com/go-acme/lego/v3/providers/dns/gcloud"
	"github.com/go-acme/lego/v3/providers/dns/linodev4"
	"github.com/go-acme/lego/v3/providers/dns/namecheap"
	"github.com/go-acme/lego/v3/providers/dns/rfc2136"
	"github.com/go-acme/lego/v3/providers/dns/route53"
	"github.com/go-acme/lego/v3/providers/dns/vultr"
)

func newDNSProvider(dns string) (challenge.Provider, error) {
	switch dns {
	case "acmedns":
		return acmedns.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	case "cloudxns":
		return cloudxns.NewDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "gcloud":
		return gcloud.NewDNSProvider()
	case "linodev4":
		return linodev4.NewDNSProvider()
	case "namecheap":
		return namecheap.NewDNSProvider()
	case "route53":
		return route53.NewDNSProvider()
	case "rfc2136":
		return rfc2136.NewDNSProvider()
	case "vultr":
		return vultr.NewDNSProvider()
	default:
		panic("Unknown dns provider " + dns)
	}
}
