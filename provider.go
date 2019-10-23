package acme

import (
	"github.com/go-acme/lego/v3/acme"
	"github.com/go-acme/lego/v3/providers/dns/cloudflare"
	"github.com/go-acme/lego/v3/providers/dns/digitalocean"
	"github.com/go-acme/lego/v3/providers/dns/dnsimple"
	"github.com/go-acme/lego/v3/providers/dns/dyn"
	"github.com/go-acme/lego/v3/providers/dns/gandi"
	"github.com/go-acme/lego/v3/providers/dns/gcloud"
	"github.com/go-acme/lego/v3/providers/dns/namecheap"
	"github.com/go-acme/lego/v3/providers/dns/rfc2136"
	"github.com/go-acme/lego/v3/providers/dns/route53"
	"github.com/go-acme/lego/v3/providers/dns/vultr"
)

func newDNSProvider(dns string) (acme.ChallengeProvider, error) {
	switch dns {
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "dnsimple":
		return dnsimple.NewDNSProvider()
	case "dyn":
		return dyn.NewDNSProvider()
	case "gandi":
		return gandi.NewDNSProvider()
	case "gcloud":
		return googlecloud.NewDNSProvider()
	case "manual":
		return acme.NewDNSProviderManual()
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
