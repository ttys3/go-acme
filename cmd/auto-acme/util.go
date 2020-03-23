package main

import (
	"net"
	"regexp"
)

const DNSNameRegrex string = `^([a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62}){1}(\.[a-zA-Z0-9_]{1}[a-zA-Z0-9_-]{0,62})*[\._]?$`
var rxDNSName = regexp.MustCompile(DNSNameRegrex)

// IsDNSName checks the specified string is domain name.
// ref to IsDNSName() https://github.com/asaskevich/govalidator/blob/master/validator.go#L557
func IsDNSName(s string) bool {
	return !IsIP(s) && "localhost" != s && rxDNSName.MatchString(s)
}

// IsIP checks the specified string is IP.
func IsIP(s string) bool {
	return nil != net.ParseIP(s)
}