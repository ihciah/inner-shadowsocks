package main

import (
	"errors"
	"net"
	"strings"
)

type Whitelist struct {
	enable     bool
	domainlist []string
	iplist     []net.IPNet
	logger     func(string, ...interface{})
}

func (w *Whitelist) check_ip(ip net.IP) bool {
	if !w.enable {
		return true
	}
	for _, ipnet := range w.iplist {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Whitelist) check_domain(d string) bool {
	if !w.enable {
		return true
	}
	for _, domain := range w.domainlist {
		if strings.HasSuffix(d, domain) {
			return true
		}
	}
	return false
}

func (w *Whitelist) check(data []byte) error {
	switch data[0] {
	case 0x01:
		if w.check_ip(net.IP(data[1 : 1+net.IPv4len])) {
			w.logger("[whitelist] Whitelist ipv4 pass.")
			return nil
		}
		w.logger("[whitelist] Whitelist ipv4 reject.")
		return errors.New("IPv4 not in whitelist.")
	case 0x03:
		if w.check_domain(string(data[2 : 2+data[1]])) {
			w.logger("[whitelist] Whitelist domain pass.")
			return nil
		}
		w.logger("[whitelist] Whitelist domain reject.")
		return errors.New("Domain not in whitelist.")
	case 0x04:
		if w.check_ip(net.IP(data[1 : 1+net.IPv6len])) {
			w.logger("[whitelist] Whitelist ipv6 pass.")
			return nil
		}
		w.logger("[whitelist] Whitelist ipv6 reject.")
		return errors.New("IPv6 not in whitelist.")
	}
	return errors.New("Unknown error.")
}
