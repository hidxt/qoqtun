package tunnel

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// targetRule is one parsed allowed_targets entry (05-config-schema: CIDR or
// IP followed by ":" then a port, range, or "*").
type targetRule struct {
	network *net.IPNet
	portLo  int
	portHi  int // -1 => any port (*)
}

// ParseTargets builds the allow-list from raw policy entries.
func ParseTargets(entries []string) ([]targetRule, error) {
	rules := make([]targetRule, 0, len(entries))
	for _, e := range entries {
		r, err := parseTarget(e)
		if err != nil {
			return nil, fmt.Errorf("tunnel: bad allowed target %q: %w", e, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func parseTarget(s string) (targetRule, error) {
	idx := strings.LastIndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return targetRule{}, fmt.Errorf("want CIDR:port (e.g. 10.0.0.0/8:*)")
	}
	cidr := s[:idx]
	portSpec := s[idx+1:]
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		// bare IP allowed: normalize to a /32 or /128
		ip := net.ParseIP(cidr)
		if ip == nil {
			return targetRule{}, err
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		_, network, err = net.ParseCIDR(fmt.Sprintf("%s/%d", ip.String(), bits))
		if err != nil {
			return targetRule{}, err
		}
	}
	rule := targetRule{network: network, portLo: 1, portHi: -1}
	if portSpec == "*" {
		return rule, nil
	}
	if strings.Contains(portSpec, "-") {
		parts := strings.SplitN(portSpec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
			return targetRule{}, fmt.Errorf("invalid port range %q", portSpec)
		}
		rule.portLo, rule.portHi = lo, hi
		return rule, nil
	}
	p, err := strconv.Atoi(portSpec)
	if err != nil || p < 1 || p > 65535 {
		return targetRule{}, fmt.Errorf("invalid port %q", portSpec)
	}
	rule.portLo, rule.portHi = p, p
	return rule, nil
}

// Allows reports whether ip:port is inside the allow-list.
// TargetsAllow reports whether (ip, port) is admitted by the raw
// allowed_targets entries. Unparsable entries deny (fail-closed).
func TargetsAllow(entries []string, ip net.IP, port int) bool {
	rules, err := ParseTargets(entries)
	if err != nil {
		return false
	}
	return Allows(rules, ip, port)
}

func Allows(rules []targetRule, ip net.IP, port int) bool {
	for _, r := range rules {
		if r.network.Contains(ip) {
			if r.portHi == -1 || (port >= r.portLo && port <= r.portHi) {
				return true
			}
		}
	}
	return false
}
