package scan

// UDP-based discovery probes to complement the TCP port scan.
//
// Each probe is discovery-only — no state-changing commands are ever sent.
// All probes run concurrently and feed results into a shared channel; the
// caller merges them with TCP results by IP address.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/gosnmp/gosnmp"
	"github.com/grandcat/zeroconf"
	ssdplib "github.com/koron/go-ssdp"
)

// udpDiscoveryTimeout is how long multicast probes (mDNS, SSDP) listen for
// responses.  Per-host probes (SNMP, NTP) use udpPerHostTimeout instead.
const udpDiscoveryTimeout = 5 * time.Second
const udpPerHostTimeout = 400 * time.Millisecond

// udpProbeResult is a single UDP-discovered service on a host.
type udpProbeResult struct {
	IP      string
	Port    int
	Service string // human-readable label, may include discovered detail
}

// udpDiscoverSubnet runs all UDP discovery probes concurrently on ni's network.
// It returns a map from IPv4 address → discovered UDP services (as OpenPort values).
// Only addresses within ni's subnet are returned.
func udpDiscoverSubnet(ni netInfo) map[string][]OpenPort {
	ch := make(chan udpProbeResult, 1024)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() { defer wg.Done(); probeMDNS(ni, udpDiscoveryTimeout, ch) }()

	wg.Add(1)
	go func() { defer wg.Done(); probeSSDP(ni, udpDiscoveryTimeout, ch) }()

	wg.Add(1)
	go func() { defer wg.Done(); probeSNMP(ni, udpPerHostTimeout, ch) }()

	wg.Add(1)
	go func() { defer wg.Done(); probeNTP(ni, udpPerHostTimeout, ch) }()

	go func() { wg.Wait(); close(ch) }()

	out := make(map[string][]OpenPort)
	seen := make(map[string]bool) // "ip:port" dedup key

	for r := range ch {
		ip := net.ParseIP(r.IP)
		if ip == nil || ip.To4() == nil {
			continue // IPv4 only
		}
		if !ni.IPNet.Contains(ip) {
			continue
		}
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if !seen[key] {
			seen[key] = true
			out[r.IP] = append(out[r.IP], OpenPort{Port: r.Port, Service: r.Service})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// mDNS / DNS-SD  (RFC 6762 / RFC 6763)
// ---------------------------------------------------------------------------

// avMDNSServiceTypes is the curated list of DNS-SD service types to browse.
// Each type that responds gives us the presence of that protocol on the host.
var avMDNSServiceTypes = []string{
	"_artnet._udp",
	"_sacn._udp",
	"_e131._udp",
	"_osc._udp",
	"_osc._tcp",
	"_ndi._tcp",
	"_ndi._udp",
	"_dante._udp",
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_sftp-ssh._tcp",
	"_googlecast._tcp",
	"_vizrt._tcp",
	"_blackmagic._tcp",
	"_qsys._tcp",
	"_atem._tcp",
	"_atem._udp",
	"_watchout._tcp",
	"_disguise._tcp",
	"_ma._tcp",
	"_eos._tcp",
	"_ptp._udp",
	"_ntp._udp",
	"_mdnsresponder._udp",
	"_device-info._tcp",
}

// probeMDNS sends DNS-SD browse queries for AV-relevant service types on ni's
// interface and emits one result per unique IPv4 address found, listing all
// service types that address advertises.
func probeMDNS(ni netInfo, timeout time.Duration, out chan<- udpProbeResult) {
	iface, err := net.InterfaceByName(ni.Name)
	if err != nil {
		return
	}

	var mu sync.Mutex
	// ip → set of advertised service types
	discovered := make(map[string]map[string]struct{})

	var wg sync.WaitGroup
	for _, svcType := range avMDNSServiceTypes {
		wg.Add(1)
		go func(svcType string) {
			defer wg.Done()
			resolver, err := zeroconf.NewResolver(
				zeroconf.SelectIfaces([]net.Interface{*iface}),
			)
			if err != nil {
				return
			}

			entries := make(chan *zeroconf.ServiceEntry)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Collect entries until the channel is closed (context expires).
			collectDone := make(chan struct{})
			go func() {
				defer close(collectDone)
				for entry := range entries {
					for _, addr := range entry.AddrIPv4 {
						ipStr := addr.String()
						mu.Lock()
						if discovered[ipStr] == nil {
							discovered[ipStr] = make(map[string]struct{})
						}
						discovered[ipStr][svcType] = struct{}{}
						mu.Unlock()
					}
				}
			}()

			_ = resolver.Browse(ctx, svcType, "local.", entries)
			<-ctx.Done()
			<-collectDone
		}(svcType)
	}
	wg.Wait()

	for ip, typeSet := range discovered {
		var svcList []string
		for t := range typeSet {
			svcList = append(svcList, t)
		}
		sort.Strings(svcList)
		out <- udpProbeResult{ip, 5353, "mDNS [" + strings.Join(svcList, " ") + "]"}
	}
}

// ---------------------------------------------------------------------------
// SSDP / UPnP  (IETF HTTPU/M-SEARCH)
// ---------------------------------------------------------------------------

// probeSSDP sends an SSDP M-SEARCH from ni's IP address and emits one result
// per unique device that responds. The responding device's IP is extracted
// from the LOCATION URL in its response.
func probeSSDP(ni netInfo, timeout time.Duration, out chan<- udpProbeResult) {
	waitSec := int(timeout.Seconds())
	if waitSec < 1 {
		waitSec = 1
	}
	if waitSec > 5 {
		waitSec = 5
	}

	// koron/go-ssdp expects "host:port" format; use empty string to let it
	// bind to 0.0.0.0 automatically.  The subnet filter downstream keeps only
	// IPs within ni's network.
	list, err := ssdplib.Search(ssdplib.All, waitSec, "")
	if err != nil {
		return
	}

	seenIP := make(map[string]bool)
	for _, srv := range list {
		ip := ipv4FromURL(srv.Location)
		if ip == "" {
			continue
		}
		if seenIP[ip] {
			continue
		}
		seenIP[ip] = true
		label := srv.Server
		if label == "" {
			label = srv.Type
		}
		if len(label) > 64 {
			label = label[:61] + "..."
		}
		out <- udpProbeResult{ip, 1900, "SSDP (" + label + ")"}
	}
}

// ipv4FromURL parses rawURL and returns the host as an IPv4 string.
// If the host is a name, it attempts a one-shot DNS resolution.
func ipv4FromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return ip.String()
		}
		return "" // IPv6 — skip
	}
	// Hostname — try a quick resolution.
	addrs, err := net.LookupHost(host)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return a
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// SNMP  (RFC 3411-3418)
// ---------------------------------------------------------------------------

// probeSNMP sends SNMPv2c GET sysDescr.0 (community "public") to every host
// in ni's subnet and emits a result for each host that responds.
// Only the read-only GET operation is used — no SET is ever sent.
func probeSNMP(ni netInfo, timeout time.Duration, out chan<- udpProbeResult) {
	hosts := subnetHosts(ni)
	if len(hosts) == 0 {
		return
	}

	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			g := &gosnmp.GoSNMP{
				Target:    ip.String(),
				Port:      161,
				Community: "public",
				Version:   gosnmp.Version2c,
				Timeout:   timeout,
				Retries:   0,
			}
			if err := g.Connect(); err != nil {
				return
			}
			defer g.Conn.Close()

			result, err := g.Get([]string{"1.3.6.1.2.1.1.1.0"}) // sysDescr.0
			if err != nil {
				return
			}
			for _, v := range result.Variables {
				if v.Type == gosnmp.OctetString {
					desc := strings.TrimSpace(string(v.Value.([]byte)))
					// Collapse internal whitespace and truncate.
					desc = strings.Join(strings.Fields(desc), " ")
					if len(desc) > 64 {
						desc = desc[:61] + "..."
					}
					out <- udpProbeResult{ip.String(), 161, "SNMP (" + desc + ")"}
					return
				}
			}
			// Responded but sysDescr was not an octet string — still mark as SNMP.
			out <- udpProbeResult{ip.String(), 161, "SNMP"}
		}(ip)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// NTP  (RFC 5905)
// ---------------------------------------------------------------------------

// probeNTP sends an NTP client request to every host in ni's subnet and emits
// a result for each host that responds as a valid NTP server.
// The local bind address is set to ni.IP so traffic stays on the right interface.
func probeNTP(ni netInfo, timeout time.Duration, out chan<- udpProbeResult) {
	hosts := subnetHosts(ni)
	if len(hosts) == 0 {
		return
	}

	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup

	for _, ip := range hosts {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resp, err := ntp.QueryWithOptions(ip.String(), ntp.QueryOptions{
				Timeout:      timeout,
				LocalAddress: ni.IP.String(),
			})
			if err != nil {
				return
			}
			out <- udpProbeResult{
				ip.String(), 123,
				fmt.Sprintf("NTP stratum-%d (v%d)", resp.Stratum, resp.Version),
			}
		}(ip)
	}
	wg.Wait()
}
