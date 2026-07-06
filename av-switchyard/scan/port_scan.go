package scan

// Port scan implementation — host discovery (ARP spray + TCP RST probe),
// full TCP connect scan on the confirmed-live set, and ARP table lookup for
// MAC addresses.

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ScannedHost is one live host found during a subnet port scan.
type ScannedHost struct {
	IP        string     `json:"ip"`
	Hostname  string     `json:"hostname,omitempty"`
	MAC       string     `json:"mac,omitempty"`
	OpenPorts []OpenPort `json:"open_ports"`
}

// SubnetScanReport collects port-scan results for one NIC's subnet.
type SubnetScanReport struct {
	Interface string         `json:"interface"`
	Subnet    string         `json:"subnet"`
	Hosts     []*ScannedHost `json:"hosts"`
	Note      string         `json:"note,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// netInfo is the subset of interface data needed to run a scan.
type netInfo struct {
	Name      string
	HWAddr    net.HardwareAddr
	IP        net.IP
	IPNet     *net.IPNet
	Broadcast net.IP
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	portScanWorkers     = 1024                      // max concurrent TCP dial goroutines
	portScanConnTimeout = 300 * time.Millisecond    // per-connection timeout for full port scan
	maxScanHosts        = 65534                     // hard cap: never enumerate more than a /16

	// Host-discovery phase constants (runs before full port scan on large subnets).
	discoverPhaseSmallMax = 256                     // subnets ≤ this host count: skip discovery, scan all
	discoverConnTimeout   = 100 * time.Millisecond // shorter timeout for discovery probes
	arpSprayWait          = 1500 * time.Millisecond // time to wait for ARP responses after spray
)

// quickDiscoveryPorts are probed in the host-discovery phase.  Three ports that
// cover the vast majority of AV devices with any TCP service at all.
var quickDiscoveryPorts = []int{22, 80, 443}

// ---------------------------------------------------------------------------
// Interface enumeration
// ---------------------------------------------------------------------------

// eligibleInterfaces returns every "up", non-loopback interface that has a
// usable IPv4 address, optionally filtered down to a single named interface.
func eligibleInterfaces(only string) ([]netInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []netInfo
	for _, iface := range ifaces {
		if only != "" && iface.Name != only {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // skip IPv6, Art-Net is IPv4-only
			}
			if ip4.IsLinkLocalUnicast() {
				continue
			}

			bcast := broadcastAddr(ip4, ipnet.Mask)
			out = append(out, netInfo{
				Name:      iface.Name,
				HWAddr:    iface.HardwareAddr,
				IP:        ip4,
				IPNet:     ipnet,
				Broadcast: bcast,
			})
			break // one IPv4 address per interface is enough
		}
	}
	return out, nil
}

func broadcastAddr(ip net.IP, mask net.IPMask) net.IP {
	bcast := make(net.IP, len(ip))
	for i := range ip {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}

// subnetHosts returns all usable host IPs in ni's subnet, excluding our own
// address, the network address, and the broadcast address.
func subnetHosts(ni netInfo) []net.IP {
	ones, bits := ni.IPNet.Mask.Size()
	if bits != 32 {
		return nil
	}
	total := uint32(1) << uint(bits-ones)
	if total <= 2 {
		return nil // /31 or /32 — no conventional host range
	}

	networkU := ipToUint32(ni.IP) & ipToUint32(net.IP(ni.IPNet.Mask))
	selfU := ipToUint32(ni.IP)
	broadcastU := networkU | ^ipToUint32(net.IP(ni.IPNet.Mask))

	var hosts []net.IP
	for i := uint32(1); i < total-1; i++ {
		u := networkU + i
		if u == selfU || u == broadcastU {
			continue
		}
		hosts = append(hosts, uint32ToIP(u))
	}
	return hosts
}

// ---------------------------------------------------------------------------
// Port scan
// ---------------------------------------------------------------------------

// portScanSubnet probes hosts in ni's subnet and returns a SubnetScanReport.
//
// Strategy (selected by subnet size):
//
//	≤ discoverPhaseSmallMax hosts  — full scan every host (current LAN behaviour)
//	> discoverPhaseSmallMax hosts  — two-phase: discover live hosts first via
//	                                 ARP spray + TCP RST probe, then full-scan
//	                                 only the confirmed-live set.
func portScanSubnet(ni netInfo, connTimeout time.Duration) *SubnetScanReport {
	r := &SubnetScanReport{
		Interface: ni.Name,
		Subnet:    ni.IPNet.String(),
	}

	hosts := subnetHosts(ni)
	if len(hosts) == 0 {
		r.Note = "no scannable hosts in subnet (prefix too small)"
		return r
	}
	if len(hosts) > maxScanHosts {
		r.Note = fmt.Sprintf("subnet has %s hosts; scanning first %s",
			commaUint64(uint64(len(hosts))), commaUint64(uint64(maxScanHosts)))
		hosts = hosts[:maxScanHosts]
	}

	// UDP discovery (mDNS/SSDP/SNMP/NTP) runs the whole time in the background.
	// Pass the already-capped hosts slice so probeSNMP/probeNTP never independently
	// re-enumerate the full subnet.
	udpDone := make(chan map[string][]OpenPort, 1)
	go func() { udpDone <- udpDiscoverSubnet(ni, hosts) }()

	// ── Host-discovery phase (skipped for small subnets) ──────────────────
	hostsToScan := hosts
	if len(hosts) > discoverPhaseSmallMax {
		live := discoverLiveHosts(ni, hosts)
		if len(live) > 0 {
			var filtered []net.IP
			for _, ip := range hosts {
				if live[ip.String()] {
					filtered = append(filtered, ip)
				}
			}
			if len(filtered) > 0 {
				hostsToScan = filtered
			}
		}
		if len(hostsToScan) == len(hosts) {
			r.Note = appendNote(r.Note, "host discovery found no live hosts; falling back to full scan")
		}
	}

	// ── Full TCP port scan on hostsToScan ─────────────────────────────────
	// Worker pool: creates exactly portScanWorkers goroutines regardless of how
	// many (ip, port) pairs there are.  The old semaphore+fan-out pattern
	// created one goroutine per pair; in the fallback path that could be
	// 65 534 hosts × 156 ports = ~10 M goroutines, crashing the process.
	type hit struct {
		ip   string
		port int
	}
	hits := make(chan hit, 4096)

	type scanWork struct {
		ip   string
		port int
	}
	scanWorkCh := make(chan scanWork, portScanWorkers)
	go func() {
		for _, ip := range hostsToScan {
			ipStr := ip.String()
			for _, port := range tcpScanPorts {
				scanWorkCh <- scanWork{ipStr, port}
			}
		}
		close(scanWorkCh)
	}()

	var wg sync.WaitGroup
	for i := 0; i < portScanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range scanWorkCh {
				conn, err := net.DialTimeout("tcp",
					fmt.Sprintf("%s:%d", w.ip, w.port), connTimeout)
				if err == nil {
					conn.Close()
					hits <- hit{w.ip, w.port}
				}
			}
		}()
	}
	go func() { wg.Wait(); close(hits) }()

	tcpHostMap := make(map[string][]OpenPort)
	for h := range hits {
		tcpHostMap[h.ip] = append(tcpHostMap[h.ip], OpenPort{
			Port:    h.port,
			Service: portServiceName[h.port],
		})
	}

	// ── Merge TCP + UDP results ───────────────────────────────────────────
	udpMap := <-udpDone

	allIPs := make(map[string]struct{})
	for ip := range tcpHostMap {
		allIPs[ip] = struct{}{}
	}
	for ip := range udpMap {
		allIPs[ip] = struct{}{}
	}

	arpTable := readARPTable()
	for ip := range allIPs {
		var ports []OpenPort
		ports = append(ports, tcpHostMap[ip]...)
		ports = append(ports, udpMap[ip]...)
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		r.Hosts = append(r.Hosts, &ScannedHost{
			IP:        ip,
			MAC:       arpTable[ip],
			OpenPorts: ports,
		})
	}
	sort.Slice(r.Hosts, func(i, j int) bool {
		return ipToUint32(net.ParseIP(r.Hosts[i].IP)) < ipToUint32(net.ParseIP(r.Hosts[j].IP))
	})
	return r
}

func appendNote(existing, note string) string {
	if existing == "" {
		return note
	}
	return existing + "; " + note
}

// ---------------------------------------------------------------------------
// Host discovery
// ---------------------------------------------------------------------------

// discoverLiveHosts uses two parallel strategies to identify which hosts in
// the subnet are actually online, before committing to a full port scan:
//
//  1. ARP spray — sends a harmless UDP packet to every host, causing the OS to
//     send ARP requests.  Hosts that reply to ARP populate the OS ARP cache,
//     which is read after a short wait.  Covers all layer-2-reachable hosts,
//     including UDP-only AV devices that would never appear in a TCP scan.
//
//  2. TCP RST probe — dials a small set of common ports with a short timeout.
//     A successful connect OR a "connection refused" (RST) proves the host is
//     alive even when no port is open.  Covers hosts across routed L3 segments
//     that are unreachable via ARP.
//
// Both strategies run concurrently; results are unioned into the returned map.
func discoverLiveHosts(ni netInfo, hosts []net.IP) map[string]bool {
	liveCh := make(chan string, 512)
	var wg sync.WaitGroup

	// Strategy 1: ARP spray + cache read (parallel with TCP probe)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip := range readARPTable() {
			liveCh <- ip
		}
		arpSpray(ni, hosts)
		time.Sleep(arpSprayWait)
		for ip := range readARPTable() {
			liveCh <- ip
		}
	}()

	// Strategy 2: TCP RST probe — bounded worker pool avoids goroutine explosion
	// on large subnets.
	wg.Add(1)
	go func() {
		defer wg.Done()
		type discWork struct {
			ip   string
			port int
		}
		workCh := make(chan discWork, portScanWorkers)
		go func() {
			for _, ip := range hosts {
				for _, port := range quickDiscoveryPorts {
					workCh <- discWork{ip.String(), port}
				}
			}
			close(workCh)
		}()
		var tcpWg sync.WaitGroup
		for i := 0; i < portScanWorkers; i++ {
			tcpWg.Add(1)
			go func() {
				defer tcpWg.Done()
				for w := range workCh {
					conn, err := net.DialTimeout("tcp",
						fmt.Sprintf("%s:%d", w.ip, w.port), discoverConnTimeout)
					if err == nil {
						conn.Close()
						liveCh <- w.ip
					} else if isConnRefused(err) {
						liveCh <- w.ip
					}
				}
			}()
		}
		tcpWg.Wait()
	}()

	go func() { wg.Wait(); close(liveCh) }()

	live := make(map[string]bool)
	for ipStr := range liveCh {
		if ip := net.ParseIP(ipStr); ip != nil && ni.IPNet.Contains(ip) {
			live[ipStr] = true
		}
	}
	return live
}

// arpSpray sends a single harmless UDP packet (port 9 / discard) to every
// host in the list.  The OS must resolve each destination's MAC via ARP before
// transmitting; hosts that respond populate the OS ARP cache without any
// application-layer handshake or state change on the target.
func arpSpray(ni netInfo, hosts []net.IP) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ni.IP, Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	payload := []byte{0}
	for _, ip := range hosts {
		_, _ = conn.WriteToUDP(payload, &net.UDPAddr{IP: ip, Port: 9})
	}
}

// isConnRefused returns true when err represents a TCP connection-refused
// response (RST from the remote), which proves the host is alive even though
// the specific port is closed.
func isConnRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "connection refused")
}

// resolvePortScanHostnames performs best-effort reverse DNS on scanned hosts.
func resolvePortScanHostnames(hosts []*ScannedHost) {
	if len(hosts) == 0 {
		return
	}
	var wg sync.WaitGroup
	for _, h := range hosts {
		wg.Add(1)
		go func(h *ScannedHost) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
			defer cancel()
			names, err := net.DefaultResolver.LookupAddr(ctx, h.IP)
			if err == nil && len(names) > 0 {
				h.Hostname = strings.TrimSuffix(names[0], ".")
			}
		}(h)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// ARP table
// ---------------------------------------------------------------------------

// readARPTable returns a map of IPv4 address → MAC address string by reading
// the OS ARP cache.  It tries /proc/net/arp on Linux first, then falls back
// to parsing `arp -a` output (works on Linux, macOS, and Windows).
func readARPTable() map[string]string {
	result := make(map[string]string)

	// Linux fast path.
	if data, err := os.ReadFile("/proc/net/arp"); err == nil {
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) >= 4 && f[3] != "00:00:00:00:00:00" {
				result[f[0]] = f[3]
			}
		}
		return result
	}

	// Cross-platform fallback via arp -a.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "arp", "-a").Output()
	if err != nil {
		return result
	}

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		var ip, mac string

		if idx := strings.Index(line, "("); idx >= 0 {
			// Unix: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
			end := strings.Index(line, ")")
			if end > idx {
				ip = line[idx+1 : end]
			}
			if at := strings.Index(line, " at "); at >= 0 {
				rest := strings.Fields(line[at+4:])
				if len(rest) > 0 {
					mac = rest[0]
				}
			}
		} else {
			// Windows: 192.168.1.1     00-aa-bb-cc-dd-ee     dynamic
			f := strings.Fields(line)
			if len(f) >= 2 {
				ip = f[0]
				mac = f[1]
			}
		}

		mac = strings.ReplaceAll(mac, "-", ":")
		if ip != "" && len(mac) >= 11 &&
			mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00" {
			result[ip] = mac
		}
	}
	return result
}
