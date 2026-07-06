package scan

// OS network interface reporting — enumerates every interface known to the
// OS, computes IPv4 addressing details, and (on Windows) queries the firewall
// network category via PowerShell.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// IPv4NetworkInfo describes one IPv4 address bound to an interface, along
// with the full addressing picture of the network it belongs to.
type IPv4NetworkInfo struct {
	Address          string `json:"address"`
	CIDR             string `json:"cidr"`
	SubnetMask       string `json:"subnet_mask"`
	NetworkAddress   string `json:"network_address"`
	BroadcastAddress string `json:"broadcast_address"`
	FullRange        string `json:"full_range"`        // e.g. "192.168.1.0 - 192.168.1.255"
	UsableRange      string `json:"usable_host_range"` // e.g. "192.168.1.1 - 192.168.1.254"
	TotalAddresses   uint64 `json:"total_addresses"`
	UsableAddresses  uint64 `json:"usable_host_addresses"`
	Note             string `json:"note,omitempty"` // e.g. "loopback", "link-local (APIPA)"
}

// OSInterfaceReport describes one network interface known to the OS.
type OSInterfaceReport struct {
	Name            string            `json:"name"`
	Index           int               `json:"index"`
	MAC             string            `json:"mac,omitempty"`
	Up              bool              `json:"up"`
	Loopback        bool              `json:"loopback"`
	MTU             int               `json:"mtu"`
	WindowsCategory string            `json:"windows_network_category,omitempty"`
	Addresses       []IPv4NetworkInfo `json:"ipv4_addresses"`
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

// buildOSInterfaceReports enumerates every interface known to the OS
// (up or down, loopback included) and computes IPv4 addressing details for
// each bound address. Only the interface named in onlyIface is returned if
// onlyIface is non-empty.
func buildOSInterfaceReports(onlyIface string) ([]*OSInterfaceReport, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []*OSInterfaceReport
	for _, iface := range ifaces {
		if onlyIface != "" && iface.Name != onlyIface {
			continue
		}

		r := &OSInterfaceReport{
			Name:     iface.Name,
			Index:    iface.Index,
			MAC:      hwString(iface.HardwareAddr),
			Up:       iface.Flags&net.FlagUp != 0,
			Loopback: iface.Flags&net.FlagLoopback != 0,
			MTU:      iface.MTU,
		}

		addrs, err := iface.Addrs()
		if err != nil {
			out = append(out, r)
			continue
		}

		for _, a := range addrs {
			var ipnet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: net.CIDRMask(32, 32)}
			default:
				continue
			}

			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue // IPv4 only, per assumption
			}

			info := ipv4NetworkInfo(ip4, ipnet)
			if r.Loopback {
				info.Note = "loopback network"
			} else if ip4.IsLinkLocalUnicast() {
				info.Note = "link-local (APIPA) - no DHCP server was reached on this interface"
			}
			r.Addresses = append(r.Addresses, info)
		}

		out = append(out, r)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ipv4NetworkInfo computes the full addressing picture (network/broadcast
// address, usable host range, total address count) for the network that ip
// belongs to, per ipnet's mask.
func ipv4NetworkInfo(ip net.IP, ipnet *net.IPNet) IPv4NetworkInfo {
	mask := ipnet.Mask
	if len(mask) != 4 {
		mask = net.CIDRMask(32, 32)
	}
	prefix, _ := mask.Size()

	ipU := ipToUint32(ip)
	maskU := ipToUint32(net.IP(mask))
	networkU := ipU & maskU
	broadcastU := networkU | ^maskU

	total := uint64(1) << uint(32-prefix)

	var usable uint64
	var firstUsableU, lastUsableU uint32
	switch {
	case prefix == 32:
		usable = 1
		firstUsableU, lastUsableU = ipU, ipU
	case prefix == 31:
		// RFC 3021 point-to-point link: both addresses are usable, no
		// broadcast address in the traditional sense.
		usable = 2
		firstUsableU, lastUsableU = networkU, broadcastU
	default:
		usable = total - 2
		firstUsableU, lastUsableU = networkU+1, broadcastU-1
	}

	network := uint32ToIP(networkU)
	broadcast := uint32ToIP(broadcastU)
	firstUsable := uint32ToIP(firstUsableU)
	lastUsable := uint32ToIP(lastUsableU)

	return IPv4NetworkInfo{
		Address:          ip.String(),
		CIDR:             fmt.Sprintf("%s/%d", ip.String(), prefix),
		SubnetMask:       net.IP(mask).String(),
		NetworkAddress:   network.String(),
		BroadcastAddress: broadcast.String(),
		FullRange:        fmt.Sprintf("%s - %s", network.String(), broadcast.String()),
		UsableRange:      fmt.Sprintf("%s - %s", firstUsable.String(), lastUsable.String()),
		TotalAddresses:   total,
		UsableAddresses:  usable,
	}
}

// ---------------------------------------------------------------------------
// Shared numeric helpers (used by os_report and port_scan)
// ---------------------------------------------------------------------------

func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// commaUint64 renders n with thousands separators, e.g. 16777216 -> "16,777,216".
func commaUint64(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
		if len(s) > lead {
			b.WriteByte(',')
		}
	}
	for i := lead; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Windows network category lookup
// ---------------------------------------------------------------------------

// windowsNetProfile mirrors the fields we care about from
// Get-NetConnectionProfile's JSON output.
type windowsNetProfile struct {
	Name            string          `json:"Name"`
	InterfaceAlias  string          `json:"InterfaceAlias"`
	InterfaceIndex  int             `json:"InterfaceIndex"`
	NetworkCategory json.RawMessage `json:"NetworkCategory"`
}

// windowsCategoryLabel translates the raw NetworkCategory value (which
// PowerShell may render as a string name or, on older versions, an integer
// enum value) into the label Windows itself shows in Settings / Firewall UI.
func windowsCategoryLabel(raw json.RawMessage) string {
	s := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	switch s {
	case "0", "Public":
		return "Public"
	case "1", "Private":
		return "Private"
	case "2", "DomainAuthenticated":
		return "Domain (business/work network joined to an Active Directory domain)"
	default:
		if s == "" {
			return "Unknown"
		}
		return s
	}
}

// getWindowsNetworkCategories asks Windows (via PowerShell's
// Get-NetConnectionProfile cmdlet) which firewall profile — Public, Private,
// or Domain — each connected network is currently classified as.
func getWindowsNetworkCategories() (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-NetConnectionProfile | ConvertTo-Json -Depth 4")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Get-NetConnectionProfile failed: %w", err)
	}

	out = []byte(strings.TrimSpace(string(out)))
	if len(out) == 0 {
		return map[string]string{}, nil
	}

	var profiles []windowsNetProfile
	if out[0] == '[' {
		if err := json.Unmarshal(out, &profiles); err != nil {
			return nil, fmt.Errorf("parsing Get-NetConnectionProfile JSON array: %w", err)
		}
	} else {
		var single windowsNetProfile
		if err := json.Unmarshal(out, &single); err != nil {
			return nil, fmt.Errorf("parsing Get-NetConnectionProfile JSON object: %w", err)
		}
		profiles = []windowsNetProfile{single}
	}

	result := make(map[string]string, len(profiles))
	for _, p := range profiles {
		if p.InterfaceAlias == "" {
			continue
		}
		result[p.InterfaceAlias] = windowsCategoryLabel(p.NetworkCategory)
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Print
// ---------------------------------------------------------------------------

func printOSReport(reports []*OSInterfaceReport, winErr error) {
	fmt.Println("OS Network Status Report")
	fmt.Println(strings.Repeat("=", 72))
	if runtime.GOOS == "windows" && winErr != nil {
		fmt.Printf("(Could not determine Windows network categories: %v)\n", winErr)
	}

	for _, r := range reports {
		status := "DOWN"
		if r.Up {
			status = "UP"
		}
		kind := ""
		if r.Loopback {
			kind = " (loopback)"
		}
		fmt.Printf("\nInterface: %s%s [%s]\n", r.Name, kind, status)
		fmt.Printf("  Index:       %d\n", r.Index)
		if r.MAC != "" {
			fmt.Printf("  MAC:         %s\n", r.MAC)
		}
		fmt.Printf("  MTU:         %d\n", r.MTU)
		if runtime.GOOS == "windows" {
			cat := r.WindowsCategory
			if cat == "" {
				cat = "N/A (no active network profile - interface may be disconnected, disabled, or has no IP connectivity)"
			}
			fmt.Printf("  Windows network category: %s\n", cat)
		}

		if len(r.Addresses) == 0 {
			fmt.Println("  IPv4 addresses: none")
			continue
		}
		for _, a := range r.Addresses {
			note := ""
			if a.Note != "" {
				note = " [" + a.Note + "]"
			}
			fmt.Printf("  IPv4 address: %s%s\n", a.CIDR, note)
			fmt.Printf("    Subnet mask:        %s\n", a.SubnetMask)
			fmt.Printf("    Network / Broadcast: %s / %s\n", a.NetworkAddress, a.BroadcastAddress)
			fmt.Printf("    Full address range:  %s  (%s addresses total)\n", a.FullRange, commaUint64(a.TotalAddresses))
			fmt.Printf("    Usable host range:   %s  (%s usable host addresses)\n", a.UsableRange, commaUint64(a.UsableAddresses))
		}
	}
	fmt.Println()
}
