package scan

// Scan result printing — scan plan (duration estimate) and port scan report.

import (
	"fmt"
	"strings"
	"time"
)

// printScanPlan prints the per-interface strategy and estimated duration
// before scans start, so the operator knows what to expect on large networks.
func printScanPlan(ifaces []netInfo, opts ScanOptions) {
	fmt.Println("Scan Strategy & Estimated Duration")
	fmt.Println(strings.Repeat("=", 72))

	var maxEst time.Duration
	for _, ni := range ifaces {
		hosts := subnetHosts(ni)
		n := len(hosts)
		if n > maxScanHosts {
			n = maxScanHosts
		}

		var est time.Duration
		var strategy string

		if n <= discoverPhaseSmallMax {
			// Full scan of all hosts.
			tcpBatches := ceilDiv(n*len(tcpScanPorts), opts.Workers)
			tcpTime := time.Duration(tcpBatches) * opts.PortTimeout
			est = tcpTime
			if udpDiscoveryTimeout > est {
				est = udpDiscoveryTimeout
			}
			strategy = "full scan"
		} else {
			// Two-phase: discovery then port-scan live hosts.
			discBatches := ceilDiv(n*len(quickDiscoveryPorts), opts.Workers)
			discTime := time.Duration(discBatches) * opts.DiscoverTimeout
			if opts.ArpWait > discTime {
				discTime = opts.ArpWait
			}
			// Assume ~5 % live hosts (conservative for AV networks).
			estLive := n / 20
			if estLive < 5 {
				estLive = 5
			}
			if estLive > 500 {
				estLive = 500
			}
			scanBatches := ceilDiv(estLive*len(tcpScanPorts), opts.Workers)
			scanTime := time.Duration(scanBatches) * opts.PortTimeout
			if udpDiscoveryTimeout > scanTime {
				scanTime = udpDiscoveryTimeout
			}
			est = discTime + scanTime + 2*time.Second
			strategy = fmt.Sprintf("two-phase (ARP+TCP discover → ~%d live)", estLive)
		}
		est += 2 * time.Second // overhead

		fmt.Printf("  %-22s  %-26s  %8s hosts  %-38s  ~%s\n",
			ni.Name,
			ni.IPNet.String(),
			commaUint64(uint64(n)),
			strategy,
			roundDuration(est))

		if est > maxEst {
			maxEst = est
		}
	}

	if len(ifaces) > 1 {
		fmt.Printf("\n  Total (interfaces run in parallel): ~%s\n", roundDuration(maxEst))
	}
	fmt.Println()
}

// ceilDiv returns ⌈a/b⌉ using integer arithmetic.
func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

// roundDuration formats d as a human-friendly string.
func roundDuration(d time.Duration) string {
	switch {
	case d < 30*time.Second:
		return fmt.Sprintf("%ds", int(d.Seconds()+0.5))
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < 10*time.Minute:
		return fmt.Sprintf("%.1f min", d.Minutes())
	default:
		return fmt.Sprintf("%.0f min", d.Minutes())
	}
}

func printPortScanReport(reports []*SubnetScanReport) {
	totalHosts := 0
	for _, r := range reports {
		totalHosts += len(r.Hosts)
	}
	fmt.Printf("\nPort Scan Report (%d TCP ports + UDP probes [mDNS/SSDP/SNMP/NTP]): %d live host(s) across %d interface(s)\n",
		len(tcpScanPorts), totalHosts, len(reports))
	fmt.Println(strings.Repeat("=", 72))

	for _, r := range reports {
		fmt.Printf("\nInterface: %s  subnet %s\n", r.Interface, r.Subnet)
		if r.Note != "" {
			fmt.Printf("  Note: %s\n", r.Note)
		}
		if r.Error != "" {
			fmt.Printf("  Error: %s\n", r.Error)
			continue
		}
		if len(r.Hosts) == 0 {
			fmt.Println("  No responsive hosts found.")
			continue
		}

		for _, h := range r.Hosts {
			fmt.Println("  " + strings.Repeat("-", 68))
			mac := h.MAC
			if mac == "" {
				mac = "(MAC unavailable)"
			}
			host := h.Hostname
			if host == "" {
				host = "(no reverse DNS)"
			}
			fmt.Printf("  Host:     %s\n", h.IP)
			fmt.Printf("  MAC:      %s\n", mac)
			fmt.Printf("  Hostname: %s\n", host)
			if len(h.OpenPorts) == 0 {
				fmt.Println("  Ports:    none open")
			} else {
				fmt.Printf("  Open ports (%d):\n", len(h.OpenPorts))
				for _, p := range h.OpenPorts {
					svc := p.Service
					proto := "tcp"
					for _, pd := range avServicePorts {
						if pd.Port == p.Port {
							proto = pd.Protocol
							break
						}
					}
					fmt.Printf("    %5d/%-3s  %s\n", p.Port, proto, svc)
				}
			}
		}
	}
	fmt.Println()
}
