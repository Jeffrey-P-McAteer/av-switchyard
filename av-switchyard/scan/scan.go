package scan

// Package scan implements the "scan" sub-command.  It discovers Art-Net nodes
// via broadcast ArtPoll, probes hosts for open TCP ports and UDP services, and
// reports OS network interface details.
//
// File layout:
//   scan.go       — entry point (RunScan) and top-level JSON envelope
//   os_report.go  — OS NIC enumeration and printOSReport
//   artnet.go     — Art-Net discovery (ArtPoll / ArtPollReply)
//   ports.go      — AV service port catalogue and derived TCP scan list
//   port_scan.go  — subnet scanning, host discovery, ARP table
//   report.go     — printScanPlan and printPortScanReport
//   udp_probe.go  — UDP service probes (mDNS, SSDP, SNMP, NTP)

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"av-switchyard/cli"
)

// FullReport is the top-level JSON envelope combining all report types.
type FullReport struct {
	OSInterfaces []*OSInterfaceReport `json:"os_interfaces"`
	ArtNetScan   []*InterfaceReport   `json:"artnet_scan"`
	PortScan     []*SubnetScanReport  `json:"port_scan,omitempty"`
}

// RunScan is the entry point for the "scan" sub-command.
func RunScan(c *cli.CLI) error {
	log.Printf("config file: %v\n", c.ConfigFile)

	var (
		timeout    = 5 * time.Second
		ifaceName  = ""
		asJSON     = false
		noDNS      = false
		noOSReport = false
	)

	var (
		osReports []*OSInterfaceReport
		winErr    error
	)
	if !noOSReport {
		var err error
		osReports, err = buildOSInterfaceReports(ifaceName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error enumerating interfaces:", err)
			os.Exit(1)
		}

		if runtime.GOOS == "windows" {
			cats, err := getWindowsNetworkCategories()
			winErr = err
			if err == nil {
				for _, r := range osReports {
					if cat, ok := cats[r.Name]; ok {
						r.WindowsCategory = cat
					}
				}
			}
		}
	}

	ifaces, err := eligibleInterfaces(ifaceName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error enumerating interfaces:", err)
		os.Exit(1)
	}

	// ── Print OS NIC report + scan plan immediately, before blocking on scans ─
	if !asJSON {
		if !noOSReport {
			printOSReport(osReports, winErr)
		}
		if len(ifaces) == 0 {
			fmt.Fprintln(os.Stderr, "no eligible IPv4 network interfaces found for scanning")
			os.Exit(1)
		}
		printScanPlan(ifaces)
	}

	var (
		wg              sync.WaitGroup
		mu              sync.Mutex
		artnetReports   []*InterfaceReport
		portScanReports []*SubnetScanReport
	)

	for _, ni := range ifaces {
		wg.Add(2)
		go func(ni netInfo) {
			defer wg.Done()
			r := scanInterface(ni, timeout)
			if !noDNS {
				resolveHostnames(r.Nodes)
			}
			mu.Lock()
			artnetReports = append(artnetReports, r)
			mu.Unlock()
		}(ni)
		go func(ni netInfo) {
			defer wg.Done()
			r := portScanSubnet(ni, portScanConnTimeout)
			if !noDNS {
				resolvePortScanHostnames(r.Hosts)
			}
			mu.Lock()
			portScanReports = append(portScanReports, r)
			mu.Unlock()
		}(ni)
	}
	wg.Wait()

	sort.Slice(artnetReports, func(i, j int) bool { return artnetReports[i].Name < artnetReports[j].Name })
	sort.Slice(portScanReports, func(i, j int) bool { return portScanReports[i].Interface < portScanReports[j].Interface })

	if asJSON {
		full := FullReport{OSInterfaces: osReports, ArtNetScan: artnetReports, PortScan: portScanReports}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(full); err != nil {
			fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
			os.Exit(1)
		}
		return nil
	}

	printTextReport(artnetReports)
	printPortScanReport(portScanReports)

	return nil
}
