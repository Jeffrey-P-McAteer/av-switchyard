package scan

import (
    "log"
    "context"
    "encoding/json"
    //"flag"
    "fmt"
    "net"
    "os"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/jsimonetti/go-artnet/packet"
    "github.com/jsimonetti/go-artnet/packet/code"

    "av-switchyard/cli"
)

func RunScan(c *cli.CLI) error {
    log.Printf("config file: %v\n", c.ConfigFile)

    // var (
    //     timeout   = flag.Duration("timeout", 3*time.Second, "how long to listen for ArtPollReply on each interface")
    //     ifaceName = flag.String("iface", "", "only scan this interface name (default: scan all eligible interfaces)")
    //     asJSON    = flag.Bool("json", false, "emit machine-readable JSON instead of a text report")
    //     noDNS     = flag.Bool("no-reverse-dns", false, "skip reverse DNS lookups for discovered IPs")
    // )
    // flag.Parse()

    timeout   := 3*time.Second
    ifaceName := ""
    asJSON    := false
    wantResolveHostnames := true

    ifaces, err := eligibleInterfaces(ifaceName)
    if err != nil {
        fmt.Fprintln(os.Stderr, "error enumerating interfaces:", err)
        os.Exit(1)
    }
    if len(ifaces) == 0 {
        fmt.Fprintln(os.Stderr, "no eligible IPv4 network interfaces found")
        os.Exit(1)
    }

    var (
        wg      sync.WaitGroup
        mu      sync.Mutex
        reports []*InterfaceReport
    )

    for _, ni := range ifaces {
        wg.Add(1)
        go func(ni netInfo) {
            defer wg.Done()
            r := scanInterface(ni, timeout)
            if wantResolveHostnames {
                resolveHostnames(r.Nodes)
            }
            mu.Lock()
            reports = append(reports, r)
            mu.Unlock()
        }(ni)
    }
    wg.Wait()

    sort.Slice(reports, func(i, j int) bool { return reports[i].Name < reports[j].Name })

    if asJSON {
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(reports); err != nil {
            fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
            os.Exit(1)
        }
        return nil
    }

    printTextReport(reports)

    return nil
}


// ArtNetPort is the well-known UDP port for Art-Net traffic.
const ArtNetPort = 6454

// PortInfo describes one DMX512 input or output port on a discovered node.
type PortInfo struct {
    Index     int    `json:"index"`
    Direction string `json:"direction"` // "input" or "output"
    Protocol  string `json:"protocol"`  // e.g. DMX512, Art-Net, MIDI...
    Universe  int    `json:"universe"`  // full 15-bit Port-Address (Net/Sub-Net/Universe combined)
    Net       uint8  `json:"net"`
    SubNet    uint8  `json:"sub_net"`
    SwOffset  uint8  `json:"sw_offset"`
    Status    string `json:"status"`
}

// Node describes one discovered Art-Net device.
type Node struct {
    IP           string     `json:"ip"`
    Hostname     string     `json:"hostname,omitempty"`
    MAC          string     `json:"mac"`
    ShortName    string     `json:"short_name"`
    LongName     string     `json:"long_name"`
    NodeReport   string     `json:"node_report,omitempty"`
    Manufacturer string     `json:"manufacturer,omitempty"`
    OEM          uint16     `json:"oem"`
    Style        string     `json:"style"` // Node, Controller, Media Server, Route, Backup, Config, Visualiser
    FirmwareVer  uint16     `json:"firmware_version"`
    BindIndex    uint8      `json:"bind_index"`
    NetSwitch    uint8      `json:"net_switch"`
    SubSwitch    uint8      `json:"sub_switch"`
    Ports        []PortInfo `json:"ports"`
    SeenOnIface  string     `json:"seen_on_interface"`
    LastSeen     time.Time  `json:"last_seen"`
}

// InterfaceReport groups discovery results per local NIC.
type InterfaceReport struct {
    Name      string  `json:"name"`
    LocalIPv4 string  `json:"local_ipv4"`
    LocalMAC  string  `json:"local_mac"`
    Broadcast string  `json:"broadcast"`
    Error     string  `json:"error,omitempty"`
    Nodes     []*Node `json:"nodes"`
}

// netInfo is the subset of interface data needed to run a scan.
type netInfo struct {
    Name      string
    HWAddr    net.HardwareAddr
    IP        net.IP
    IPNet     *net.IPNet
    Broadcast net.IP
}

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

// scanInterface binds to the given interface's IPv4 address, broadcasts an
// ArtPoll, and collects replies until timeout expires.
func scanInterface(ni netInfo, timeout time.Duration) *InterfaceReport {
    report := &InterfaceReport{
        Name:      ni.Name,
        LocalIPv4: ni.IP.String(),
        LocalMAC:  hwString(ni.HWAddr),
        Broadcast: ni.Broadcast.String(),
    }

    localAddr := &net.UDPAddr{IP: ni.IP, Port: ArtNetPort}
    conn, err := net.ListenUDP("udp4", localAddr)
    if err != nil {
        // Port 6454 may already be held by another Art-Net node/app on this
        // host; fall back to an ephemeral port so we can still discover
        // devices, just without being able to run as a full node ourselves.
        localAddr.Port = 0
        conn, err = net.ListenUDP("udp4", localAddr)
        if err != nil {
            report.Error = fmt.Sprintf("bind failed: %v", err)
            return report
        }
    }
    defer conn.Close()

    pollBytes, err := buildArtPoll()
    if err != nil {
        report.Error = fmt.Sprintf("failed to build ArtPoll: %v", err)
        return report
    }

    dst := &net.UDPAddr{IP: ni.Broadcast, Port: ArtNetPort}
    if _, err := conn.WriteToUDP(pollBytes, dst); err != nil {
        report.Error = fmt.Sprintf("failed to send ArtPoll on %s: %v", ni.Name, err)
        return report
    }

    deadline := time.Now().Add(timeout)
    conn.SetReadDeadline(deadline)

    nodesBySrc := map[string]*Node{}
    buf := make([]byte, 4096)
    for {
        if time.Now().After(deadline) {
            break
        }
        n, src, err := conn.ReadFromUDP(buf)
        if err != nil {
            // timeout or socket closed; stop listening
            break
        }

        p, err := packet.Unmarshal(buf[:n])
        if err != nil {
            continue // not a valid/known Art-Net packet, ignore
        }

        reply, ok := p.(*packet.ArtPollReplyPacket)
        if !ok {
            continue // we only care about poll replies for discovery
        }

        node := nodeFromReply(reply, ni.Name, src.IP)
        nodesBySrc[node.IP] = node // last reply wins; also de-dupes bound sub-nodes by IP
    }

    for _, n := range nodesBySrc {
        report.Nodes = append(report.Nodes, n)
    }
    sort.Slice(report.Nodes, func(i, j int) bool { return report.Nodes[i].IP < report.Nodes[j].IP })
    return report
}

// buildArtPoll constructs a standard ArtPoll packet requesting replies from
// every node/controller/media-server on the segment.
func buildArtPoll() ([]byte, error) {
    p := &packet.ArtPollPacket{
        TalkToMe: code.TalkToMe(0), // no auto-diagnostics, plain poll/reply behaviour
        Priority: code.DpAll,
    }
    return p.MarshalBinary()
}

// nodeFromReply converts a decoded ArtPollReplyPacket into our reporting Node type.
func nodeFromReply(r *packet.ArtPollReplyPacket, ifaceName string, srcIP net.IP) *Node {
    node := &Node{
        IP:           srcIP.String(),
        MAC:          hwString(net.HardwareAddr(r.Macaddress[:])),
        ShortName:    decodeCStr(r.ShortName[:]),
        LongName:     decodeCStr(r.LongName[:]),
        NodeReport:   decodeNodeReport(r.NodeReport[:]),
        Manufacturer: decodeCStr(r.ESTAmanufacturer[:]),
        OEM:          r.Oem,
        Style:        r.Style.String(),
        FirmwareVer:  r.VersionInfo,
        BindIndex:    r.BindIndex,
        NetSwitch:    r.NetSwitch,
        SubSwitch:    r.SubSwitch,
        SeenOnIface:  ifaceName,
        LastSeen:     time.Now(),
    }

    numPorts := int(r.NumPorts)
    if numPorts > 4 {
        numPorts = 4 // protocol caps ArtPollReply at 4 ports per packet
    }
    for i := 0; i < numPorts; i++ {
        pt := r.PortTypes[i]
        if pt.Input() {
            node.Ports = append(node.Ports, PortInfo{
                Index:     i,
                Direction: "input",
                Protocol:  pt.Type(),
                Net:       r.NetSwitch,
                SubNet:    r.SubSwitch,
                SwOffset:  r.SwIn[i],
                Universe:  universeAddress(r.NetSwitch, r.SubSwitch, r.SwIn[i]),
                Status:    fmt.Sprintf("%08b", uint8(r.GoodInput[i])),
            })
        }
        if pt.Output() {
            node.Ports = append(node.Ports, PortInfo{
                Index:     i,
                Direction: "output",
                Protocol:  pt.Type(),
                Net:       r.NetSwitch,
                SubNet:    r.SubSwitch,
                SwOffset:  r.SwOut[i],
                Universe:  universeAddress(r.NetSwitch, r.SubSwitch, r.SwOut[i]),
                Status:    fmt.Sprintf("%08b", uint8(r.GoodOutput[i])),
            })
        }
    }

    return node
}

// universeAddress combines Net (7 bit), Sub-Net (4 bit) and the per-port
// switch nibble into Art-Net's 15-bit Port-Address, and returns it as a
// plain integer universe number the way most consoles/media-servers display it.
func universeAddress(netSwitch, subSwitch, sw uint8) int {
    subUni := (subSwitch << 4) | (sw & 0x0f)
    return int(netSwitch)<<8 | int(subUni)
}

// resolveHostnames performs best-effort reverse DNS lookups for discovered nodes.
func resolveHostnames(nodes []*Node) {
    if len(nodes) == 0 {
        return
    }
    var wg sync.WaitGroup
    for _, n := range nodes {
        wg.Add(1)
        go func(n *Node) {
            defer wg.Done()
            ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
            defer cancel()
            names, err := net.DefaultResolver.LookupAddr(ctx, n.IP)
            if err == nil && len(names) > 0 {
                n.Hostname = strings.TrimSuffix(names[0], ".")
            }
        }(n)
    }
    wg.Wait()
}

func hwString(hw net.HardwareAddr) string {
    if len(hw) == 0 {
        return ""
    }
    return hw.String()
}

// decodeCStr trims a fixed-size, null-padded/null-terminated byte array down
// to its printable, null-terminated string content.
func decodeCStr(b []byte) string {
    if i := indexByte(b, 0); i >= 0 {
        b = b[:i]
    }
    return strings.TrimSpace(string(b))
}

func indexByte(b []byte, c byte) int {
    for i, v := range b {
        if v == c {
            return i
        }
    }
    return -1
}

// decodeNodeReport renders the NodeReport field (an array of NodeReportCode,
// which in practice carries an ASCII status string from the device) as text.
func decodeNodeReport(codes []code.NodeReportCode) string {
    b := make([]byte, 0, len(codes))
    for _, c := range codes {
        if c == 0 {
            break
        }
        b = append(b, byte(c))
    }
    return strings.TrimSpace(string(b))
}

func printTextReport(reports []*InterfaceReport) {
    total := 0
    for _, r := range reports {
        total += len(r.Nodes)
    }
    fmt.Printf("Art-Net scan complete: %d node(s) found across %d interface(s)\n", total, len(reports))
    fmt.Println(strings.Repeat("=", 72))

    for _, r := range reports {
        fmt.Printf("\nInterface: %s\n", r.Name)
        fmt.Printf("  Local IPv4:  %s\n", r.LocalIPv4)
        fmt.Printf("  Local MAC:   %s\n", r.LocalMAC)
        fmt.Printf("  Broadcast:   %s\n", r.Broadcast)
        if r.Error != "" {
            fmt.Printf("  Error:       %s\n", r.Error)
            continue
        }
        if len(r.Nodes) == 0 {
            fmt.Println("  No Art-Net devices responded on this interface.")
            continue
        }

        for _, n := range r.Nodes {
            fmt.Println("  " + strings.Repeat("-", 68))
            host := n.Hostname
            if host == "" {
                host = "(no reverse DNS)"
            }
            fmt.Printf("  Device:       %s / %s\n", n.ShortName, n.LongName)
            fmt.Printf("  IP:           %s\n", n.IP)
            fmt.Printf("  Hostname:     %s\n", host)
            fmt.Printf("  MAC:          %s\n", n.MAC)
            fmt.Printf("  Style:        %s\n", n.Style)
            if n.Manufacturer != "" {
                fmt.Printf("  Manufacturer: %s (OEM 0x%04X)\n", n.Manufacturer, n.OEM)
            }
            fmt.Printf("  Firmware:     %d\n", n.FirmwareVer)
            fmt.Printf("  Net/SubNet:   %d / %d (BindIndex %d)\n", n.NetSwitch, n.SubSwitch, n.BindIndex)
            if n.NodeReport != "" {
                fmt.Printf("  Node report:  %s\n", n.NodeReport)
            }
            if len(n.Ports) == 0 {
                fmt.Println("  Ports:        none reported")
            } else {
                fmt.Println("  Ports:")
                for _, p := range n.Ports {
                    fmt.Printf("    [%d] %-6s  protocol=%-8s universe=%-5d (net=%d sub=%d sw=%d) status=%s\n",
                        p.Index, p.Direction, p.Protocol, p.Universe, p.Net, p.SubNet, p.SwOffset, p.Status)
                }
            }
        }
    }
    fmt.Println()
}
