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
    "runtime"
    "strconv"
    "os/exec"

    "github.com/jsimonetti/go-artnet/packet"
    "github.com/jsimonetti/go-artnet/packet/code"

    "av-switchyard/cli"
)

func RunScan(c *cli.CLI) error {
    log.Printf("config file: %v\n", c.ConfigFile)

    var (
        timeout    = 5*time.Second
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

    var (
        wg            sync.WaitGroup
        mu            sync.Mutex
        artnetReports []*InterfaceReport
    )

    for _, ni := range ifaces {
        wg.Add(1)
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
    }
    wg.Wait()

    sort.Slice(artnetReports, func(i, j int) bool { return artnetReports[i].Name < artnetReports[j].Name })

    if asJSON {
        full := FullReport{OSInterfaces: osReports, ArtNetScan: artnetReports}
        enc := json.NewEncoder(os.Stdout)
        enc.SetIndent("", "  ")
        if err := enc.Encode(full); err != nil {
            fmt.Fprintln(os.Stderr, "error encoding JSON:", err)
            os.Exit(1)
        }
        return nil
    }

    if !noOSReport {
        printOSReport(osReports, winErr)
    }
    if len(ifaces) == 0 {
        fmt.Fprintln(os.Stderr, "no eligible IPv4 network interfaces found for Art-Net scanning")
        os.Exit(1)
    }
    printTextReport(artnetReports)

    return nil
}


// ArtNetPort is the well-known UDP port for Art-Net traffic.
const ArtNetPort = 6454

// ---------------------------------------------------------------------------
// OS network status report
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
// Windows network category (Public / Private / Domain) lookup
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
// or Domain — each connected network is currently classified as. This is a
// best-effort call: interfaces with no active network connection (unplugged,
// disabled, or otherwise not IP-connected) will not appear in the result and
// are reported separately by the caller.
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

// ---------------------------------------------------------------------------
// Art-Net discovery
// ---------------------------------------------------------------------------

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

// FullReport is the top-level JSON envelope combining both report types.
type FullReport struct {
    OSInterfaces []*OSInterfaceReport `json:"os_interfaces"`
    ArtNetScan   []*InterfaceReport   `json:"artnet_scan"`
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
    fmt.Printf("Art-Net Discovery Report: %d node(s) found across %d interface(s)\n", total, len(reports))
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

