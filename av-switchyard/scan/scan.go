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

    if !noOSReport {
        printOSReport(osReports, winErr)
    }
    if len(ifaces) == 0 {
        fmt.Fprintln(os.Stderr, "no eligible IPv4 network interfaces found for Art-Net scanning")
        os.Exit(1)
    }
    printTextReport(artnetReports)
    printPortScanReport(portScanReports)

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
    OSInterfaces []*OSInterfaceReport  `json:"os_interfaces"`
    ArtNetScan   []*InterfaceReport    `json:"artnet_scan"`
    PortScan     []*SubnetScanReport   `json:"port_scan,omitempty"`
}

// ---------------------------------------------------------------------------
// Port scan types
// ---------------------------------------------------------------------------

// portDef names one well-known port used by AV / broadcast equipment.
// Protocol is the primary transport; every port is also probed via TCP.
type portDef struct {
    Port     int
    Protocol string // "tcp" or "udp" — informational; TCP connect is always used
    Service  string
}

// OpenPort is one confirmed-open TCP port found during a host scan.
type OpenPort struct {
    Port    int    `json:"port"`
    Service string `json:"service"`
}

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

// avServicePorts is the ~200-entry catalogue of ports commonly found on AV and
// broadcast equipment.  UDP-primary entries are noted as such and are still
// probed via TCP so that devices sharing a port number on both transports are
// detected without requiring raw-socket privileges.
var avServicePorts = []portDef{
    // ── Standard infrastructure ───────────────────────────────────────────
    {21,    "tcp", "FTP"},
    {22,    "tcp", "SSH"},
    {23,    "tcp", "Telnet"},
    {25,    "tcp", "SMTP"},
    {53,    "tcp", "DNS"},
    {80,    "tcp", "HTTP"},
    {110,   "tcp", "POP3"},
    {111,   "tcp", "RPC-Portmapper"},
    {123,   "udp", "NTP"},
    {135,   "tcp", "MS-RPC"},
    {139,   "tcp", "NetBIOS-SSN"},
    {143,   "tcp", "IMAP"},
    {161,   "udp", "SNMP"},
    {162,   "udp", "SNMP-Trap"},
    {389,   "tcp", "LDAP"},
    {427,   "udp", "SLP"},
    {443,   "tcp", "HTTPS"},
    {445,   "tcp", "SMB"},
    {500,   "udp", "IKE-ISAKMP"},
    {502,   "tcp", "Modbus-TCP"},
    {514,   "udp", "Syslog"},
    {520,   "udp", "RIPv1"},
    {548,   "tcp", "AFP"},
    {554,   "tcp", "RTSP"},
    {623,   "udp", "IPMI-RMCP"},
    {3306,  "tcp", "MySQL"},
    {3389,  "tcp", "RDP"},
    {5432,  "tcp", "PostgreSQL"},
    {5900,  "tcp", "VNC"},
    {5901,  "tcp", "VNC-Display1"},
    {5902,  "tcp", "VNC-Display2"},
    // ── IEEE 1588 Precision Time Protocol ────────────────────────────────
    {179,   "tcp", "BGP"},
    {319,   "udp", "PTP-Event-IEEE1588"},
    {320,   "udp", "PTP-General-IEEE1588"},
    // ── AV lighting / DMX / stage control ────────────────────────────────
    {1024,  "tcp", "ShowXpress"},
    {2323,  "tcp", "Pharos-Telnet"},
    {2430,  "tcp", "Pharos"},
    {3000,  "tcp", "Pharos-Alt"},
    {3007,  "udp", "ESP-Net-DMX"},
    {3030,  "tcp", "Adamson-Blueprint"},
    {3032,  "tcp", "ETC-EOS"},
    {3033,  "udp", "ETC-EOS-OSC"},
    {3034,  "tcp", "ETC-EOS-Alt"},
    {3036,  "udp", "ETC-EOS-OSC-Alt"},
    {3037,  "tcp", "ETC-EOS-TCP-Alt"},
    {3039,  "tcp", "Dataton-WATCHOUT"},
    {3040,  "tcp", "WATCHOUT-Alt"},
    {3197,  "tcp", "MADRIX"},
    {3333,  "tcp", "ENTTEC-ODE"},
    {3938,  "tcp", "MA-Net3-Alt"},
    {4543,  "tcp", "Pharos-Designer-Alt"},
    {4703,  "tcp", "Avolites-TitanNet"},
    {5401,  "tcp", "disguise-d3"},
    {5568,  "udp", "sACN-E1.31"},
    {6038,  "tcp", "grandMA3-Remote"},
    {6160,  "tcp", "Hippotizer"},
    {6200,  "tcp", "Martin-M-PC"},
    {6454,  "udp", "Art-Net"},
    {6549,  "tcp", "grandMA-Net"},
    {6553,  "tcp", "ChamSys-MagicQ"},
    {6600,  "tcp", "Pathport"},
    {6699,  "tcp", "grandMA3"},
    {6790,  "tcp", "Pharos-Designer"},
    {7600,  "tcp", "Pandoras-Box"},
    {8595,  "tcp", "grandMA-Web"},
    {9090,  "tcp", "OLA-Web"},
    {9119,  "tcp", "Chauvet-LuminAir"},
    {9898,  "tcp", "WATCHOUT-Display"},
    {9999,  "tcp", "QLC+"},
    {38423, "tcp", "Unreal-nDisplay"},
    {57120, "tcp", "SuperCollider-OSC"},
    // ── OSC / generic AV control ──────────────────────────────────────────
    {1234,  "tcp", "VLC-QLC+"},
    {7000,  "tcp", "Resolume-OSC"},
    {8000,  "tcp", "OSC-Generic"},
    {9000,  "tcp", "SRT-OSC-Christie"},
    // ── Dante / AES67 audio networking ───────────────────────────────────
    {4440,  "udp", "Dante-ARC"},
    {4455,  "udp", "Dante-ARC-Alt"},
    {5004,  "udp", "RTP-AES67"},
    {5005,  "udp", "RTCP"},
    {8700,  "udp", "Dante-Controller"},
    {8701,  "udp", "Dante-Controller-Alt"},
    {8702,  "udp", "Dante-Controller-Alt2"},
    {8703,  "udp", "Dante-Controller-Alt3"},
    {14336, "udp", "Dante-Audio"},
    {14337, "udp", "Dante-Audio-Alt"},
    {51000, "udp", "Dante-Discovery"},
    // ── NDI (NewTek Network Device Interface) ─────────────────────────────
    {5353,  "udp", "mDNS-Bonjour"},
    {5355,  "udp", "LLMNR"},
    {5959,  "tcp", "NDI-Discovery"},
    {5960,  "tcp", "NDI-Video"},
    {5961,  "tcp", "NDI-Video-Alt"},
    {5962,  "tcp", "NDI-Audio"},
    {5963,  "tcp", "NDI-Meta"},
    // ── NMOS / AMWA IS-04/05/06 ───────────────────────────────────────────
    {3211,  "tcp", "NMOS-IS04-Reg"},
    {3212,  "tcp", "NMOS-IS05"},
    {3213,  "tcp", "NMOS-IS06"},
    // ── Video streaming / broadcast ───────────────────────────────────────
    {1720,  "tcp", "H.323-Ctrl"},
    {1793,  "udp", "EtherSound"},
    {1794,  "udp", "sACN-Unicast"},
    {1900,  "udp", "SSDP-UPnP"},
    {1935,  "tcp", "RTMP"},
    {3478,  "udp", "STUN-TURN"},
    {3479,  "udp", "STUN-Alt"},
    {3702,  "udp", "WSD"},
    {6100,  "tcp", "Vizrt-Engine"},
    {8092,  "tcp", "Ross-Xpression"},
    {8554,  "tcp", "RTSP-Alt"},
    {32400, "tcp", "Plex-Media"},
    {51400, "tcp", "Plex-DLNA"},
    // ── AV control systems ────────────────────────────────────────────────
    {1319,  "tcp", "AMX-ICSP"},
    {1702,  "tcp", "QSC-Q-SYS"},
    {1710,  "tcp", "QSC-Q-SYS-Alt"},
    {1718,  "udp", "AMX-Beacon"},
    {1883,  "tcp", "MQTT"},
    {1902,  "udp", "SDDP"},
    {2001,  "tcp", "Extron-SIS"},
    {2050,  "tcp", "GrassValley-GVOrbit"},
    {2101,  "tcp", "dB-ArrayCalc"},
    {3283,  "tcp", "Apple-ARD"},
    {3671,  "udp", "KNX-EIBnet"},
    {4352,  "tcp", "PJLink"},
    {4840,  "tcp", "OPC-UA"},
    {4999,  "tcp", "AMX-ICSP-Alt"},
    {5000,  "tcp", "Pathway-Kramer-AJA"},
    {5001,  "tcp", "RGB-Spectrum"},
    {5678,  "tcp", "Ventuz"},
    {6107,  "tcp", "Lightware-LW2"},
    {7142,  "tcp", "TV-One"},
    {7474,  "tcp", "ATEN-Web"},
    {7788,  "tcp", "Ross-Video"},
    {8880,  "tcp", "L-ISA"},
    {9001,  "tcp", "Riedel-MediorNet"},
    {9600,  "tcp", "Calrec-Brio"},
    {9993,  "tcp", "Blackmagic-Videohub"},
    {10001, "tcp", "Biamp-Lightware"},
    {10002, "tcp", "BSS-London"},
    {10003, "tcp", "BSS-London-Alt"},
    {10010, "tcp", "Catalyst-Media"},
    {41794, "tcp", "Crestron-CIP"},
    {41796, "tcp", "Crestron-CIP-Secure"},
    {47808, "udp", "BACnet-IP"},
    // ── Displays / projectors ─────────────────────────────────────────────
    {3629,  "tcp", "Epson-Projector"},
    {9110,  "tcp", "Epson-Projector-Net"},
    // ── Yamaha / DJ equipment / music production ──────────────────────────
    {49280, "tcp", "Yamaha-SCP"},
    {50000, "tcp", "Yamaha-MC-ProDJLink"},
    {50001, "tcp", "ProDJLink"},
    {50002, "tcp", "ProDJLink-Alt"},
    // ── Blackmagic Design / AJA ───────────────────────────────────────────
    {7770,  "tcp", "AJA-KiPro"},
    {52381, "tcp", "Blackmagic-ATEM"},
    // ── Network audio production ──────────────────────────────────────────
    {1400,  "tcp", "Sonos"},
    {2048,  "udp", "DigiNet"},
    {3689,  "tcp", "DAAP-iTunes"},
    {4001,  "tcp", "Luminex-GigaCore"},
    {4004,  "tcp", "Luminex-Alt"},
    {4569,  "udp", "IAX2-VoIP"},
    {5060,  "tcp", "SIP"},
    {5061,  "tcp", "SIP-TLS"},
    {8001,  "tcp", "SSL-Network"},
    {8088,  "tcp", "Waves-Server"},
    {49000, "tcp", "Sonos-Discovery"},
    {51325, "tcp", "Allen-Heath-SQ"},
    // ── Remote access / admin ────────────────────────────────────────────
    {2222,  "tcp", "SSH-Alt"},
    {5555,  "tcp", "ADB-Generic"},
    {5938,  "tcp", "TeamViewer"},
    {7070,  "tcp", "AnyDesk"},
    // ── HTTP / web management interfaces ─────────────────────────────────
    {8008,  "tcp", "Chromecast-HTTP"},
    {8080,  "tcp", "HTTP-Alt"},
    {8081,  "tcp", "HTTP-Alt"},
    {8096,  "tcp", "Jellyfin-Emby"},
    {8099,  "tcp", "ArKaos-MediaMaster"},
    {8180,  "tcp", "HTTP-Alt"},
    {8181,  "tcp", "HTTP-Alt"},
    {8443,  "tcp", "HTTPS-Alt"},
    {7443,  "tcp", "HTTPS-Alt"},
    {8888,  "tcp", "HTTP-Alt"},
    {8920,  "tcp", "Jellyfin-TLS"},
    {9002,  "tcp", "HTTP-Alt"},
    {9003,  "tcp", "HTTP-Alt"},
    {9100,  "tcp", "RAW-Print"},
    {9030,  "tcp", "NMOS-Alt"},
    {10080, "tcp", "HTTP-Alt"},
    {10100, "tcp", "HTTP-Alt"},
    // ── Miscellaneous AV / generic ────────────────────────────────────────
    {4000,  "tcp", "Clear-Com"},
    {4444,  "tcp", "Generic-Control"},
    {4500,  "udp", "IPsec-NAT-T"},
    {4789,  "udp", "VXLAN"},
    {4800,  "tcp", "Pixera-Generic"},
    {5100,  "tcp", "HTTP-Alt"},
    {5200,  "tcp", "HTTP-Alt"},
    {5800,  "tcp", "VNC-HTTP"},
    {6000,  "tcp", "X11"},
    {6001,  "tcp", "X11-Display1"},
    {6633,  "tcp", "OpenFlow"},
    {6666,  "tcp", "Generic-AV"},
    {11000, "tcp", "Generic-AV"},
    {30010, "tcp", "Pixera-Alt"},
    {38000, "tcp", "Pixera-Server"},
    {49152, "tcp", "UPnP-Dynamic"},
}

// tcpScanPorts is the deduplicated, sorted list of TCP port numbers derived
// from avServicePorts.  Built once at init time.
var tcpScanPorts []int

// portServiceName maps port number → service label from avServicePorts.
var portServiceName map[int]string

func init() {
    portServiceName = make(map[int]string, len(avServicePorts))
    seenName := make(map[int]bool, len(avServicePorts))
    seenTCP := make(map[int]bool, len(avServicePorts))
    for _, pd := range avServicePorts {
        if !seenName[pd.Port] {
            seenName[pd.Port] = true
            portServiceName[pd.Port] = pd.Service
        }
        // Only TCP-scan ports marked "tcp". Pure-UDP ports (Art-Net, sACN,
        // Dante, mDNS…) would produce false-positives because net.DialTimeout
        // on UDP always "connects" — UDP has no handshake to refuse.
        if pd.Protocol == "tcp" && !seenTCP[pd.Port] {
            seenTCP[pd.Port] = true
            tcpScanPorts = append(tcpScanPorts, pd.Port)
        }
    }
    sort.Ints(tcpScanPorts)
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

// ---------------------------------------------------------------------------
// Port scan implementation
// ---------------------------------------------------------------------------

const (
    portScanWorkers    = 1024           // max concurrent TCP dial goroutines
    portScanConnTimeout = 300 * time.Millisecond
    portScanMaxHosts   = 2048           // guard against accidentally scanning huge subnets
)

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

// portScanSubnet probes every host in ni's subnet via TCP connect on all
// ports listed in avServicePorts.  It returns a SubnetScanReport with the
// live hosts and their open ports.
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
    if len(hosts) > portScanMaxHosts {
        r.Note = fmt.Sprintf("subnet has %d hosts; scanning first %d only", len(hosts), portScanMaxHosts)
        hosts = hosts[:portScanMaxHosts]
    }

    type hit struct {
        ip   string
        port int
    }

    hits := make(chan hit, 4096)
    sem := make(chan struct{}, portScanWorkers)
    var wg sync.WaitGroup

    for _, ip := range hosts {
        ipStr := ip.String()
        for _, port := range tcpScanPorts {
            wg.Add(1)
            go func(ipStr string, port int) {
                defer wg.Done()
                sem <- struct{}{}
                defer func() { <-sem }()
                conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ipStr, port), connTimeout)
                if err == nil {
                    conn.Close()
                    hits <- hit{ipStr, port}
                }
            }(ipStr, port)
        }
    }

    go func() {
        wg.Wait()
        close(hits)
    }()

    hostMap := make(map[string][]OpenPort)
    for h := range hits {
        hostMap[h.ip] = append(hostMap[h.ip], OpenPort{
            Port:    h.port,
            Service: portServiceName[h.port],
        })
    }

    // Resolve MACs from the OS ARP cache (populated as a side-effect of TCP connects).
    arpTable := readARPTable()

    for ip, ports := range hostMap {
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

func printPortScanReport(reports []*SubnetScanReport) {
    totalHosts := 0
    for _, r := range reports {
        totalHosts += len(r.Hosts)
    }
    fmt.Printf("\nPort Scan Report (%d TCP ports probed, %d ports catalogued): %d live host(s) across %d interface(s)\n",
        len(tcpScanPorts), len(avServicePorts), totalHosts, len(reports))
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
                    // Surface the declared protocol for informational context.
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

