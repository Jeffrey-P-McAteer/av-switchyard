package scan

// AV service port catalogue — the ~200-entry list of ports commonly found on
// AV and broadcast equipment, plus the derived TCP-only scan list built at
// startup.

import "sort"

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
