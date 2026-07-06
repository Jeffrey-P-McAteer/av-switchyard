package cli

import (
	"time"
//    "github.com/alecthomas/kong"
//    "github.com/jsimonetti/go-artnet/packet"
)

const SupportedSubcommandNames = "daemon, scan, usb-scan, test, version, upgrade"

type CLI struct {
    Command     string `arg:"" optional:"" help:"subcommand to run, defaults to 'daemon'"`

    // daemon flags

    // upgrade flags
    UpgradeVersion string `help:"command: upgrade. Instead of the most-recent version, upgrade to this specific version." default:""`

    // Flags used by 2+ subcommands
    ConfigFile string `help:"command: daemon, scan. Configuration file. If not specified and the environment variable AV_SWITCHYARD_CONFIG is set, we will use that as the default value." default:"av-switchyard.toml"`

    // Flags used by all subcommands
    Verbose bool `help:"command: All. Enable verbose logging."`

    // Scan tuning flags.  Defaults are conservative: thorough timeouts for
    // typical AV networks.  Use shorter values when scanning large (e.g. /16)
    // networks where speed matters more than catching the slowest devices.
    ScanDiscoverTimeout time.Duration `name:"discover-timeout" help:"command: scan. Per-connection timeout for the host-discovery probe phase (e.g. 100ms for speed, 4s for thoroughness)." default:"4s"`
    ScanPortTimeout     time.Duration `name:"port-timeout"     help:"command: scan. Per-connection timeout for the full TCP port scan (e.g. 300ms for speed, 2s for slow/sleepy devices)." default:"2s"`
    ScanArpWait         time.Duration `name:"arp-wait"         help:"command: scan. How long to wait for ARP replies after the ARP spray before reading the ARP cache." default:"1500ms"`
    ScanWorkers         int           `name:"workers"          help:"command: scan. Concurrent TCP goroutines. 0 = auto (subnet hosts/4, max 4098). Explicit values above 4098 are honoured." default:"0"`

    // ── test subcommand ───────────────────────────────────────────────────
    // Common
    TestIP       string        `name:"ip"       help:"command: test. Target device IPv4 address."`
    TestProtocol string        `name:"protocol" help:"command: test. Protocol: artnet, sacn, osc, pjlink." default:"artnet"`
    TestDuration time.Duration `name:"duration" help:"command: test. Hold duration (0 = send once; DMX fixtures need continuous data, e.g. 5s)." default:"0s"`
    TestInterval time.Duration `name:"interval" help:"command: test. Re-send interval while holding (only used when --duration > 0)." default:"100ms"`

    // DMX / Art-Net / sACN
    TestUniverse     int    `name:"universe"      help:"command: test. DMX universe (Art-Net 0–32767; sACN 1–63999)." default:"0"`
    TestChannels     string `name:"channels"      help:"command: test. DMX channel:value pairs, comma-separated. E.g. 1:255,2:0,3:128. Channels 1–512, values 0–255."`
    TestAll          int    `name:"all"           help:"command: test. Preset all 512 channels to this value before applying --channels. -1 = disabled." default:"-1"`
    TestSACNPriority int    `name:"sacn-priority" help:"command: test. sACN stream priority (0–200)." default:"100"`

    // OSC
    TestOSCPort    int     `name:"osc-port"    help:"command: test. UDP port for OSC." default:"8000"`
    TestOSCAddress string  `name:"osc-address" help:"command: test. OSC address string (e.g. /1/fader1)." default:"/1/test"`
    TestOSCType    string  `name:"osc-type"    help:"command: test. OSC argument type: f=float32, i=int32, s=string, none=no args." default:"f"`
    TestOSCFloat   float64 `name:"osc-float"   help:"command: test. Float argument (--osc-type=f)." default:"1.0"`
    TestOSCInt     int     `name:"osc-int"     help:"command: test. Integer argument (--osc-type=i)." default:"0"`
    TestOSCString  string  `name:"osc-string"  help:"command: test. String argument (--osc-type=s)."`

    // PJLink (TCP 4352, projectors and displays)
    TestPJLinkCmd string `name:"pjlink-cmd"      help:"command: test. PJLink command: POWR, INPT, AVMT, LAMP, CLSS." default:"POWR"`
    TestPJLinkArg string `name:"pjlink-arg"      help:"command: test. PJLink command argument (e.g. 1=on, 0=off, ?=query, 11=RGB1, 31=HDMI1)." default:"?"`
    TestPJLinkPwd string `name:"pjlink-password" help:"command: test. PJLink authentication password (empty = no auth)."`

    // Injected by main, to allow cli -> daemon calls without violating Go's strict DAG compilation design.
    Func_RunDaemon  func(*CLI) error `kong:"-"`
    Func_RunUpgrade func(*CLI) error `kong:"-"`
    Func_RunScan    func(*CLI) error `kong:"-"`
    Func_RunUSBScan func(*CLI) error `kong:"-"`
    Func_RunTest    func(*CLI) error `kong:"-"`
}

