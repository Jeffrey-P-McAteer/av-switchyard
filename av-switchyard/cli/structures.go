package cli

import (
	"time"
//    "github.com/alecthomas/kong"
//    "github.com/jsimonetti/go-artnet/packet"
)

const SupportedSubcommandNames = "daemon, scan, usb-scan, version, upgrade"

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

    // Injected by main, to allow cli -> daemon calls without violating Go's strict DAG compilation design.
    Func_RunDaemon  func(*CLI) error `kong:"-"`
    Func_RunUpgrade func(*CLI) error `kong:"-"`
    Func_RunScan    func(*CLI) error `kong:"-"`
    Func_RunUSBScan func(*CLI) error `kong:"-"`
}

