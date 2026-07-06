package cli

import (
//    "fmt"
//    "log"
//    "net"

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

    // Flags used by all all subcommands
    Verbose bool `help:"command: All. Enable verbose logging."`

    // Injected by main, to allow cli -> daemon calls without violating Go's strict DAG compilation design.
    Func_RunDaemon  func(*CLI) error `kong:"-"`
    Func_RunUpgrade func(*CLI) error `kong:"-"`
    Func_RunScan    func(*CLI) error `kong:"-"`
    Func_RunUSBScan func(*CLI) error `kong:"-"`
}

