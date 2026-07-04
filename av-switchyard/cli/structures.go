package cli

import (
//    "fmt"
//    "log"
//    "net"

//    "github.com/alecthomas/kong"
//    "github.com/jsimonetti/go-artnet/packet"
)

const SupportedSubcommandNames = "daemon, upgrade, scan"

type CLI struct {
    Command string `arg:"" optional:"" help:"subcommand to run, defaults to 'daemon'"`

    Verbose bool `help:"Enable verbose logging."`

    Config string `help:"Configuration file." default:"config.yaml"`

    // Injected by main, to allow cli -> daemon calls without violating Go's strict DAG compilation design.
    Func_RunDaemon func(*CLI) error `kong:"-"`
}

