package cli

import (
//    "fmt"
//    "log"
//    "net"

//    "github.com/alecthomas/kong"
//    "github.com/jsimonetti/go-artnet/packet"
)

type CLI struct {
    Verbose bool `help:"Enable verbose logging."`

    Config string `help:"Configuration file." default:"config.yaml"`

    Listen string `help:"Address to listen on." default:":9000"`

    RunDaemon RunCmd `cmd:"" help:"Run the bridge daemon."`

    Version VersionCmd `cmd:"" help:"Print version information."`

    // Injected by main, to allow cli -> daemon calls without violating Go's strict DAG compilation design.
    Func_RunDaemon func(*CLI) error `kong:"-"`
}

type RunCmd struct {
    ArtNet bool `help:"Enable Art-Net."`

    SACN bool `help:"Enable sACN."`

    Universe int `help:"Universe number." default:"1"`

    DryRun bool `help:"Don't send any network traffic."`
}

type VersionCmd struct{}

