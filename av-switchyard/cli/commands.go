package cli

import (
    "fmt"
//    "log"
//    "net"

//    "github.com/alecthomas/kong"
//    "github.com/jsimonetti/go-artnet/packet"

    "av-switchyard/version"
)

// func (r *RunCmd) Run(cli *CLI) error {
//     fmt.Println("Running...")

//     fmt.Printf("Verbose:  %v\n", cli.Verbose)
//     fmt.Printf("Config:   %s\n", cli.Config)

//     fmt.Printf("ArtNet:   %v\n", r.ArtNet)
//     fmt.Printf("sACN:     %v\n", r.SACN)
//     fmt.Printf("Universe: %d\n", r.Universe)
//     fmt.Printf("DryRun:   %v\n", r.DryRun)

//     // This is daemon.RunDaemon, but Go's import system forces a function pointer.
//     cli.Func_RunDaemon(cli)

//     return nil
// }

// func (v *VersionCmd) Run() error {
//     fmt.Println("switchyard 1.0.0")
//     return nil
// }

func (c *CLI) Run() error {
    switch c.Command {
        case "", "daemon", "run-daemon":
            return c.Func_RunDaemon(c)

        case "version":
            fmt.Println(version.VersionString())
            return nil

        default:
            return fmt.Errorf("unknown command: %s\nSupported commands are: %s", c.Command, SupportedSubcommandNames)
    }
    return nil
}
