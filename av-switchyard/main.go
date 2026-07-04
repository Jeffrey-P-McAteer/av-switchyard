package main

import (
    "fmt"
    "log"
    "net"

    "github.com/alecthomas/kong"
    "github.com/jsimonetti/go-artnet/packet"
)

const (
    listenAddr     = "0.0.0.0:6454" // where we receive Art-Net from the console
    controllerAddr = "2.0.0.6:6454" // the fixture's Art-Net node
    listenNet      = uint8(0)       // Art-Net "Net" of the incoming universe
    listenSubUni   = uint8(3)       // Art-Net "SubUni" of the incoming universe
)

// fixtureGroup is one virtual RGBW fixture: 4 consecutive incoming DMX
// channels, fanned out (as GRBW) to every universe listed here.
type fixtureGroup struct {
    name    string
    subUnis []uint8 // destination SubUni per universe (Net assumed 0)
}

// groups mirrors ring_helper.py's A_INNER/A_OUTER/B_INNER/B_OUTER layout.
// Channel offset into the incoming universe = index * 4.
var groups = []fixtureGroup{
    {name: "A_INNER", subUnis: []uint8{199, 200, 201}},
    {name: "A_OUTER", subUnis: []uint8{205, 206, 207}},
    {name: "B_INNER", subUnis: []uint8{211, 212}},
    {name: "B_OUTER", subUnis: []uint8{217, 218}},
}

type CLI struct {
    Verbose bool `help:"Enable verbose logging."`

    Config string `help:"Configuration file." default:"config.yaml"`

    Listen string `help:"Address to listen on." default:":9000"`

    RunDaemon RunCmd `cmd:"" help:"Run the bridge daemon."`

    Version VersionCmd `cmd:"" help:"Print version information."`
}

type RunCmd struct {
    ArtNet bool `help:"Enable Art-Net."`

    SACN bool `help:"Enable sACN."`

    Universe int `help:"Universe number." default:"1"`

    DryRun bool `help:"Don't send any network traffic."`
}

func (r *RunCmd) Run(cli *CLI) error {
    fmt.Println("Running...")

    fmt.Printf("Verbose:  %v\n", cli.Verbose)
    fmt.Printf("Config:   %s\n", cli.Config)
    fmt.Printf("Listen:   %s\n", cli.Listen)

    fmt.Printf("ArtNet:   %v\n", r.ArtNet)
    fmt.Printf("sACN:     %v\n", r.SACN)
    fmt.Printf("Universe: %d\n", r.Universe)
    fmt.Printf("DryRun:   %v\n", r.DryRun)

    addr, err := net.ResolveUDPAddr("udp", listenAddr)
    if err != nil {
        log.Fatalf("resolving %q: %v", listenAddr, err)
    }
    in, err := net.ListenUDP("udp", addr)
    if err != nil {
        log.Fatalf("listening on %q: %v", listenAddr, err)
    }
    defer in.Close()

    out, err := net.Dial("udp", controllerAddr)
    if err != nil {
        log.Fatalf("connecting to %q: %v", controllerAddr, err)
    }
    defer out.Close()

    log.Printf("listening on %s (net %d, universe %d), forwarding to %s",
        listenAddr, listenNet, listenSubUni, controllerAddr)

    var seq uint8 = 1
    buf := make([]byte, 1024)
    for {
        n, _, err := in.ReadFromUDP(buf)
        if err != nil {
            log.Printf("read error: %v", err)
            continue
        }

        p, err := packet.Unmarshal(buf[:n])
        if err != nil {
            continue // not a valid Art-Net packet (or one we don't care about)
        }
        dmx, ok := p.(*packet.ArtDMXPacket)
        if !ok || dmx.Net != listenNet || dmx.SubUni != listenSubUni {
            continue
        }

        for i, g := range groups {
            offset := i * 4
            if int(dmx.Length) < offset+4 {
                continue
            }
            r, gr, b, w := dmx.Data[offset], dmx.Data[offset+1], dmx.Data[offset+2], dmx.Data[offset+3]

            var out512 [512]byte
            for c := 0; c < 512; c += 4 {
                out512[c], out512[c+1], out512[c+2], out512[c+3] = gr, r, b, w // GRBW
            }

            for _, subUni := range g.subUnis {
                op := packet.NewArtDMXPacket()
                op.Sequence = seq
                op.SubUni = subUni
                op.Net = 0
                op.Length = 512
                op.Data = out512

                b, err := op.MarshalBinary()
                if err != nil {
                    log.Printf("marshal error (universe %d): %v", subUni, err)
                    continue
                }
                if _, err := out.Write(b); err != nil {
                    log.Printf("send error (universe %d): %v", subUni, err)
                }
            }
        }

        seq++
        if seq == 0 {
            seq = 1 // 0 is reserved for "sequence not in use"
        }
    }

    return nil
}

type VersionCmd struct{}

func (v *VersionCmd) Run() error {
    fmt.Println("switchyard 1.0.0")
    return nil
}

func (v *CLI) Run() error {
    fmt.Println("This is the no-arg branch")
    return nil
}

func main() {
    var cli CLI

    ctx := kong.Parse(
        &cli,
        kong.Name("switchyard"),
        kong.Description("Lighting protocol bridge"),
    )
    fmt.Println("ctx.Selected().Type = %s", ctx.Selected().Type)
    // If a subcommand was selected, let Kong execute it.
    if ctx.Selected().Type != kong.ApplicationNode {
        ctx.FatalIfErrorf(ctx.Run())
        return
    }

    // Otherwise execute the default action.
    if err := cli.Run(); err != nil {
        log.Fatal(err)
    }
}
