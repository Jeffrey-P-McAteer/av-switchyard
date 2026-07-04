package main

import (
    "log"

    "github.com/alecthomas/kong"

    "av-switchyard/cli"
    "av-switchyard/daemon"
)

func main() {
    var c cli.CLI

    ctx := kong.Parse(
        &c,
        kong.Name("switchyard"),
        kong.Description("Lighting protocol bridge"),
    )

    c.Func_RunDaemon = daemon.RunDaemon

    // If a subcommand was selected, let Kong execute it.
    if ctx.Selected().Type != kong.ApplicationNode {
        ctx.FatalIfErrorf(ctx.Run())
        return
    }

    // Otherwise execute the default action.
    if err := c.Run(); err != nil {
        log.Fatal(err)
    }
}
