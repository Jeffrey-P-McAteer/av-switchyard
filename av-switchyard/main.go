package main

import (
    "github.com/alecthomas/kong"

    "av-switchyard/cli"
    "av-switchyard/daemon"
    "av-switchyard/upgrade"
    "av-switchyard/version"
)

func main() {
    var c cli.CLI

    ctx := kong.Parse(
        &c,
        kong.Name("av-switchyard"),
        kong.Description(
            "Lighting protocol bridge " + version.VersionString() + "\n" +
            "Sub-commands: " + cli.SupportedSubcommandNames),
    )

    c.Func_RunDaemon = daemon.RunDaemon
    c.Func_RunUpgrade = upgrade.RunUpgrade

    // Executes Run() in cli/commands.go
    ctx.FatalIfErrorf(ctx.Run())
}
