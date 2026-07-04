package main

import (
    "github.com/alecthomas/kong"

    "av-switchyard/cli"
    "av-switchyard/daemon"
    "av-switchyard/scan"
    "av-switchyard/upgrade"
    "av-switchyard/version"
)

func main() {
    var c cli.CLI

    ctx := kong.Parse(
        &c,
        kong.Name("av-switchyard"),
        kong.Description(
            "av-switchyard " + version.VersionString() + "\n\n" +
            "Sub-commands: " + cli.SupportedSubcommandNames),
        kong.ConfigureHelp(kong.HelpOptions{
            WrapUpperBound: 120,
        }),
    )

    c.Func_RunDaemon = daemon.RunDaemon
    c.Func_RunUpgrade = upgrade.RunUpgrade
    c.Func_RunScan = scan.RunScan

    // Executes Run() in cli/commands.go
    ctx.FatalIfErrorf(ctx.Run())
}
