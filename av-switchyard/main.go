/**
 *  av-switchyard - an experimental AV control bridge software
 *  Copyright (C) 2026  Jeffrey McAteer <jeffrey@jmcateer.com>
 *                      Paige Marshall <https://github.com/marshallpt>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; version 2 of the License ONLY.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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
