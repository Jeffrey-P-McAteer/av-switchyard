package cli

import (
    "fmt"

    "av-switchyard/version"
)

func (c *CLI) Run() error {
    switch c.Command {
        case "", "daemon", "run-daemon":
            return c.Func_RunDaemon(c)

        case "version":
            fmt.Println(version.VersionString())
            return nil

        case "upgrade", "update":
            return c.Func_RunUpgrade(c)

        case "scan":
            return c.Func_RunScan(c)

        default:
            return fmt.Errorf("unknown command: %s\nSupported commands are: %s", c.Command, SupportedSubcommandNames)
    }
    return nil
}
