package scan

import (
    "log"

    "av-switchyard/cli"
)

func RunScan(c *cli.CLI) error {
    log.Printf("config file: %v\n", c.ConfigFile)

    return nil
}

