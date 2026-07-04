package upgrade

import (
    "log"
    "fmt"
    "runtime"
    "os"

    "av-switchyard/cli"
)

func RunUpgrade(c *cli.CLI) error {
    log.Printf("c.UpgradeVersion = %s", c.UpgradeVersion)
    log.Printf("ComputeBinaryName() = %s", ComputeBinaryName())
    log.Printf("getExecutablePath() = %s", getExecutablePath())

    log.Printf(" // TODO fetch Github release data, compute most-recent, and grab appropriate artifact. ")

    return nil
}

func ComputeBinaryName() string {
    os := runtime.GOOS
    arch := runtime.GOARCH

    // Normalize Go's naming to our labels
    if os == "darwin" {
        os = "macos"
    }

    extension := ""
    if os == "windows" {
        extension = ".exe"
    }

    return fmt.Sprintf("av-switchyard-%s-%s%s", os, arch, extension)
}

func getExecutablePath() string {
    exe_path, err := os.Executable()
    if err != nil {
        computed_exe_path := ComputeBinaryName()
        log.Printf("Cannot determine executable path, falling back to %s - %v", computed_exe_path, err)
        return computed_exe_path
    } else {
        return exe_path
    }
}
