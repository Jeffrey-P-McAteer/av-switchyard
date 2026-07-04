package version

import (
    "strings"
)

// Injected using LDFLAGS in Makefile
var (
    Version   = "v0.0.0"
    GitCommit = "none"
    BuildDate = "unknown"
    BuildHost = "localhost"
)

func VersionString() string {
    return Version + " (" + GitCommit + ") built " + BuildDate + " by " + strings.TrimSpace(BuildHost)
}


