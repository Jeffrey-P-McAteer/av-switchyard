//go:build windows

package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	CREATE_NEW_PROCESS_GROUP = 0x00000200
	DETACHED_PROCESS         = 0x00000008
	CREATE_NO_WINDOW         = 0x08000000
)

func psQuote(s string) string {
	// Escape embedded single quotes for PowerShell single-quoted strings.
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func FinalizeUpgrade(exePath string, newBinary []byte) error {
	pid := os.Getpid()

	tmp, err := os.CreateTemp("", "av-switchyard-upgrade-*.exe")
	if err != nil {
		return err
	}
	defer tmp.Close()

	if _, err := tmp.Write(newBinary); err != nil {
		return err
	}

	script := strings.Join([]string{
	    fmt.Sprintf("$Pid=%d", pid),
	    fmt.Sprintf("$TempFile=%s", psQuote(tmp.Name())),
	    fmt.Sprintf("$TargetFile=%s", psQuote(exePath)),
	    "",
	    "$Deadline=(Get-Date).AddSeconds(30)",
	    "",
	    "while ($true) {",
	    "    if (!(Get-Process -Id $Pid -ErrorAction SilentlyContinue)) {",
	    "        break",
	    "    }",
	    "",
	    "    if ((Get-Date) -gt $Deadline) {",
	    "        Add-Type -AssemblyName PresentationFramework",
	    "",
	    "        [System.Windows.MessageBox]::Show(",
	    `            "Unable to replace."`,
	    `            ,"Upgrade Failed"`,
	    "        )",
	    "",
	    "        exit 1",
	    "    }",
	    "",
	    "    Start-Sleep -Milliseconds 500",
	    "}",
	    "",
	    "Move-Item -LiteralPath $TempFile -Destination $TargetFile -Force",
	}, "\n")

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-WindowStyle", "Hidden",
		"-Command", script,
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NEW_PROCESS_GROUP |
			DETACHED_PROCESS,
	}

	return cmd.Start()
}

