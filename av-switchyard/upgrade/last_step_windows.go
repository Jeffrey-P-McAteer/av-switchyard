//go:build windows

package upgrade

import (
	"fmt"
	"os"
	//"os/exec"
	//"syscall"
	"strings"
	"log"
	"golang.org/x/sys/windows"
	"encoding/base64"
	"unicode/utf16"
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
	log.Printf("Wrote to temp file %s\n", tmp.Name())

	script := strings.Join([]string{
	    fmt.Sprintf("$TrackedPid=%d", pid),
	    fmt.Sprintf("$TempFile=%s", psQuote(tmp.Name())),
	    fmt.Sprintf("$TargetFile=%s", psQuote(exePath)),
	    "",
	    "$Deadline=(Get-Date).AddSeconds(12)",
	    "",
	    "Add-Type -AssemblyName PresentationFramework",
	    "Start-Sleep -Milliseconds 500",
	    "while ($true) {",
	    "    if (!(Get-Process -Id $TrackedPid -ErrorAction SilentlyContinue)) {",
	    "        break",
	    "    }",
	    "",
	    "    if ((Get-Date) -gt $Deadline) {",
	    "",
	    "        [System.Windows.MessageBox]::Show(",
	    `            "Unable to replace."`,
	    `            ,"Upgrade Failed"`,
	    "        )",
	    "",
	    "        break",
	    "    }",
	    "",
	    "    Start-Sleep -Milliseconds 500",
	    "}",
	    "",
	    "Move-Item -LiteralPath $TempFile -Destination $TargetFile -Force",
	    "Start-Sleep -Milliseconds 1500",
	    "[System.Windows.MessageBox]::Show(",
	    `    "Upgrade Success"`,
	    `    ,"Upgrade Success"`,
	    ")",
	    "Start-Sleep -Milliseconds 2500",
	    "Start-Sleep -Milliseconds 7500",
	}, "\n")

	log.Printf("= = = powershell script = = =\n%s\n\n", script)

	// cmd := exec.Command(
	// 	"powershell.exe",
	// 	"-NoProfile",
	// 	"-ExecutionPolicy", "Bypass",
	// 	"-Command", script,
	// )

	// sysproc_attrs := syscall.SysProcAttr{
	// 	CreationFlags: CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
	// }
	// cmd.SysProcAttr = &sysproc_attrs

	// return cmd.Start()
	encoded := encodePowerShell(script)

	err2 := windows.ShellExecute(
		0,
		nil,
		windows.StringToUTF16Ptr("powershell.exe"),
		windows.StringToUTF16Ptr("-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand \""+encoded+"\""),
		nil,
		windows.SW_SHOWNORMAL,
	)

	return err2
}

func encodePowerShell(script string) string {
	utf16Bytes := utf16.Encode([]rune(script))

	b := make([]byte, len(utf16Bytes)*2)
	for i, v := range utf16Bytes {
		b[i*2] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}

	return base64.StdEncoding.EncodeToString(b)
}
