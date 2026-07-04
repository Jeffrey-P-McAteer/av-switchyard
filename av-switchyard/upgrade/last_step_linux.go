//go:build linux

package upgrade

import (
	"os"
)

func FinalizeUpgrade(exePath string, newBinary []byte) error {
	tmp := exePath + ".new"

	if err := os.WriteFile(tmp, newBinary, 0755); err != nil {
		return err
	}

	return os.Rename(tmp, exePath)
}

