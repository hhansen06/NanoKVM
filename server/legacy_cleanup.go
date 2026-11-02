package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"

	"NanoKVM-Server/service/controlmode"

	log "github.com/sirupsen/logrus"
)

// What the MCP service and the PicoClaw assistant of the upstream firmware
// leave on a device. This fork ships neither, so a device updated from
// upstream would otherwise keep an orphaned assistant running at boot and an
// MCP API key on disk that nothing checks any more.
const (
	legacyPicoclawInitScript   = "/etc/init.d/S96picoclaw"
	legacyPicoclawBinary       = "/usr/bin/picoclaw"
	legacyPicoclawCacheDir     = "/root/.picoclaw-cache"
	legacyPicoclawHome         = "/root/.picoclaw"
	legacyPicoclawInternalFile = "/etc/kvm/.picoclaw_internal_token"
	legacyMCPConfigFile        = "/etc/kvm/mcp.json"
	legacyStopTimeout          = 15 * time.Second
)

// removeAIFeatures stops and removes the PicoClaw runtime, deletes the MCP
// API key and the internal loopback token, and pins the AI control mode to
// off so manual input is never held back for an assistant. The PicoClaw home
// directory is kept: it holds the administrator's model settings and chat
// history, which are theirs to delete.
func removeAIFeatures() {
	if _, err := os.Stat(legacyPicoclawInitScript); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), legacyStopTimeout)
		if err = exec.CommandContext(ctx, legacyPicoclawInitScript, "stop").Run(); err != nil {
			log.Warnf("stop PicoClaw: %s", err)
		}
		cancel()
		removeLegacyPath(legacyPicoclawInitScript, false)
		log.Infof("PicoClaw is not part of this firmware; its service was stopped and removed")
	}
	removeLegacyPath(legacyPicoclawBinary, false)
	removeLegacyPath(legacyPicoclawCacheDir, true)
	removeLegacyPath(legacyPicoclawInternalFile, false)
	removeLegacyPath(legacyMCPConfigFile, false)
	if _, err := os.Stat(legacyPicoclawHome); err == nil {
		log.Infof("PicoClaw settings and history remain in %s; delete the directory if they are no longer needed", legacyPicoclawHome)
	}

	control := controlmode.GetManager()
	if control.Current() != controlmode.ModeOff {
		if err := control.SwitchOff(nil); err != nil {
			log.Warnf("switch AI control mode off: %s", err)
		}
	}
}

func removeLegacyPath(path string, recursive bool) {
	var err error
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	if err == nil {
		log.Debugf("removed %s", path)
		return
	}
	if !errors.Is(err, os.ErrNotExist) {
		log.Warnf("remove %s: %s", path, err)
	}
}
