package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"NanoKVM-Server/common"
	"NanoKVM-Server/config"
	"NanoKVM-Server/logger"
	"NanoKVM-Server/middleware"
	"NanoKVM-Server/router"
	"NanoKVM-Server/service/hid"
	"NanoKVM-Server/service/storage/diskfs"
	"NanoKVM-Server/service/vm"
	"NanoKVM-Server/service/vm/jiggler"
	"NanoKVM-Server/utils"

	"github.com/gin-gonic/gin"
	cors "github.com/rs/cors/wrapper/gin"
)

func main() {
	initialize()
	defer dispose()

	run()
}

func initialize() {
	logger.Init()

	// This fork ships without MCP and PicoClaw; retire what an earlier
	// firmware left behind before anything else starts.
	removeAIFeatures()

	// This fork runs HID-only; switch the USB gadget over if it is not.
	hid.EnsureHidOnly()

	// init screen parameters
	_ = common.GetScreen()

	// init HDMI
	vm.DisableHdmiCapture()
	time.Sleep(10 * time.Millisecond)
	if !utils.IsHdmiDisabled() {
		vm.EnableHdmiCapture()
	}
	vm.SetHdmiViewerCount(0)

	// run mouse jiggler
	jiggler.GetJiggler().Run()

	// A medium left mounted by a crash or a restart keeps its loop device
	// busy; nothing can be mounted by this process yet, so whatever is there
	// is stale.
	diskfs.CleanupStale()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		log.Printf("\nReceived signal: %v\n", sig)

		dispose()
		os.Exit(0)
	}()
}

func run() {
	conf := config.GetInstance()

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	if conf.Authentication == "disable" {
		r.Use(cors.AllowAll())
	}

	router.Init(r)

	httpAddr := utils.ListenAddr(conf.Host, strconv.Itoa(conf.Port.Http))

	if conf.Proto == "https" {
		httpsPortStr := strconv.Itoa(conf.Port.Https)

		go func() {
			err := r.RunTLS(utils.ListenAddr(conf.Host, httpsPortStr), conf.Cert.Crt, conf.Cert.Key)
			if err != nil {
				panic("start https server failed")
			}
		}()

		if err := middleware.ListenAndServeHTTPRedirect(httpAddr, httpsPortStr); err != nil {
			panic("start http server failed")
		}
	} else {
		if err := r.Run(httpAddr); err != nil {
			panic("start http server failed")
		}
	}
}

func dispose() {
	diskfs.CleanupStale()
	common.GetKvmVision().Close()
}
