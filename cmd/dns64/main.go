package main

import (
	"flag"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"nat64/pkg/dns64"
	"os"
	"os/signal"
	"time"
)

var (
	UseTCP       = flag.Bool("tcp", true, "Use TCP")
	BindAddr     = flag.String("bind", ":53", "Address to bind to")
	ResolverAddr = flag.String("resolver", "1.1.1.1:53", "Recursive DNS resolver address")
)

func main() {
	flag.Parse()

	// Set up logger
	logConfig := zap.NewProductionConfig()
	logConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	logConfig.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.DateTime)
	logConfig.Encoding = "console"

	logger, err := logConfig.Build()
	if err != nil {
		fmt.Println("Failed to create logger: ", err)
		os.Exit(1)
	}

	// Configure and started DNS64 server
	opts := dns64.Options{
		UseTCP:       *UseTCP,
		BindAddr:     *BindAddr,
		ResolverAddr: *ResolverAddr,
	}

	server := dns64.NewServer(opts, logger)
	server.Run()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)
	<-shutdown
}
