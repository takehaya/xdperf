package xdperf

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

func (x *Xdperf) StartServer(ctx context.Context) error {
	x.Logger.Info("start server mode")
	if x.cfg.TCPServer {
		return x.runTCPServer(ctx)
	}
	l, err := x.runRxPacket(ctx)
	if err != nil {
		return fmt.Errorf("failed to run rx packet processing: %w", err)
	}
	x.cleanupFnList = append(x.cleanupFnList, func(ctx context.Context) error {
		x.Logger.Info("detaching XDP program")
		return l.Close()
	})
	x.beginSummary()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	statsDone := make(chan struct{})
	go func() { defer close(statsDone); x.ShowStats(ctx, TrafficTypeRX) }()
	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	select {
	case <-ctx.Done():
		x.Logger.Info("context cancelled, shutting down server")
	case sig := <-sigCh:
		x.Logger.Info("received signal, shutting down server", zap.String("signal", sig.String()))
	}
	cancel()
	<-statsDone
	if x.summary != nil {
		if err := l.Close(); err != nil {
			return fmt.Errorf("detach RX before summary JSON: %w", err)
		}
	}
	return x.writeSummary()
}

func (x *Xdperf) runRxPacket(_ context.Context) (link.Link, error) {
	x.Logger.Info("start rx packet processing")
	// dummy XDP Prog attachment
	l, err := x.attachXDP(x.bpfobjs.XdpRx, x.Device)
	if err != nil {
		return l, err
	}

	return l, nil
}
