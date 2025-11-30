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
	l, err := x.runRxPacket(ctx)
	if err != nil {
		return fmt.Errorf("failed to run rx packet processing: %w", err)
	}
	x.cleanupFnList = append(x.cleanupFnList, func(ctx context.Context) error {
		x.Logger.Info("detaching XDP program")
		return l.Close()
	})
	go x.ShowStats(ctx, TrafficTypeRX)
	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ctx.Done():
		x.Logger.Info("context cancelled, shutting down server")
	case sig := <-sigCh:
		x.Logger.Info("received signal, shutting down server", zap.String("signal", sig.String()))
	}
	return nil
}

func (x *Xdperf) runRxPacket(_ context.Context) (link.Link, error) {
	x.Logger.Info("start rx packet processing")
	// dummy XDP Prog attachment
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   x.bpfobjs.XdpRx,
		Interface: x.Device.Index,
	})
	if err != nil {
		return l, fmt.Errorf("failed to attach XDP program: %w", err)
	}

	return l, nil
}
