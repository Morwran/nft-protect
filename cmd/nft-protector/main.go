package main

import (
	"context"
	"time"

	"github.com/Morwran/nft-protect/internal/app"
	. "github.com/Morwran/nft-protect/internal/app/nft-protector" //nolint:revive

	"github.com/H-BF/corlib/logger"
	gs "github.com/H-BF/corlib/pkg/patterns/graceful-shutdown"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func main() {
	SetupContext()
	ctx := app.Context()
	logger.SetLevel(zap.InfoLevel)
	logger.InfoKV(ctx, "-= HELLO =-", "version", app.GetVersion())

	if err := SetupLogger(LogLevel); err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup logger"))
	}

	gracefulDuration := 5 * time.Second
	errc := make(chan error, 1)

	protector, err := SetupProtector()
	if err != nil {
		logger.Fatal(ctx, errors.WithMessage(err, "setup protector"))
	}
	defer protector.Close()

	go func() {
		defer close(errc)
		errc <- protector.Run(ctx)
	}()
	var jobErr error

Loop:
	for {
		select {
		case <-ctx.Done():
			if gracefulDuration >= time.Second {
				logger.Infof(ctx, "%s in shutdowning...", gracefulDuration)
				_ = gs.ForDuration(gracefulDuration).Run(
					gs.Chan(errc).Consume(
						func(_ context.Context, err error) {
							jobErr = err
						},
					),
				)
			}
		case jobErr = <-errc:
		case p, ok := <-protector.EvtReader():
			if ok {
				logger.Infof(ctx, "pid=%d, process=%s", p.Pid, p.Name)
				continue
			} else {
				logger.Fatal(ctx, errors.New("event reader closed"))
			}
		}
		break Loop
	}

	if jobErr != nil {
		logger.Fatal(ctx, jobErr)
	}

	logger.SetLevel(zap.InfoLevel)
	logger.Info(ctx, "-= BYE =-")
}
