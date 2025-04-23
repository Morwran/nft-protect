package nft_protector

import (
	"context"

	"github.com/Morwran/nft-protect/internal/app"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/signals"
	"go.uber.org/zap"
)

// SetupContext setup app ctx
func SetupContext() {
	ctx, cancel := context.WithCancel(context.Background())
	signals.WhenSignalExit(func() error {
		logger.SetLevel(zap.InfoLevel)
		logger.Info(ctx, "caught application stop signal")
		cancel()
		return nil
	})
	app.SetContext(ctx)
}
