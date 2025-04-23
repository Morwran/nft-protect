package nft_protector

import (
	"context"

	"github.com/Morwran/nft-protect/internal/model"
)

type (
	Protector interface {
		Run(context.Context) error
		Close() error
		EvtReader() <-chan model.ProcessInfo
	}
)
