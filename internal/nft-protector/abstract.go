package nft_protector

import (
	"context"

	"github.com/Morwran/nft-protect/internal/model"
)

const MaxTblNameLen = 64

type (
	Protector interface {
		Run(context.Context) error
		Close() error
		EvtReader() <-chan model.ProcessInfo
	}
)
