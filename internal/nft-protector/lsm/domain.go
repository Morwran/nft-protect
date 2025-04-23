package lsm

import (
	"bytes"
	"unsafe"

	"github.com/Morwran/nft-protect/internal/model"
)

type LsmEvent bpfEvent

func (l *LsmEvent) ToModel() model.ProcessInfo {
	return model.ProcessInfo{
		Pid:  l.Pid,
		Name: FastBytes2String(bytes.TrimRight(l.Comm[:], "\x00")),
	}
}

func FastBytes2String(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
