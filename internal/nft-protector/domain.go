package nft_protector

import (
	"bytes"
	"unsafe"

	kernel_info "github.com/Morwran/nft-protect/internal/kernel-info"
	"github.com/Morwran/nft-protect/internal/model"
	"github.com/pkg/errors"
)

var requiredKernelModules = []string{"nf_tables"}

type Event bpfEvent

func (l *Event) ToModel() model.ProcessInfo {
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

func ensureKernelSupport(ver kernel_info.KernelVersion) (err error) {
	if err = kernel_info.CheckKernelVersion(ver); err != nil {
		return errors.WithMessage(err, "failed to check kernel version")
	}
	if err = kernel_info.CheckBTFKernelSupport(); err != nil {
		return errors.WithMessage(err, "failed to check BTF kernel support")
	}
	if err = kernel_info.CheckKernelModules(requiredKernelModules...); err != nil {
		err = errors.WithMessage(err, "failed to check kernel modules")
	}
	return err
}

func ensureLsmSupport() (err error) {
	if err = kernel_info.CheckLsmBpfKernelSupport(); err != nil {
		return errors.WithMessage(err, "failed to check LSM BPF kernel support")
	}
	if err = kernel_info.CheckLsmBpfGrubOption(); err != nil {
		return errors.WithMessage(err, "failed to check LSM BPF grub option support")
	}
	return err
}
