package nft_protector

import (
	"context"
	"os"
	"sync"
	"time"
	"unsafe"

	kernelinfo "github.com/Morwran/nft-protect/internal/kernel-info"
	"github.com/Morwran/nft-protect/internal/model"

	"github.com/H-BF/corlib/logger"
	"github.com/H-BF/corlib/pkg/queue"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
)

var _ Protector = (*lsmBpfProtector)(nil)

type (
	lsmBpfProtector struct {
		objs      bpfObjects
		que       queue.FIFO[model.ProcessInfo]
		onceRun   sync.Once
		onceClose sync.Once
		stop      chan struct{}
		stopped   chan struct{}
	}
)

func NewLsmEbpfProtector(pid uint32, protectedTblName string) (*lsmBpfProtector, error) {
	err := ensureKernelSupport(kernelinfo.KernelVersion{Major: 5, Minor: 11, Patch: 0})
	if err != nil {
		return nil, err
	}
	if err = ensureLsmSupport(); err != nil {
		return nil, errors.WithMessage(err, "failed to check LSM kernel support")
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return nil, errors.WithMessage(err, "failed to lock memory for process")
	}
	objs := bpfObjects{}
	loadOpts := &ebpf.CollectionOptions{}
	if err = loadBpfObjects(&objs, loadOpts); err != nil {
		return nil, errors.WithMessage(err, "failed to load bpf objects")
	}

	key := uint32(0)
	if err = objs.AllowedPidMap.Put(key, pid); err != nil {
		return nil, errors.WithMessage(err, "failed to setup allowed pid")
	}
	var tblNameArr [MaxTblNameLen]uint8
	copy(tblNameArr[:], protectedTblName)

	if err = objs.ProtectedTblNameMap.Put(key, tblNameArr); err != nil {
		return nil, errors.WithMessage(err, "failed to setup protected table name")
	}

	return &lsmBpfProtector{
		objs: objs,
		que:  queue.NewFIFO[model.ProcessInfo](),
		stop: make(chan struct{}),
	}, nil
}

func (p *lsmBpfProtector) Run(ctx context.Context) error {
	var doRun bool

	p.onceRun.Do(func() {
		doRun = true
	})
	if !doRun {
		return errors.New("it has been run or closed yet")
	}
	p.stopped = make(chan struct{})

	log := logger.FromContext(ctx).Named("lsm-protector")
	defer func() {
		log.Info("stop")
		close(p.stopped)
	}()
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: p.objs.LsmNetlinkSend})
	if err != nil {
		return errors.WithMessage(err, "failed to attach LSM program")
	}
	defer func() { _ = lsmLink.Close() }()
	log.Info("start")
	return p.rcvEvent(logger.ToContext(ctx, log), func(event Event) error {
		p.que.Put(event.ToModel())
		return nil
	})
}

// EvtReader
func (p *lsmBpfProtector) EvtReader() <-chan model.ProcessInfo {
	return p.que.Reader()
}

// Close
func (p *lsmBpfProtector) Close() error {
	p.onceClose.Do(func() {
		close(p.stop)
		p.onceRun.Do(func() {})
		if p.stopped != nil {
			<-p.stopped
		}
		_ = p.objs.Close()
	})
	return nil
}

func (p *lsmBpfProtector) rcvEvent(ctx context.Context, callback func(event Event) error) error {
	log := logger.FromContext(ctx)
	rd, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		return errors.WithMessage(err, "opening ringbuf reader")
	}
	defer rd.Close()

	var (
		event  bpfEvent
		record ringbuf.Record
	)
Loop:
	for err == nil {
		select {
		case <-ctx.Done():
			log.Info("will exit cause ctx canceled")
			err = ctx.Err()
			goto Loop
		case <-p.stop:
			break Loop
		default:
		}
		rd.SetDeadline(time.Now().Add(2 * time.Second))
		err = rd.ReadInto(&record)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				err = nil
				continue
			}
			err = errors.WithMessage(err, "reading events from reader")
			goto Loop
		}
		if len(record.RawSample) == 0 {
			continue
		}

		event = *(*bpfEvent)(unsafe.Pointer(&record.RawSample[0]))
		if callback != nil {
			err = callback(Event(event))
		}
	}
	return err
}
