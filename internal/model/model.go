package model

type (
	ProcessInfo struct {
		Pid  uint32
		Name string
	}
)

func (p *ProcessInfo) Reset() {
	*p = ProcessInfo{}
}
