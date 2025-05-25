package nft_protector

import (
	"flag"
)

var (
	LogLevel           string
	ProtectedTableName string
	ProtectorType      string
)

func init() {
	flag.StringVar(&LogLevel, "level", "INFO", "log level: INFO|DEBUG|WARN|ERROR|PANIC|FATAL")
	flag.StringVar(&ProtectedTableName, "table", "", "protected table name")
	flag.StringVar(&ProtectorType, "type", "nlbpf", "type of protection: lsm|nlbpf")
	flag.Parse()
}
