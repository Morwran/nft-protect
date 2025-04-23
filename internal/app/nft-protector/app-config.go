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
	flag.StringVar(&ProtectorType, "type", "lsm", "type of protection: lsm")
	flag.Parse()
}
