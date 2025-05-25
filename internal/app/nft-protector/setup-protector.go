package nft_protector

import (
	"os"
	"strings"

	nft_protector "github.com/Morwran/nft-protect/internal/nft-protector"

	"github.com/pkg/errors"
)

type protectConstrutor func(pid uint32, protectedTblName string) (nft_protector.Protector, error)

var protectConstrutors = map[string]protectConstrutor{
	"lsm":   setupLsmProtector,
	"nlbpf": setupNlBpfProtector,
}

func SetupProtector() (nft_protector.Protector, error) {
	protector, ok := protectConstrutors[strings.ToLower(strings.TrimSpace(ProtectorType))]
	if !ok {
		return nil, errors.Errorf("unknown type of protection '%s'", ProtectorType)
	}
	return protector(uint32(os.Getpid()), strings.TrimSpace(ProtectedTableName))
}

func setupLsmProtector(pid uint32, protectedTblName string) (nft_protector.Protector, error) {
	return nft_protector.NewLsmEbpfProtector(pid, protectedTblName)
}

func setupNlBpfProtector(pid uint32, protectedTblName string) (nft_protector.Protector, error) {
	return nft_protector.NewNlBpfProtector(pid, protectedTblName)
}
