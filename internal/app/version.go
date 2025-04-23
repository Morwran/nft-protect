package app

import (
	"fmt"

	app_identity "github.com/H-BF/corlib/app/identity"
)

func GetVersion() string {
	if app_identity.Version != "" {
		if app_identity.BuildTag == "" {
			return fmt.Sprintf("v%s|%s", app_identity.Version, app_identity.BuildHash)
		}
		return "v" + app_identity.Version
	}
	if app_identity.BuildTag != "" {
		return app_identity.BuildTag
	}

	return app_identity.BuildHash
}
