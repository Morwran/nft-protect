package kernelinfo

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/host"
)

const kernelModulesFile = "/proc/modules"

var (
	kernelVersionRe = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)
	btfConfigRe     = regexp.MustCompile(`^CONFIG_DEBUG_INFO_BTF\s*=\s*y`)
	lsmConfigRe     = regexp.MustCompile(`^CONFIG_BPF_LSM\s*=\s*y`)
	lsmGrubOptionRe = regexp.MustCompile(`^GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\blsm=bpf\b[^"]*"`)
)

type KernelVersion struct {
	Major, Minor, Patch int
}

func (v KernelVersion) IsAtLeast(ver KernelVersion) bool {
	if v.Major != ver.Major {
		return v.Major > ver.Major
	}
	if v.Minor != ver.Minor {
		return v.Minor > ver.Minor
	}
	return v.Patch >= ver.Patch
}

func (v KernelVersion) String() string {
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func GetKernelVersion() (v KernelVersion, err error) {
	versionStr, err := host.KernelVersion()
	if err != nil {
		return v, err
	}
	return parseKernelVersion(versionStr)
}

func CheckKernelVersion(minVersion KernelVersion) error {
	v, err := GetKernelVersion()
	if err != nil {
		return err
	}
	if ok := v.IsAtLeast(minVersion); !ok {
		return fmt.Errorf("current kernel version is %s has to be not lower than %s", v, minVersion)
	}
	return nil
}

func CheckBTFKernelSupport() error {
	return errors.WithMessage(checkKernelConfigByRe(btfConfigRe), "BTF support")
}

func CheckLsmBpfKernelSupport() error {
	return errors.WithMessage(checkKernelConfigByRe(lsmConfigRe), "LSM BPF support")
}

func CheckLsmBpfGrubOption() error {
	return errors.WithMessage(checkConfigByRe("/etc/default/grub", lsmGrubOptionRe), "LSM BPF grub option")
}

func CheckKernelModules(modules ...string) error {
	file, err := os.Open(kernelModulesFile)
	if err != nil {
		return errors.WithMessagef(err, "failed to open %s", kernelModulesFile)
	}
	defer file.Close() //nolint:errcheck

	loadedModules := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		moduleName := strings.SplitN(line, " ", 2)[0]
		loadedModules[moduleName] = struct{}{}
	}

	if err = scanner.Err(); err != nil {
		return errors.WithMessagef(err, "error reading %s", kernelModulesFile)
	}
	var unloadedModules []string
	for _, mod := range modules {
		if _, ok := loadedModules[mod]; !ok {
			unloadedModules = append(unloadedModules, mod)
		}
	}
	if len(unloadedModules) > 0 {
		return errors.Errorf("modules %s is not loaded. Please load it with 'modprobe %s'",
			strings.Join(unloadedModules, ","), strings.Join(unloadedModules, " "))
	}

	return nil
}

func parseKernelVersion(ver string) (v KernelVersion, err error) {
	matches := kernelVersionRe.FindStringSubmatch(ver)
	if len(matches) < 3 {
		return v, fmt.Errorf("invalid kernel version format: %s", ver)
	}

	parsePart := func(s string) int {
		if s == "" {
			return 0
		}
		n, _ := strconv.Atoi(s)
		return n
	}

	return KernelVersion{
		Major: parsePart(matches[1]),
		Minor: parsePart(matches[2]),
		Patch: parsePart(matches[3]),
	}, nil
}

func checkKernelConfigByRe(re *regexp.Regexp) error {
	kernelVersion, err := host.KernelVersion()
	if err != nil {
		return err
	}
	configFilePath := fmt.Sprintf("/boot/config-%s", strings.TrimSpace(kernelVersion))
	return errors.WithMessagef(
		checkConfigByRe(configFilePath, re),
		"failed to check config in %s for the kernel version %s", configFilePath, kernelVersion)
}

func checkConfigByRe(filePath string, re *regexp.Regexp) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		if re.MatchString(line) {
			return nil
		}
	}
	return fmt.Errorf("failed to find config in file %s", filePath)
}
