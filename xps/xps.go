// Package xps clears the XPS (Transmit Packet Steering) CPU maps of TX queues.
package xps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SysClassNet is where sysfs lists network interfaces.
const SysClassNet = "/sys/class/net"

// Queue is a TX queue whose XPS CPU map was found set.
type Queue struct {
	Interface string
	Queue     string
	Mask      string
}

// IsZero reports whether a mask read from an xps_cpus file selects no CPUs.
// The kernel prints it as comma separated hex words, e.g. "00000000,00000000".
func IsZero(mask []byte) bool {
	digits := strings.ReplaceAll(strings.TrimSpace(string(mask)), ",", "")

	return digits != "" && strings.Trim(digits, "0") == ""
}

// Clear zeroes every set XPS CPU map on the TX queues of ifaces, reads it back,
// and returns the queues it found set. Failures don't stop it; they're joined.
func Clear(sysClassNet string, ifaces []string) ([]Queue, error) {
	set := []Queue{}
	errs := []error{}

	for _, ifaceName := range ifaces {
		queueDirs, err := filepath.Glob(
			filepath.Join(sysClassNet, ifaceName, "queues", "tx-*"),
		)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if len(queueDirs) == 0 {
			errs = append(errs, fmt.Errorf("interface %v has no tx queues", ifaceName))
			continue
		}

		for _, queueDir := range queueDirs {
			queue := filepath.Base(queueDir)
			xpsCpusFile := filepath.Join(queueDir, "xps_cpus")

			mask, err := os.ReadFile(xpsCpusFile)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			if IsZero(mask) {
				continue
			}

			set = append(set, Queue{
				Interface: ifaceName,
				Queue:     queue,
				Mask:      strings.TrimSpace(string(mask)),
			})

			if err := os.WriteFile(xpsCpusFile, []byte("0"), 0644); err != nil {
				errs = append(errs, fmt.Errorf(
					"couldn't disable XPS on %v %v: %w", ifaceName, queue, err,
				))
				continue
			}

			mask, err = os.ReadFile(xpsCpusFile)
			if err != nil {
				errs = append(errs, err)
				continue
			}

			if !IsZero(mask) {
				errs = append(errs, fmt.Errorf(
					"XPS on %v %v still reads %v after disabling it",
					ifaceName,
					queue,
					strings.TrimSpace(string(mask)),
				))
			}
		}
	}

	return set, errors.Join(errs...)
}
