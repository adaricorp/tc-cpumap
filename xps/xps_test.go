package xps

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Build a fake /sys/class/net with an xps_cpus file per TX queue
func fakeSysClassNet(t *testing.T, masks map[string]map[string]string) string {
	t.Helper()

	root := t.TempDir()
	for ifaceName, queues := range masks {
		for queue, mask := range queues {
			queueDir := filepath.Join(root, ifaceName, "queues", queue)
			if err := os.MkdirAll(queueDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(queueDir, "xps_cpus"), []byte(mask), 0644,
			); err != nil {
				t.Fatal(err)
			}
		}
	}

	return root
}

func readMask(t *testing.T, root string, ifaceName string, queue string) string {
	t.Helper()

	mask, err := os.ReadFile(filepath.Join(root, ifaceName, "queues", queue, "xps_cpus"))
	if err != nil {
		t.Fatal(err)
	}

	return string(mask)
}

func TestIsZero(t *testing.T) {
	for mask, want := range map[string]bool{
		"0\n":                 true,
		"00000000\n":          true,
		"00,00000000\n":       true,
		"00000000,00000000\n": true,
		"40000000\n":          false,
		"00000001,00000000\n": false,
		"80,00000000\n":       false,
		"":                    false,
		"\n":                  false,
	} {
		if got := IsZero([]byte(mask)); got != want {
			t.Errorf("IsZero(%q) = %v, want %v", mask, got, want)
		}
	}
}

func TestClearDisablesQueuesThatWereSet(t *testing.T) {
	root := fakeSysClassNet(t, map[string]map[string]string{
		"eth0": {
			"tx-0": "00000000\n",
			"tx-1": "40000000\n",
		},
		"eth1": {
			"tx-0": "00,00000002\n",
			"tx-1": "00,00000000\n",
		},
	})

	set, err := Clear(root, []string{"eth0", "eth1"})
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	want := []Queue{
		{Interface: "eth0", Queue: "tx-1", Mask: "40000000"},
		{Interface: "eth1", Queue: "tx-0", Mask: "00,00000002"},
	}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("Clear() = %v, want %v", set, want)
	}

	for _, q := range want {
		if mask := readMask(t, root, q.Interface, q.Queue); !IsZero([]byte(mask)) {
			t.Errorf("%v %v reads %q after Clear()", q.Interface, q.Queue, mask)
		}
	}

	// A queue that was already disabled isn't written to
	if mask := readMask(t, root, "eth0", "tx-0"); mask != "00000000\n" {
		t.Errorf("eth0 tx-0 reads %q, want it untouched", mask)
	}
}

func TestClearReportsNothingWhenAllQueuesAreDisabled(t *testing.T) {
	root := fakeSysClassNet(t, map[string]map[string]string{
		"eth0": {"tx-0": "00000000\n", "tx-1": "00000000\n"},
	})

	set, err := Clear(root, []string{"eth0"})
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if len(set) != 0 {
		t.Errorf("Clear() = %v, want no queues", set)
	}
}

func TestClearCarriesOnPastFailures(t *testing.T) {
	root := fakeSysClassNet(t, map[string]map[string]string{
		"eth0": {"tx-1": "00000001\n"},
		"eth2": {"tx-0": "00000004\n"},
	})

	// An xps_cpus that can't be read
	if err := os.MkdirAll(
		filepath.Join(root, "eth0", "queues", "tx-0", "xps_cpus"), 0755,
	); err != nil {
		t.Fatal(err)
	}

	// eth1 has no TX queues at all
	set, err := Clear(root, []string{"eth0", "eth1", "eth2"})
	if err == nil {
		t.Fatal("Clear() error = nil, want the failures")
	}
	for _, failure := range []string{"eth0/queues/tx-0/xps_cpus", "eth1 has no tx queues"} {
		if !strings.Contains(err.Error(), failure) {
			t.Errorf("Clear() error = %q, want it to mention %q", err, failure)
		}
	}

	want := []Queue{
		{Interface: "eth0", Queue: "tx-1", Mask: "00000001"},
		{Interface: "eth2", Queue: "tx-0", Mask: "00000004"},
	}
	if !reflect.DeepEqual(set, want) {
		t.Errorf("Clear() = %v, want %v", set, want)
	}

	for _, q := range want {
		if mask := readMask(t, root, q.Interface, q.Queue); !IsZero([]byte(mask)) {
			t.Errorf("%v %v reads %q after Clear()", q.Interface, q.Queue, mask)
		}
	}
}
