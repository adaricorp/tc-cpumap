package main

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"path"
	"sort"
	"time"

	"github.com/adaricorp/tc-cpumap/bpf"
	"github.com/adaricorp/tc-cpumap/tc"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
)

var (
	version = "dev"
	date    = "unknown"

	bpfMaps     = []string{"local", "remote"}
	perCpuStats *bool
	sortColumn  *int
	bootTime    time.Time
)

// Print program usage
func printUsage(fs ff.Flags) {
	fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
	os.Exit(1)
}

// Print program version
func printVersion() {
	fmt.Printf("tc_cpumap_trafficstats v%s built on %s\n", version, date)
	os.Exit(0)
}

func init() {
	fs := ff.NewFlagSet("tc_cpumap_trafficstats")
	displayVersion := fs.BoolLong("version", "Print version")
	perCpuStats = fs.BoolLong(
		"per-cpu-stats",
		"Provide separate traffic stats per CPU core",
	)
	sortColumn = fs.IntLong(
		"sort-column",
		0,
		"Column number to sort on, or 0 to disable sorting",
	)

	err := ff.Parse(fs, os.Args[1:])
	if err != nil {
		printUsage(fs)
	}

	if *displayVersion {
		printVersion()
	}
}

func decodeLastSeenTime(lastseen uint64) string {
	return bootTime.Add(time.Duration(lastseen)).Format(time.RFC3339)
}

func printMap(mapName string, m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle(fmt.Sprintf("Traffic stats - %v", mapName))

	if *perCpuStats {
		t.AppendHeader(
			table.Row{
				"IP",
				"RX CPU",
				"Sent",
				"Sent",
				"Received",
				"Received",
				"TC handle",
				"Last seen",
			},
			table.RowConfig{AutoMerge: true},
		)
		t.AppendHeader(
			table.Row{
				"",
				"",
				"Bytes",
				"Packets",
				"Bytes",
				"Packets",
				"",
				"",
			},
		)
	} else {
		t.AppendHeader(
			table.Row{
				"IP",
				"Sent",
				"Sent",
				"Received",
				"Received",
				"TC handle",
				"Last seen",
			},
			table.RowConfig{AutoMerge: true},
		)
		t.AppendHeader(
			table.Row{
				"",
				"Bytes",
				"Packets",
				"Bytes",
				"Packets",
				"",
				"",
			},
		)
	}

	var (
		key  bpf.BpfIn6Addr
		vals []bpf.BpfHostCounter
	)

	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		ip := netip.AddrFrom16(key.In6U.U6Addr8)
		if *perCpuStats {
			for cpu, val := range vals {
				t.AppendRow(
					[]interface{}{
						ip.Unmap(),
						cpu,
						val.TxBytes,
						val.TxPackets,
						val.RxBytes,
						val.RxPackets,
						tc.TcHandleString(val.TcHandle),
						val.LastSeen,
						decodeLastSeenTime(val.LastSeen),
					},
				)
			}
		} else {
			aggData := bpf.BpfHostCounter{}

			// Sort by last seen so TcHandle/LastSeen values that
			// get stored in aggData are the most up to date
			sort.Slice(vals, func(a, b int) bool {
				return vals[a].LastSeen < vals[b].LastSeen
			})

			for _, val := range vals {
				aggData.TxBytes += val.TxBytes
				aggData.TxPackets += val.TxPackets
				aggData.RxBytes += val.RxBytes
				aggData.RxPackets += val.RxPackets

				aggData.TcHandle = val.TcHandle
				aggData.LastSeen = val.LastSeen
			}

			t.AppendRow(
				[]interface{}{
					ip.Unmap(),
					aggData.TxBytes,
					aggData.TxPackets,
					aggData.RxBytes,
					aggData.RxPackets,
					tc.TcHandleString(aggData.TcHandle),
					decodeLastSeenTime(aggData.LastSeen),
				},
			)
		}
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Style().Options.SeparateRows = true
	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "IP", AutoMerge: true},
	})

	if !*perCpuStats && *sortColumn > 0 {
		t.SortBy([]table.SortBy{
			{Number: *sortColumn, Mode: table.DscNumeric},
		})
	}

	t.Render()

	return iter.Err()
}

func main() {
	var bootTimespec unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec); err != nil {
		log.Fatalf("Error getting system boot time: %v", err)
	}
	bootTime = time.Now().Add(-1 * time.Duration(bootTimespec.Nano()))

	for _, mapName := range bpfMaps {
		mapFileName := fmt.Sprintf("map_traffic_%v", mapName)
		mapTraffic, err := ebpf.LoadPinnedMap(
			path.Join(bpf.MapPinPath, mapFileName),
			&ebpf.LoadPinOptions{
				ReadOnly: true,
			},
		)
		if err != nil {
			log.Fatalf("Error loading map: %v", err)
		}

		err = printMap(mapName, mapTraffic)
		if err != nil {
			log.Fatalf("Error reading map: %s", err)
		}
	}
}
