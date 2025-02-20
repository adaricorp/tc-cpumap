package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path"
	"slices"
	"sort"
	"time"

	"github.com/IncSW/geoip2"
	"github.com/adaricorp/tc-cpumap/bpf"
	"github.com/adaricorp/tc-cpumap/mac"
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
	asnDBPath   *string
	bootTime    time.Time

	asnReader *geoip2.ASNReader
)

type hostKey struct {
	ip  bpf.BpfIn6Addr
	mac uint64
}

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
	asnDBPath = fs.StringLong(
		"maxmind-asn-db-path",
		"",
		"Path to GeoLite2-ASN.mmdb file (optional)",
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

	headingRow := table.Row{
		"IP",
		"MAC",
		"Sent",
		"Sent",
		"Received",
		"Received",
		"TC handle",
		"Last seen",
	}

	subheadingRow := table.Row{
		"",
		"",
		"Bytes",
		"Packets",
		"Bytes",
		"Packets",
		"",
		"",
	}

	if *perCpuStats {
		headingRow = slices.Insert(headingRow, 2, "RX CPU")
		subheadingRow = slices.Insert(subheadingRow, 2, "")
	}

	if mapName == "remote" && asnReader != nil {
		headingRow = slices.Insert(headingRow, 1, "AS")
		headingRow = slices.Insert(headingRow, 2, "AS")
		headingRow = slices.Insert(headingRow, 3, "AS")
		subheadingRow = slices.Insert(subheadingRow, 1, "Number")
		subheadingRow = slices.Insert(subheadingRow, 2, "Organization")
		subheadingRow = slices.Insert(subheadingRow, 3, "Prefix")
	}

	t.AppendHeader(
		headingRow,
		table.RowConfig{AutoMerge: true},
	)
	t.AppendHeader(subheadingRow)

	var (
		key  bpf.BpfIn6Addr
		vals []bpf.BpfHostCounter
	)

	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		ip := netip.AddrFrom16(key.In6U.U6Addr8)
		if *perCpuStats {
			for cpu, val := range vals {
				row := table.Row{
					ip.Unmap(),
				}

				if mapName == "remote" && asnReader != nil {
					record, err := asnReader.Lookup(net.IP(ip.Unmap().AsSlice()))
					if err != nil {
						row = append(row,
							table.Row{
								"",
								"",
								"",
							}...,
						)
					} else {
						prefix := record.Network
						if prefix == "<nil>" {
							prefix = ""
						}

						row = append(row,
							table.Row{
								record.AutonomousSystemNumber,
								record.AutonomousSystemOrganization,
								prefix,
							}...,
						)
					}
				}

				row = append(row,
					table.Row{
						mac.MacAddress(val.Mac),
						cpu,
						val.TxBytes,
						val.TxPackets,
						val.RxBytes,
						val.RxPackets,
						tc.TcHandleString(val.TcHandle),
						val.LastSeen,
						decodeLastSeenTime(val.LastSeen),
					}...,
				)

				t.AppendRow(row)
			}
		} else {
			// Sort by last seen so TcHandle/LastSeen values that
			// are stored in aggData are the most up to date
			sort.Slice(vals, func(a, b int) bool {
				return vals[a].LastSeen < vals[b].LastSeen
			})

			hostAggData := map[hostKey]bpf.BpfHostCounter{}

			for _, val := range vals {
				host := hostKey{
					ip:  key,
					mac: val.Mac,
				}

				// Aggregate statistics by host
				if stats, exists := hostAggData[host]; exists {
					stats.TxBytes += val.TxBytes
					stats.TxPackets += val.TxPackets
					stats.RxBytes += val.RxBytes
					stats.RxPackets += val.RxPackets
					stats.LastSeen = val.LastSeen

					hostAggData[host] = stats
				} else {
					hostAggData[host] = bpf.BpfHostCounter{
						TxBytes:   val.TxBytes,
						TxPackets: val.TxPackets,
						RxBytes:   val.RxBytes,
						RxPackets: val.RxPackets,
						TcHandle:  val.TcHandle,
						Mac:       val.Mac,
						LastSeen:  val.LastSeen,
					}
				}
			}

			for host, stats := range hostAggData {
				row := table.Row{
					ip.Unmap(),
				}

				if mapName == "remote" && asnReader != nil {
					record, err := asnReader.Lookup(net.IP(ip.Unmap().AsSlice()))
					if err != nil {
						row = append(row,
							table.Row{
								"",
								"",
								"",
							}...,
						)
					} else {
						prefix := record.Network
						if prefix == "<nil>" {
							prefix = ""
						}

						row = append(row,
							table.Row{
								record.AutonomousSystemNumber,
								record.AutonomousSystemOrganization,
								prefix,
							}...,
						)
					}
				}

				row = append(row,
					table.Row{
						mac.MacAddress(host.mac),
						stats.TxBytes,
						stats.TxPackets,
						stats.RxBytes,
						stats.RxPackets,
						tc.TcHandleString(stats.TcHandle),
						decodeLastSeenTime(stats.LastSeen),
					}...,
				)

				t.AppendRow(row)
			}
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

	if *asnDBPath != "" {
		var err error
		asnReader, err = geoip2.NewASNReaderFromFile(*asnDBPath)
		if err != nil {
			log.Fatalf("Error opening ASN database: %s", err)
		}
	}

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
