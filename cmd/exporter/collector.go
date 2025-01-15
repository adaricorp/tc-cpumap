package main

import (
	"log/slog"
	"net/netip"
	"path"
	"sort"

	"github.com/adaricorp/tc-cpumap/bpf"
	"github.com/adaricorp/tc-cpumap/mac"
	"github.com/adaricorp/tc-cpumap/tc"
	"github.com/cilium/ebpf"
	"github.com/mitchellh/go-ps"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "tc_cpumap"
)

var (
	ipTrafficLabels       = []string{"ip", "mac", "tc_handle", "tc_handle_name"}
	tcHandleTrafficLabels = []string{"tc_handle", "tc_handle_name"}

	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is the program running.",
		nil,
		nil,
	)

	ipTrafficLocalRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "rx_bytes_total"),
		"Bytes received from local network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficLocalRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "rx_packets_total"),
		"Packets received from local network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficLocalTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "tx_bytes_total"),
		"Bytes sent to local network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficLocalTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "tx_packets_total"),
		"Packets sent from local network hosts.",
		ipTrafficLabels,
		nil,
	)

	tcHandleTrafficLocalRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "rx_bytes_total"),
		"Bytes received from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "rx_packets_total"),
		"Packets received from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "tx_bytes_total"),
		"Bytes sent to local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "tx_packets_total"),
		"Packets sent from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)

	ipTrafficRemoteRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_remote", "rx_bytes_total"),
		"Bytes received from remote network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficRemoteRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_remote", "rx_packets_total"),
		"Packets received from remote network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficRemoteTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_remote", "tx_bytes_total"),
		"Bytes sent to remote network hosts.",
		ipTrafficLabels,
		nil,
	)
	ipTrafficRemoteTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_remote", "tx_packets_total"),
		"Packets sent from remote network hosts.",
		ipTrafficLabels,
		nil,
	)
)

type hostKey struct {
	ip  bpf.BpfIn6Addr
	mac uint64
}

type tcCpumapCollector struct {
	logger        *slog.Logger
	tcHandleNames tc.TcHandleNames

	up *prometheus.Desc

	ipTrafficLocalRxBytes         *prometheus.Desc
	ipTrafficLocalRxPackets       *prometheus.Desc
	ipTrafficLocalTxBytes         *prometheus.Desc
	ipTrafficLocalTxPackets       *prometheus.Desc
	tcHandleTrafficLocalRxBytes   *prometheus.Desc
	tcHandleTrafficLocalRxPackets *prometheus.Desc
	tcHandleTrafficLocalTxBytes   *prometheus.Desc
	tcHandleTrafficLocalTxPackets *prometheus.Desc
	ipTrafficRemoteRxBytes        *prometheus.Desc
	ipTrafficRemoteRxPackets      *prometheus.Desc
	ipTrafficRemoteTxBytes        *prometheus.Desc
	ipTrafficRemoteTxPackets      *prometheus.Desc
}

func newTcCpumapCollector(logger *slog.Logger, tcHandleNames tc.TcHandleNames) *tcCpumapCollector {
	return &tcCpumapCollector{
		logger:                        logger,
		tcHandleNames:                 tcHandleNames,
		up:                            up,
		ipTrafficLocalRxBytes:         ipTrafficLocalRxBytes,
		ipTrafficLocalRxPackets:       ipTrafficLocalRxPackets,
		ipTrafficLocalTxBytes:         ipTrafficLocalTxBytes,
		ipTrafficLocalTxPackets:       ipTrafficLocalTxPackets,
		tcHandleTrafficLocalRxBytes:   tcHandleTrafficLocalRxBytes,
		tcHandleTrafficLocalRxPackets: tcHandleTrafficLocalRxPackets,
		tcHandleTrafficLocalTxBytes:   tcHandleTrafficLocalTxBytes,
		tcHandleTrafficLocalTxPackets: tcHandleTrafficLocalTxPackets,
		ipTrafficRemoteRxBytes:        ipTrafficRemoteRxBytes,
		ipTrafficRemoteRxPackets:      ipTrafficRemoteRxPackets,
		ipTrafficRemoteTxBytes:        ipTrafficRemoteTxBytes,
		ipTrafficRemoteTxPackets:      ipTrafficRemoteTxPackets,
	}
}

func (collector *tcCpumapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.up

	ch <- collector.ipTrafficLocalRxBytes
	ch <- collector.ipTrafficLocalRxPackets
	ch <- collector.ipTrafficLocalTxBytes
	ch <- collector.ipTrafficLocalTxPackets
	ch <- collector.tcHandleTrafficLocalRxBytes
	ch <- collector.tcHandleTrafficLocalRxPackets
	ch <- collector.tcHandleTrafficLocalTxBytes
	ch <- collector.tcHandleTrafficLocalTxPackets
	ch <- collector.ipTrafficRemoteRxBytes
	ch <- collector.ipTrafficRemoteRxPackets
	ch <- collector.ipTrafficRemoteTxBytes
	ch <- collector.ipTrafficRemoteTxPackets
}

func (collector *tcCpumapCollector) Collect(ch chan<- prometheus.Metric) {
	collector.collectBpfMapMetrics(ch)
	collector.collectProcessHealth(ch)
}

func (collector *tcCpumapCollector) collectBpfMapMetrics(ch chan<- prometheus.Metric) {
	bpfMaps := []string{"map_traffic_local", "map_traffic_remote"}

	for _, bpfMap := range bpfMaps {
		mapPath := path.Join(bpf.MapPinPath, bpfMap)
		m, err := ebpf.LoadPinnedMap(
			mapPath,
			&ebpf.LoadPinOptions{
				ReadOnly: true,
			},
		)
		if err != nil {
			collector.logger.Error(
				"Error loading map",
				"map", mapPath,
				"error", err.Error(),
			)
			continue
		}

		var (
			key  bpf.BpfIn6Addr
			vals []bpf.BpfHostCounter
		)

		tcHandleAggData := map[uint32]bpf.BpfHostCounter{}

		iter := m.Iterate()
		for iter.Next(&key, &vals) {
			// Sort by last seen so TcHandle/LastSeen values that
			// are stored in aggData are the most recent
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

				// Aggregate data by TC handle
				stats := tcHandleAggData[val.TcHandle]
				stats.TxBytes += val.TxBytes
				stats.TxPackets += val.TxPackets
				stats.RxBytes += val.RxBytes
				stats.RxPackets += val.RxPackets
				tcHandleAggData[val.TcHandle] = stats
			}

			for host, stats := range hostAggData {
				ip := netip.AddrFrom16(host.ip.In6U.U6Addr8)
				hwAddr := mac.MacAddress(host.mac)

				tcHandleString := tc.TcHandleString(stats.TcHandle)

				tcHandleName, exists := collector.tcHandleNames[tcHandleString]
				if !exists {
					tcHandleName = ""
				}

				switch bpfMap {
				case "map_traffic_local":
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalRxBytes,
						prometheus.CounterValue,
						float64(stats.RxBytes),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalRxPackets,
						prometheus.CounterValue,
						float64(stats.RxPackets),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalTxBytes,
						prometheus.CounterValue,
						float64(stats.TxBytes),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalTxPackets,
						prometheus.CounterValue,
						float64(stats.TxPackets),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
				case "map_traffic_remote":
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficRemoteRxBytes,
						prometheus.CounterValue,
						float64(stats.RxBytes),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficRemoteRxPackets,
						prometheus.CounterValue,
						float64(stats.RxPackets),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficRemoteTxBytes,
						prometheus.CounterValue,
						float64(stats.TxBytes),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficRemoteTxPackets,
						prometheus.CounterValue,
						float64(stats.TxPackets),
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					)
				}
			}
		}

		if iter.Err() != nil {
			collector.logger.Error(
				"Error reading map",
				"map", mapPath,
				"error", iter.Err(),
			)
		}

		if bpfMap == "map_traffic_local" {
			for handle, stats := range tcHandleAggData {
				tcHandleString := tc.TcHandleString(handle)

				tcHandleName, exists := collector.tcHandleNames[tcHandleString]
				if !exists {
					tcHandleName = ""
				}

				ch <- prometheus.MustNewConstMetric(
					collector.tcHandleTrafficLocalRxBytes,
					prometheus.CounterValue,
					float64(stats.RxBytes),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.tcHandleTrafficLocalRxPackets,
					prometheus.CounterValue,
					float64(stats.RxPackets),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.tcHandleTrafficLocalTxBytes,
					prometheus.CounterValue,
					float64(stats.TxBytes),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.tcHandleTrafficLocalTxPackets,
					prometheus.CounterValue,
					float64(stats.TxPackets),
					tcHandleString,
					tcHandleName,
				)
			}
		}
	}
}

func (collector *tcCpumapCollector) collectProcessHealth(ch chan<- prometheus.Metric) {
	tcCpumapPid := 0

	pids, err := ps.Processes()
	if err != nil {
		collector.logger.Error(
			"Error getting process list",
			"error", err.Error(),
		)
	} else {
		for _, p := range pids {
			if p.Executable() == "tc_cpumap" {
				tcCpumapPid = p.Pid()
				break
			}
		}
	}

	if tcCpumapPid >= 1 {
		ch <- prometheus.MustNewConstMetric(
			collector.up,
			prometheus.GaugeValue,
			float64(1),
		)
	} else {
		ch <- prometheus.MustNewConstMetric(
			collector.up,
			prometheus.GaugeValue,
			float64(0),
		)
	}
}
