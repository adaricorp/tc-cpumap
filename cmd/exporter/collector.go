package main

import (
	"log/slog"
	"net"
	"net/netip"
	"path"
	"sort"
	"strconv"

	"github.com/IncSW/geoip2"
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

type hostKey struct {
	ip  bpf.BpfIn6Addr
	mac uint64
}

type asKey struct {
	localIp netip.Addr
	asn     string
	org     string
}

type tcCpumapCollector struct {
	logger        *slog.Logger
	tcHandleNames tc.TcHandleNames
	asnReader     *geoip2.ASNReader

	up *prometheus.Desc

	ipTrafficLocalRxBytes         *prometheus.Desc
	ipTrafficLocalRxPackets       *prometheus.Desc
	ipTrafficLocalTxBytes         *prometheus.Desc
	ipTrafficLocalTxPackets       *prometheus.Desc
	tcHandleTrafficLocalRxBytes   *prometheus.Desc
	tcHandleTrafficLocalRxPackets *prometheus.Desc
	tcHandleTrafficLocalTxBytes   *prometheus.Desc
	tcHandleTrafficLocalTxPackets *prometheus.Desc
	asTrafficRemoteRxBytes        *prometheus.Desc
	asTrafficRemoteRxPackets      *prometheus.Desc
	asTrafficRemoteTxBytes        *prometheus.Desc
	asTrafficRemoteTxPackets      *prometheus.Desc
}

func newTcCpumapCollector(
	logger *slog.Logger,
	tcHandleNames tc.TcHandleNames,
	asnReader *geoip2.ASNReader,
) *tcCpumapCollector {
	ipTrafficLocalLabels := []string{"ip", "mac", "tc_handle", "tc_handle_name"}
	ipTrafficRemoteLabels := []string{"local_ip", "as_num", "as_org"}
	tcHandleTrafficLabels := []string{"tc_handle", "tc_handle_name"}

	up := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is the program running.",
		nil,
		nil,
	)

	ipTrafficLocalRxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "rx_bytes_total"),
		"Bytes received from local network hosts.",
		ipTrafficLocalLabels,
		nil,
	)
	ipTrafficLocalRxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "rx_packets_total"),
		"Packets received from local network hosts.",
		ipTrafficLocalLabels,
		nil,
	)
	ipTrafficLocalTxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "tx_bytes_total"),
		"Bytes sent to local network hosts.",
		ipTrafficLocalLabels,
		nil,
	)
	ipTrafficLocalTxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "ip_traffic_local", "tx_packets_total"),
		"Packets sent from local network hosts.",
		ipTrafficLocalLabels,
		nil,
	)

	tcHandleTrafficLocalRxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "rx_bytes_total"),
		"Bytes received from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalRxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "rx_packets_total"),
		"Packets received from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalTxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "tx_bytes_total"),
		"Bytes sent to local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)
	tcHandleTrafficLocalTxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "tc_handle_traffic_local", "tx_packets_total"),
		"Packets sent from local network hosts.",
		tcHandleTrafficLabels,
		nil,
	)

	asTrafficRemoteRxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "as_traffic_remote", "rx_bytes_total"),
		"Bytes received from remote autonomous systems.",
		ipTrafficRemoteLabels,
		nil,
	)
	asTrafficRemoteRxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "as_traffic_remote", "rx_packets_total"),
		"Packets received from remote autonomous systems.",
		ipTrafficRemoteLabels,
		nil,
	)
	asTrafficRemoteTxBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "as_traffic_remote", "tx_bytes_total"),
		"Bytes sent to remote autonomous systems.",
		ipTrafficRemoteLabels,
		nil,
	)
	asTrafficRemoteTxPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "as_traffic_remote", "tx_packets_total"),
		"Packets sent from remote autonomous systems.",
		ipTrafficRemoteLabels,
		nil,
	)

	return &tcCpumapCollector{
		logger:                        logger,
		tcHandleNames:                 tcHandleNames,
		asnReader:                     asnReader,
		up:                            up,
		ipTrafficLocalRxBytes:         ipTrafficLocalRxBytes,
		ipTrafficLocalRxPackets:       ipTrafficLocalRxPackets,
		ipTrafficLocalTxBytes:         ipTrafficLocalTxBytes,
		ipTrafficLocalTxPackets:       ipTrafficLocalTxPackets,
		tcHandleTrafficLocalRxBytes:   tcHandleTrafficLocalRxBytes,
		tcHandleTrafficLocalRxPackets: tcHandleTrafficLocalRxPackets,
		tcHandleTrafficLocalTxBytes:   tcHandleTrafficLocalTxBytes,
		tcHandleTrafficLocalTxPackets: tcHandleTrafficLocalTxPackets,
		asTrafficRemoteRxBytes:        asTrafficRemoteRxBytes,
		asTrafficRemoteRxPackets:      asTrafficRemoteRxPackets,
		asTrafficRemoteTxBytes:        asTrafficRemoteTxBytes,
		asTrafficRemoteTxPackets:      asTrafficRemoteTxPackets,
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
	ch <- collector.asTrafficRemoteRxBytes
	ch <- collector.asTrafficRemoteRxPackets
	ch <- collector.asTrafficRemoteTxBytes
	ch <- collector.asTrafficRemoteTxPackets
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

		asAggData := map[asKey]bpf.BpfHostCounter{}
		tcHandleAggData := map[uint32]bpf.BpfHostCounter{}

		iter := m.Iterate()

		switch bpfMap {
		case "map_traffic_local":
			var (
				key  bpf.BpfIn6Addr
				vals []bpf.BpfHostCounter
			)

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

					labels := []string{
						ip.Unmap().String(),
						hwAddr.String(),
						tcHandleString,
						tcHandleName,
					}

					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalRxBytes,
						prometheus.CounterValue,
						float64(stats.RxBytes),
						labels...,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalRxPackets,
						prometheus.CounterValue,
						float64(stats.RxPackets),
						labels...,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalTxBytes,
						prometheus.CounterValue,
						float64(stats.TxBytes),
						labels...,
					)
					ch <- prometheus.MustNewConstMetric(
						collector.ipTrafficLocalTxPackets,
						prometheus.CounterValue,
						float64(stats.TxPackets),
						labels...,
					)
				}
			}
		case "map_traffic_remote":
			if collector.asnReader == nil {
				continue
			}

			var (
				key  bpf.BpfRemoteStatsKey
				vals []bpf.BpfHostCounter
			)

			for iter.Next(&key, &vals) {
				for _, val := range vals {
					var as asKey

					ip := netip.AddrFrom16(key.RemoteIp.In6U.U6Addr8)
					localIp := netip.AddrFrom16(key.LocalIp.In6U.U6Addr8)

					record, err := collector.asnReader.Lookup(net.IP(ip.Unmap().AsSlice()))
					if err != nil {
						as = asKey{
							localIp: localIp,
							asn:     "unknown",
							org:     "unknown",
						}
					} else {
						as = asKey{
							localIp: localIp,
							asn:     strconv.Itoa(int(record.AutonomousSystemNumber)),
							org:     record.AutonomousSystemOrganization,
						}
					}

					// Aggregate statistics by AS
					if stats, exists := asAggData[as]; exists {
						stats.TxBytes += val.TxBytes
						stats.TxPackets += val.TxPackets
						stats.RxBytes += val.RxBytes
						stats.RxPackets += val.RxPackets
						stats.LastSeen = val.LastSeen

						asAggData[as] = stats
					} else {
						asAggData[as] = bpf.BpfHostCounter{
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
			}
		}

		if iter.Err() != nil {
			collector.logger.Error(
				"Error reading map",
				"map", mapPath,
				"error", iter.Err(),
			)
		}

		switch bpfMap {
		case "map_traffic_local":
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
		case "map_traffic_remote":
			for as, stats := range asAggData {
				labels := []string{as.localIp.Unmap().String(), as.asn, as.org}

				ch <- prometheus.MustNewConstMetric(
					collector.asTrafficRemoteRxBytes,
					prometheus.CounterValue,
					float64(stats.RxBytes),
					labels...,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.asTrafficRemoteRxPackets,
					prometheus.CounterValue,
					float64(stats.RxPackets),
					labels...,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.asTrafficRemoteTxBytes,
					prometheus.CounterValue,
					float64(stats.TxBytes),
					labels...,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.asTrafficRemoteTxPackets,
					prometheus.CounterValue,
					float64(stats.TxPackets),
					labels...,
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
