package main

import (
	"net/netip"
	"path"
	"sort"

	"github.com/adaricorp/tc-cpumap/bpf"
	"github.com/adaricorp/tc-cpumap/tc"
	"github.com/cilium/ebpf"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/mitchellh/go-ps"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "tc_cpumap"
)

var (
	trafficLabels = []string{"ip", "tc_handle", "tc_handle_name"}

	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is the program running.",
		nil,
		nil,
	)

	trafficLocalRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_local", "rx_bytes_total"),
		"Bytes received from local network hosts.",
		trafficLabels,
		nil,
	)
	trafficLocalRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_local", "rx_packets_total"),
		"Packets received from local network hosts.",
		trafficLabels,
		nil,
	)
	trafficLocalTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_local", "tx_bytes_total"),
		"Bytes sent to local network hosts.",
		trafficLabels,
		nil,
	)
	trafficLocalTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_local", "tx_packets_total"),
		"Packets sent from local network hosts.",
		trafficLabels,
		nil,
	)

	trafficRemoteRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_remote", "rx_bytes_total"),
		"Bytes received from remote network hosts.",
		trafficLabels,
		nil,
	)
	trafficRemoteRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_remote", "rx_packets_total"),
		"Packets received from remote network hosts.",
		trafficLabels,
		nil,
	)
	trafficRemoteTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_remote", "tx_bytes_total"),
		"Bytes sent to remote network hosts.",
		trafficLabels,
		nil,
	)
	trafficRemoteTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "traffic_remote", "tx_packets_total"),
		"Packets sent from remote network hosts.",
		trafficLabels,
		nil,
	)
)

type tcCpumapCollector struct {
	logger        log.Logger
	tcHandleNames tc.TcHandleNames

	up *prometheus.Desc

	trafficLocalRxBytes    *prometheus.Desc
	trafficLocalRxPackets  *prometheus.Desc
	trafficLocalTxBytes    *prometheus.Desc
	trafficLocalTxPackets  *prometheus.Desc
	trafficRemoteRxBytes   *prometheus.Desc
	trafficRemoteRxPackets *prometheus.Desc
	trafficRemoteTxBytes   *prometheus.Desc
	trafficRemoteTxPackets *prometheus.Desc
}

func newTcCpumapCollector(logger log.Logger, tcHandleNames tc.TcHandleNames) *tcCpumapCollector {
	return &tcCpumapCollector{
		logger:                 logger,
		tcHandleNames:          tcHandleNames,
		up:                     up,
		trafficLocalRxBytes:    trafficLocalRxBytes,
		trafficLocalRxPackets:  trafficLocalRxPackets,
		trafficLocalTxBytes:    trafficLocalTxBytes,
		trafficLocalTxPackets:  trafficLocalTxPackets,
		trafficRemoteRxBytes:   trafficRemoteRxBytes,
		trafficRemoteRxPackets: trafficRemoteRxPackets,
		trafficRemoteTxBytes:   trafficRemoteTxBytes,
		trafficRemoteTxPackets: trafficRemoteTxPackets,
	}
}

func (collector *tcCpumapCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- collector.up

	ch <- collector.trafficLocalRxBytes
	ch <- collector.trafficLocalRxPackets
	ch <- collector.trafficLocalTxBytes
	ch <- collector.trafficLocalTxPackets
	ch <- collector.trafficRemoteRxBytes
	ch <- collector.trafficRemoteRxPackets
	ch <- collector.trafficRemoteTxBytes
	ch <- collector.trafficRemoteTxPackets
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
			// nolint:errcheck
			level.Error(collector.logger).Log(
				"msg", "Error loading map",
				"map", mapPath,
				"err", err,
			)
			continue
		}

		var (
			key  bpf.BpfIn6Addr
			vals []bpf.BpfHostCounter
		)

		iter := m.Iterate()
		for iter.Next(&key, &vals) {
			ip := netip.AddrFrom16(key.In6U.U6Addr8)
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

			tcHandleString := tc.TcHandleString(aggData.TcHandle)
			tcHandleName, exists := collector.tcHandleNames[tcHandleString]
			if !exists {
				tcHandleName = ""
			}

			switch bpfMap {
			case "map_traffic_local":
				ch <- prometheus.MustNewConstMetric(
					collector.trafficLocalRxBytes,
					prometheus.CounterValue,
					float64(aggData.RxBytes),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficLocalRxPackets,
					prometheus.CounterValue,
					float64(aggData.RxPackets),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficLocalTxBytes,
					prometheus.CounterValue,
					float64(aggData.TxBytes),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficLocalTxPackets,
					prometheus.CounterValue,
					float64(aggData.TxPackets),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
			case "map_traffic_remote":
				ch <- prometheus.MustNewConstMetric(
					collector.trafficRemoteRxBytes,
					prometheus.CounterValue,
					float64(aggData.RxBytes),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficRemoteRxPackets,
					prometheus.CounterValue,
					float64(aggData.RxPackets),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficRemoteTxBytes,
					prometheus.CounterValue,
					float64(aggData.TxBytes),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
				ch <- prometheus.MustNewConstMetric(
					collector.trafficRemoteTxPackets,
					prometheus.CounterValue,
					float64(aggData.TxPackets),
					ip.Unmap().String(),
					tcHandleString,
					tcHandleName,
				)
			}
		}

		if iter.Err() != nil {
			// nolint:errcheck
			level.Error(collector.logger).Log(
				"msg", "Error reading map",
				"map", mapPath,
				"err", iter.Err(),
			)
		}
	}
}

func (collector *tcCpumapCollector) collectProcessHealth(ch chan<- prometheus.Metric) {
	tcCpumapPid := 0

	pids, err := ps.Processes()
	if err != nil {
		// nolint:errcheck
		level.Error(collector.logger).Log(
			"msg", "Error getting process list",
			"err", err,
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
