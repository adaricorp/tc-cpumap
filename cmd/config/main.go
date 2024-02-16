package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"

	"github.com/adaricorp/tc-cpumap/bpf"
	"github.com/adaricorp/tc-cpumap/tc"

	"golang.org/x/exp/maps"

	"github.com/cilium/ebpf"
	"github.com/danjacques/gofslock/fslock"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"

	"gopkg.in/yaml.v2"
)

var (
	version = "dev"
	date    = "unknown"

	lockPath       = "/var/lock/tc_cpumap_config"
	mode           Mode
	configFilePath *string
	logLevel       *string
	slogLevel      *slog.LevelVar = new(slog.LevelVar)

	bpfMapNames = []string{
		"cpu_map",
		"cpus_available",
		"map_ifindex_direction",
		"map_ip_to_cpu_and_tc",
		"map_txq_config",
	}
)

// Print program usage
func printUsage(cmd *ff.Command) {
	fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Command(cmd))
	os.Exit(1)
}

// Print program version
func printVersion() {
	fmt.Printf("tc_cpumap_config v%s built on %s\n", version, date)
	os.Exit(0)
}

func init() {
	rootFlags := ff.NewFlagSet("tc_cpumap_config")
	displayVersion := rootFlags.BoolLong("version", "Print version")
	logLevel = rootFlags.StringEnumLong(
		"log-level",
		"Log level: debug, info, warn, error",
		"info",
		"debug",
		"error",
		"warn",
	)
	rootCommand := &ff.Command{
		Name:  "tc_cpumap_config",
		Usage: "tc_cpumap_config [FLAGS] <SUBCOMMAND> ...",
		Flags: rootFlags,
	}

	showFlags := ff.NewFlagSet("show").SetParent(rootFlags)
	showCommand := &ff.Command{
		Name:  "show",
		Usage: "tc_cpumap_config show",
		Flags: showFlags,
	}
	rootCommand.Subcommands = append(rootCommand.Subcommands, showCommand)

	updateFlags := ff.NewFlagSet("update").SetParent(rootFlags)
	configFilePath = updateFlags.StringLong("config", "tc-cpumap.yml", "Path to config file")
	updateCommand := &ff.Command{
		Name:  "update",
		Usage: "tc_cpumap_config update [FLAGS]",
		Flags: updateFlags,
	}
	rootCommand.Subcommands = append(rootCommand.Subcommands, updateCommand)

	clearFlags := ff.NewFlagSet("clear").SetParent(rootFlags)
	clearCommand := &ff.Command{
		Name:  "clear",
		Usage: "tc_cpumap_config clear",
		Flags: clearFlags,
	}
	rootCommand.Subcommands = append(rootCommand.Subcommands, clearCommand)

	err := rootCommand.Parse(os.Args[1:],
		ff.WithEnvVarPrefix("TC_CPUMAP_CONFIG"),
	)
	if err != nil {
		printUsage(rootCommand)
	}

	if *displayVersion {
		printVersion()
	}

	if selected := showCommand.GetSelected(); selected != nil {
		mode = ModeShow
	}
	if selected := updateCommand.GetSelected(); selected != nil {
		mode = ModeUpdate
	}
	if selected := clearCommand.GetSelected(); selected != nil {
		mode = ModeClear
	}

	if mode == ModeUndefined {
		printUsage(rootCommand)
	}

	switch *logLevel {
	case "debug":
		slogLevel.Set(slog.LevelDebug)
	case "info":
		slogLevel.Set(slog.LevelInfo)
	case "warn":
		slogLevel.Set(slog.LevelWarn)
	case "error":
		slogLevel.Set(slog.LevelError)
	}

	logger := slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slogLevel,
		}),
	)
	slog.SetDefault(logger)
}

func updateIpToCpuAndTcMap(
	ebpfMap *ebpf.Map,
	entries map[bpf.BpfIpHashKey]bpf.BpfIpHashInfo,
) error {
	// Calculate diff between current map state and new map state
	keysToDelete := []bpf.BpfIpHashKey{}
	iter := ebpfMap.Iterate()
	var curKey bpf.BpfIpHashKey
	var curVal bpf.BpfIpHashInfo
	for iter.Next(&curKey, &curVal) {
		if newVal, ok := entries[curKey]; ok {
			if newVal == curVal {
				// Entry already exists in map with same values,
				// we don't need to include in the batch update
				delete(entries, curKey)
			}
		} else {
			keysToDelete = append(keysToDelete, curKey)
		}
	}

	// Delete obsolete keys
	for _, key := range keysToDelete {
		if err := ebpfMap.Delete(key); err != nil {
			return err
		}
	}

	keys := []bpf.BpfIpHashKey{}
	vals := []bpf.BpfIpHashInfo{}
	for k, v := range entries {
		keys = append(keys, k)
		vals = append(vals, v)
	}

	// Update map
	if _, err := ebpfMap.BatchUpdate(
		keys,
		vals,
		&ebpf.BatchOptions{
			ElemFlags: uint64(ebpf.UpdateAny),
		},
	); err != nil {
		return err
	}

	return nil
}

func updateCpuRedirectionMap(
	ebpfMap *ebpf.Map,
	entries map[uint32]uint32,
) error {
	// Calculate diff between current map state and new map state
	keysToDelete := []uint32{}
	iter := ebpfMap.Iterate()
	var curKey uint32
	var curVal uint32
	for iter.Next(&curKey, &curVal) {
		if newVal, ok := entries[curKey]; ok {
			if newVal == curVal {
				// Entry already exists in map with same values,
				// we don't need to include in the batch update
				delete(entries, curKey)
			}
		} else {
			keysToDelete = append(keysToDelete, curKey)
		}
	}

	// Delete obsolete keys
	for _, key := range keysToDelete {
		if err := ebpfMap.Delete(key); err != nil {
			return err
		}
	}

	// Update map
	for k, v := range entries {
		if err := ebpfMap.Put(k, v); err != nil {
			return err
		}
	}

	return nil
}

func updateCpuTxQueueConfigMap(
	ebpfMap *ebpf.Map,
	entriesToAdd map[uint32]bpf.BpfTxqConfig,
) error {
	keys := []uint32{}
	vals := []bpf.BpfTxqConfig{}
	for k, v := range entriesToAdd {
		keys = append(keys, k)
		vals = append(vals, v)
	}

	if _, err := ebpfMap.BatchUpdate(keys, vals, &ebpf.BatchOptions{}); err != nil {
		return err
	}

	return nil
}

func updateAvailableCpuMap(
	ebpfMap *ebpf.Map,
	entriesToAdd map[uint32]uint32,
) error {
	keys := []uint32{}
	vals := []uint32{}
	for k, v := range entriesToAdd {
		keys = append(keys, k)
		vals = append(vals, v)
	}

	if _, err := ebpfMap.BatchUpdate(keys, vals, &ebpf.BatchOptions{}); err != nil {
		return err
	}

	return nil
}

func printCpuMap(m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle("CPU redirection map")
	t.AppendHeader(table.Row{"CPU", "Queue size"})

	var (
		key uint32
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		t.AppendRow([]interface{}{key, val})
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Render()

	return iter.Err()
}

func printCpusAvailableMap(m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle("Available CPUs map")
	t.AppendHeader(table.Row{"CPU", "Available"})

	var (
		key uint32
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		available := (val == bpf.CpuAvailable)
		if !available {
			continue
		}
		t.AppendRow([]interface{}{key, available})
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Render()

	return iter.Err()
}

func printDirectionMap(m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle("Interface direction map")
	t.AppendHeader(table.Row{"Ifindex", "Direction"})

	var (
		key uint32
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val == bpf.DirectionNone {
			continue
		}

		iface, err := net.InterfaceByIndex(int(key))
		if err != nil {
			slog.Error("Unable to find an interface", "index", key)
			continue
		}

		var direction string
		switch val {
		case bpf.DirectionInternet:
			direction = "Internet"
		case bpf.DirectionClient:
			direction = "Client"
		}
		t.AppendRow([]interface{}{iface.Name, direction})
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Render()

	return iter.Err()
}

func printIpToCpuAndTcMap(m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle("IP to CPU and TC handle map")
	t.AppendHeader(table.Row{"Prefix", "CPU", "TC handle"})

	var (
		key bpf.BpfIpHashKey
		val bpf.BpfIpHashInfo
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		ip := netip.AddrFrom16(key.Address.In6U.U6Addr8)
		var prefixlen int = int(key.Prefixlen)
		if ip.Is4In6() {
			prefixlen = int(key.Prefixlen) - 96
		}
		prefix := netip.PrefixFrom(ip.Unmap(), prefixlen)
		t.AppendRow([]interface{}{prefix, val.Cpu, tc.TcHandleString(val.TcHandle)})
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Render()

	return iter.Err()
}

func printTxqConfigMap(m *ebpf.Map) error {
	t := table.NewWriter()
	t.SetTitle("CPU to TX queue and TC major map")
	t.AppendHeader(table.Row{"CPU", "Queue mapping", "TC major"})

	var (
		key uint32
		val bpf.BpfTxqConfig
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if val.QueueMapping == 0 && val.TcMajor == 0 {
			continue
		}
		t.AppendRow([]interface{}{key, val.QueueMapping, val.TcMajor})
	}

	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	t.Render()

	return iter.Err()
}

func main() {
	if mode == ModeUpdate || mode == ModeClear {
		// Acquire exclusive lock
		_, err := fslock.Lock(lockPath)
		if err != nil {
			slog.Error(
				"Error acquiring exclusive lock, is another instance already running?",
				"error",
				err,
				"path",
				lockPath,
			)
			os.Exit(1)
		}
	}

	var (
		config        YamlConfig
		qsize         int
		cpuMap        map[int]bpf.BpfTxqConfig
		prefixMap     map[string]PrefixMapping
		availableCpus map[uint32]uint32
	)

	switch mode {
	case ModeShow:
		slog.Info("Showing current state of eBPF maps")
	case ModeClear:
		slog.Info("Clearing and showing new state of eBPF maps")
	case ModeUpdate:
		slog.Info("Updating and showing new state of eBPF maps")
	}

	switch mode {
	case ModeClear:
		cpuMap = map[int]bpf.BpfTxqConfig{}
		prefixMap = map[string]PrefixMapping{}
	case ModeUpdate:
		// Parse configuration file
		configFile, err := os.ReadFile(*configFilePath)
		if err != nil {
			slog.Error(
				"Couldn't open configuration file",
				"file",
				*configFilePath,
				"error",
				err.Error(),
			)
			os.Exit(1)
		}

		config = YamlConfig{}
		if err := yaml.Unmarshal(configFile, &config); err != nil {
			slog.Error(
				"Couldn't parse configuration file",
				"file",
				*configFilePath,
				"error",
				err.Error(),
			)
			os.Exit(1)
		}

		qsize = config.Qsize
		cpuMap = make(map[int]bpf.BpfTxqConfig, len(config.Cpus))
		prefixMap = make(map[string]PrefixMapping, len(config.Prefixes))

		for _, cpu := range config.Cpus {
			cpuMap[cpu.Cpu] = bpf.BpfTxqConfig{
				QueueMapping: uint16(cpu.QueueMapping),
				TcMajor:      uint16(cpu.TcMajor),
			}
		}

		for _, prefix := range config.Prefixes {
			prefixMap[prefix.Prefix] = PrefixMapping{
				Cpu:     prefix.Cpu,
				TcMinor: prefix.TcMinor,
			}
		}
	}

	bpfMaps := make(map[string]*ebpf.Map, len(bpfMapNames))
	for _, bpfMapName := range bpfMapNames {
		bpfLoadOptions := ebpf.LoadPinOptions{}

		if mode == ModeShow {
			bpfLoadOptions.ReadOnly = true
		}

		bpfMap, err := ebpf.LoadPinnedMap(
			path.Join(bpf.MapPinPath, bpfMapName),
			&bpfLoadOptions,
		)
		bpfMaps[bpfMapName] = bpfMap

		if err != nil {
			slog.Error(
				"Failed to open eBPF map",
				"map",
				bpfMapName,
				"error",
				err.Error(),
			)
			os.Exit(1)
		}
	}

	// Print interface direction map
	if err := printDirectionMap(bpfMaps["map_ifindex_direction"]); err != nil {
		slog.Error("Failed to print interface direction map", "error", err.Error())
		os.Exit(1)
	}

	if mode == ModeUpdate || mode == ModeClear {
		// Populate CPU redirects
		cpuRedirects := make(map[uint32]uint32, len(maps.Keys(cpuMap)))
		for _, cpu := range maps.Keys(cpuMap) {
			cpuRedirects[uint32(cpu)] = uint32(qsize)
		}

		// Update CPU redirection map
		if err := updateCpuRedirectionMap(bpfMaps["cpu_map"], cpuRedirects); err != nil {
			slog.Error("Failed to update CPU redirection map", "error", err.Error())
			os.Exit(1)
		}
	}

	// Print CPU redirection map
	if err := printCpuMap(bpfMaps["cpu_map"]); err != nil {
		slog.Error("Failed to print CPU redirection map", "error", err.Error())
		os.Exit(1)
	}

	if mode == ModeUpdate || mode == ModeClear {
		// Populate CPU availability and TX queue / TC major mapping
		availableCpus = make(map[uint32]uint32, bpf.MaxCpus)
		cpuTxqConfig := make(map[uint32]bpf.BpfTxqConfig, bpf.MaxCpus)
		for cpu := 0; cpu < bpf.MaxCpus; cpu++ {
			if txqConfig, ok := cpuMap[cpu]; ok {
				availableCpus[uint32(cpu)] = bpf.CpuAvailable
				cpuTxqConfig[uint32(cpu)] = txqConfig
			} else {
				availableCpus[uint32(cpu)] = bpf.CpuNotAvailable
				cpuTxqConfig[uint32(cpu)] = bpf.BpfTxqConfig{}
			}
		}

		// Update CPU TX queue config map
		if err := updateCpuTxQueueConfigMap(
			bpfMaps["map_txq_config"],
			cpuTxqConfig,
		); err != nil {
			slog.Error("Failed to update CPU TX queue map", "error", err.Error())
			os.Exit(1)
		}

		// Mark CPUs as available after bpf redirect map and TX queue config has been
		// created, but before we map IPs
		if err := updateAvailableCpuMap(
			bpfMaps["cpus_available"],
			availableCpus,
		); err != nil {
			slog.Error("Failed to update available CPUs map", "error", err.Error())
			os.Exit(1)
		}
	}

	// Print CPU TX queue config map
	if err := printTxqConfigMap(bpfMaps["map_txq_config"]); err != nil {
		slog.Error("Failed to print CPU TX queue map", "error", err.Error())
		os.Exit(1)
	}

	// Print available CPU map
	if err := printCpusAvailableMap(bpfMaps["cpus_available"]); err != nil {
		slog.Error("Failed to print available CPUs map", "error", err.Error())
		os.Exit(1)
	}

	if mode == ModeUpdate || mode == ModeClear {
		// Update CPU and TC handle map
		ipToCpuAndTcMappings := make(
			map[bpf.BpfIpHashKey]bpf.BpfIpHashInfo,
			len(maps.Keys(prefixMap)),
		)
		for cidr, mapping := range prefixMap {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				slog.Error("Can't parse CIDR", "cidr", cidr, "error", err.Error())
				os.Exit(1)
			}

			key := new(bpf.BpfIpHashKey)
			key.Address.In6U.U6Addr8 = prefix.Addr().As16()

			if prefix.Addr().Is6() {
				key.Prefixlen = uint32(prefix.Bits())
			} else {
				// Mask out IPv6 portion of IPv4-mapped IPv6 address
				key.Prefixlen = 96 + uint32(prefix.Bits())
			}

			tcMajor := int(cpuMap[mapping.Cpu].TcMajor)
			tcHandle := tc.TcHandleMake(tcMajor, mapping.TcMinor)
			val := bpf.BpfIpHashInfo{
				Cpu:      uint32(mapping.Cpu),
				TcHandle: uint32(tcHandle),
			}

			ipToCpuAndTcMappings[*key] = val
		}

		// Update IP to CPU and TC handle map
		if err := updateIpToCpuAndTcMap(
			bpfMaps["map_ip_to_cpu_and_tc"],
			ipToCpuAndTcMappings,
		); err != nil {
			slog.Error(
				"Failed to update IP to CPU and TC handle map",
				"error",
				err.Error(),
			)
			os.Exit(1)
		}
	}

	// Print IP to CPU and TC handle map
	if err := printIpToCpuAndTcMap(bpfMaps["map_ip_to_cpu_and_tc"]); err != nil {
		slog.Error("Failed to print IP to CPU and TC handle map", "error", err.Error())
		os.Exit(1)
	}
}
