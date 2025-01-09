package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/adaricorp/tc-cpumap/bpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/danjacques/gofslock/fslock"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/pkg/errors"
	"github.com/safchain/ethtool"
)

var (
	version = "dev"
	date    = "unknown"

	lockPath           = "/var/lock/tc_cpumap"
	internetIfaceNames *[]string
	clientIfaceNames   *[]string
	rxCpus             *[]string
	rxCpuIrqStrategy   *string
	ctZoneId           *uint
	logLevel           *string
	slogLevel          *slog.LevelVar = new(slog.LevelVar)
	bpfDebug           *bool
	// NIC offloads to disable or enable
	nicOffloads = EthtoolFeatures{
		"rx-vlan-hw-parse": false,
	}
	// NIC coalesce configuration
	nicCoalesce = EthtoolCoalesceConfig{
		"rx-usecs": 8,
		"tx-usecs": 8,
	}
)

// Print program usage
func printUsage(fs ff.Flags) {
	fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
	os.Exit(1)
}

// Print program version
func printVersion() {
	fmt.Printf("tc_cpumap v%s built on %s\n", version, date)
	os.Exit(0)
}

func init() {
	fs := ff.NewFlagSet("tc_cpumap")
	displayVersion := fs.BoolLong("version", "Print version")
	logLevel = fs.StringEnumLong(
		"log-level",
		"Log level: debug, info, warn, error",
		"info",
		"debug",
		"error",
		"warn",
	)
	bpfDebug = fs.BoolLong(
		"bpf-debug",
		"Write eBPF debug messages to /sys/kernel/debug/tracing/trace_pipe",
	)
	internetIfaceNames = fs.StringSetLong("wan", "Internet interface(s) to attach to")
	clientIfaceNames = fs.StringSetLong("lan", "Client interface(s) to attach to")
	rxCpus = fs.StringSetLong(
		"rx-cpu",
		"CPU core(s) to use for handling NIC RX queues, or \"all\" to use all CPU cores")
	rxCpuIrqStrategy = fs.StringEnumLong(
		"rx-cpu-irq-strategy",
		"Strategy to use when assigning CPU core(s) to NIC RX queues: all or round-robin",
		"all",         // RX CPU cores will be assigned IRQs for all NIC RX queues
		"round-robin", // RX CPU cores will be round-robin assigned to NIC RX queues
	)
	ctZoneId = fs.UintLong("ct-zone-id", 0, "Conntrack zone id to use for lookups")

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("TC_CPUMAP"),
		ff.WithEnvVarSplit(" "),
	)
	if err != nil {
		printUsage(fs)
	}

	if *displayVersion {
		printVersion()
	}

	if len(*internetIfaceNames) == 0 && len(*clientIfaceNames) == 0 {
		fmt.Fprintf(os.Stderr, "No network interfaces specified\n")
		printUsage(fs)
	}

	if len(*internetIfaceNames) == 0 || len(*clientIfaceNames) == 0 {
		fmt.Fprintf(
			os.Stderr,
			"Need to specify network interfaces for both Internet and Client\n",
		)
		printUsage(fs)
	}

	for _, ifaceName := range *internetIfaceNames {
		if _, err := net.InterfaceByName(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "Interface %v does not exist\n", ifaceName)
			printUsage(fs)
		}

		if slices.Contains(*clientIfaceNames, ifaceName) {
			fmt.Fprintf(
				os.Stderr,
				"Interface %v can't be used for both WAN and LAN\n",
				ifaceName,
			)
			printUsage(fs)
		}

	}

	for _, ifaceName := range *clientIfaceNames {
		if _, err := net.InterfaceByName(ifaceName); err != nil {
			fmt.Fprintf(os.Stderr, "Interface %v does not exist\n", ifaceName)
			printUsage(fs)
		}

		if slices.Contains(*internetIfaceNames, ifaceName) {
			fmt.Fprintf(
				os.Stderr,
				"Interface %v can't be used for both WAN and LAN\n",
				ifaceName,
			)
			printUsage(fs)
		}

	}

	if slices.Contains(*rxCpus, "all") {
		*rxCpus = []string{}
		for c := 0; c < runtime.NumCPU(); c++ {
			*rxCpus = append(*rxCpus, fmt.Sprintf("%d", c))

		}
	}

	for _, cpu := range *rxCpus {
		// Check CPU core exists
		cpuFile := path.Join("/sys/devices/system/cpu", fmt.Sprintf("cpu%s", cpu))
		if _, err := os.Stat(cpuFile); err != nil {
			fmt.Fprintf(os.Stderr, "CPU %v does not exist\n", cpu)
			printUsage(fs)
		}
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

// Attach bpf object to interface with XDP
func attachXdp(objs bpf.BpfObjects, iface *net.Interface) (link.Link, error) {
	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, err
	}

	slog.Info("Attached XDP eBPF program", "interface", iface.Name, "index", iface.Index)

	return l, nil
}

// Attach bpf object to interface with TCX
func attachTc(
	objs bpf.BpfObjects,
	iface *net.Interface,
) (link.Link, error) {
	// Attach the program.
	l, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcProg,
		Attach:    ebpf.AttachTCXIngress,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, err
	}

	slog.Info("Attached TC eBPF program", "interface", iface.Name, "index", iface.Index)

	return l, nil
}

// Detatch eBPF programs, unload eBPF objects and restore XPS masks
func cleanup(
	oldIfaceEthtoolConfig map[string]EthtoolConfig,
	oldXpsMasks map[string]TxQueueXpsConfig,
	oldIrqAffinities map[string]string,
	bpfObjs bpf.BpfObjects,
	links []link.Link,
) {
	for _, l := range links {
		if err := l.Close(); err != nil {
			slog.Error("Couldn't detach eBPF program from link", "error", err.Error())
		}
	}

	// Unload eBPF objects
	if err := bpfObjs.Close(); err != nil {
		slog.Error("Couldn't unload eBPF objects", "error", err.Error())
	}

	// Restore IRQ affinities
	restoreIrqAffinity(oldIrqAffinities)

	// Restore XPS masks for NIC queues back to what they were
	restoreXps(oldXpsMasks)

	// Restore NIC ethtool settings back to what they were
	restoreNic(oldIfaceEthtoolConfig)
}

// Unpin BPF maps with a signature that doesn't match with the maps we will load
func unpinIncompatibleMaps(maps map[string]*ebpf.MapSpec, opts ebpf.MapOptions) error {
	for _, bpfMap := range maps {
		if bpfMap.Pinning != ebpf.PinByName {
			continue
		}

		if _, err := ebpf.NewMapWithOptions(bpfMap, opts); errors.Is(
			err,
			ebpf.ErrMapIncompatible,
		) {
			oldMap, err := ebpf.LoadPinnedMap(
				path.Join(bpf.MapPinPath, bpfMap.Name),
				&opts.LoadPinOptions)
			if err != nil {
				return errors.Wrap(err, "Loading pinned BPF map failed")
			}

			defer func() {
				if err := oldMap.Close(); err != nil {
					slog.Error(
						"Failed to close pinned BPF map",
						"map",
						bpfMap.Name,
						"error",
						err.Error(),
					)
				}
			}()

			if err = oldMap.Unpin(); err != nil {
				return errors.Wrapf(
					err,
					"Failed to unpin BPF map: %s",
					bpfMap.Name,
				)
			}
		}
	}

	return nil
}

func loadBpf() (bpf.BpfObjects, error) {
	bpfSpec, err := bpf.LoadBpf()
	if err != nil {
		return bpf.BpfObjects{}, errors.Wrap(err, "Parsing BPF ELF file failed")
	}

	if err := bpfSpec.Variables["CT_ZONE_ID"].Set(uint16(*ctZoneId)); err != nil {
		slog.Error("Couldn't rewrite CT_ZONE_ID constant", "error", err.Error())
	}

	if _, err := os.Stat("/sys/kernel/btf/nf_conntrack"); err == nil {
		conntrackSpec, err := btf.LoadKernelModuleSpec("nf_conntrack")
		if err != nil {
			slog.Error("Couldn't load nf_conntrack BTF", "error", err.Error())
		} else {
			iter := conntrackSpec.Iterate()
			for iter.Next() {
				if _, ok := iter.Type.(*btf.Enum); !ok {
					continue
				}
				for _, i := range iter.Type.(*btf.Enum).Values {
					if i.Name == "NF_BPF_CT_OPTS_SZ" {
						if err := bpfSpec.Variables["BPF_CT_OPTS_SIZE"].Set(uint32(i.Value)); err != nil {
							slog.Error(
								"Couldn't rewrite BPF_CT_OPTS_SIZE constant",
								"error", err.Error(),
							)
						}
					}
				}
			}
		}
	}

	bpfProgOpts := ebpf.ProgramOptions{}
	if *bpfDebug {
		// Enable debug logging
		slogLevel.Set(slog.LevelDebug)

		// Turn on verifier instruction level debugging
		bpfProgOpts.LogLevel = ebpf.LogLevelInstruction

		// Rewrite BPF program to enable per-packet debug logging to
		// /sys/kernel/debug/tracing/trace_pipe
		if err := bpfSpec.Variables["DEBUG"].Set(bool(true)); err != nil {
			slog.Error("Couldn't rewrite debug constant", "error", err.Error())
		}
	}

	bpfMapOpts := ebpf.MapOptions{
		// Pin the map to the BPF filesystem and configure the
		// library to automatically re-write it in the BPF
		// program so it can be re-used if it already exists or
		// create it if not
		PinPath:        bpf.MapPinPath,
		LoadPinOptions: ebpf.LoadPinOptions{},
	}

	objs := bpf.BpfObjects{}

	if err := unpinIncompatibleMaps(bpfSpec.Maps, bpfMapOpts); err != nil {
		return bpf.BpfObjects{}, errors.Wrap(err, "Unpinning incompatible BPF maps failed")
	}

	if err := bpfSpec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Programs: bpfProgOpts,
		Maps:     bpfMapOpts,
	}); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "BPF verifier error: %+v\n", ve)
		}

		return bpf.BpfObjects{}, errors.Wrap(err, "Loading BPF objects failed")
	}

	return objs, nil
}

func attachBpf(objs bpf.BpfObjects) ([]link.Link, error) {
	links := []link.Link{}

	for _, ifaceName := range append(*internetIfaceNames, *clientIfaceNames...) {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		link, err := attachXdp(objs, iface)
		if err != nil {
			return links, errors.Wrapf(
				err, "Couldn't attach XDP eBPF program to interface %v", ifaceName,
			)
		}
		links = append(links, link)

		link, err = attachTc(objs, iface)
		if err != nil {
			return links, errors.Wrapf(
				err, "Couldn't attach TC eBPF program to interface %v", ifaceName,
			)
		}
		links = append(links, link)
	}

	for _, ifaceName := range *internetIfaceNames {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		if err := objs.MapIfindexDirection.Update(
			uint32(iface.Index),
			uint32(bpf.DirectionInternet),
			ebpf.UpdateAny,
		); err != nil {
			return links, errors.Wrap(err, "Failed to write to map")
		}
	}

	for _, ifaceName := range *clientIfaceNames {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		if err := objs.MapIfindexDirection.Update(
			int32(iface.Index),
			int32(bpf.DirectionClient),
			ebpf.UpdateAny,
		); err != nil {
			return links, errors.Wrap(err, "Failed to write to map")
		}
	}

	return links, nil
}

func getIfaceQueues(ifaceName string, direction string) (map[string]string, error) {
	if direction != "rx" && direction != "tx" {
		return map[string]string{}, errors.New("Direction must be rx or tx")

	}

	queuesGlob := path.Join("/sys/class/net", ifaceName, "queues", direction+"-*")

	queueDirs, err := filepath.Glob(queuesGlob)
	if err != nil {
		return map[string]string{}, errors.Wrapf(
			err, "Couldn't read sysfs for interface %v", ifaceName,
		)
	}

	if len(queueDirs) == 0 {
		return map[string]string{}, errors.New(
			fmt.Sprintf("Interface %v has no %v queues", ifaceName, direction),
		)
	}

	queues := make(map[string]string, len(queueDirs))

	for _, queueDir := range queueDirs {
		id := filepath.Base(queueDir)
		queues[id] = filepath.Base(queueDir)
	}

	return queues, nil
}

func configureNic(
	ethtoolFeatures EthtoolFeatures,
	ethtoolCoalesceConfig EthtoolCoalesceConfig,
) (map[string]EthtoolConfig, error) {
	ifaces := append(*internetIfaceNames, *clientIfaceNames...)

	oldIfaceEthtoolConfig := make(map[string]EthtoolConfig, len(ifaces))

	ethtool, err := ethtool.NewEthtool()
	if err != nil {
		return oldIfaceEthtoolConfig, errors.Wrap(err, "Couldn't create new ethtool")
	}
	defer ethtool.Close()

	for _, ifaceName := range ifaces {
		// Handle features

		features, err := ethtool.Features(ifaceName)
		if err != nil {
			return oldIfaceEthtoolConfig, errors.Wrapf(
				err,
				"Couldn't get features for %v",
				ifaceName,
			)
		}

		curFeatureConfig := EthtoolFeatures{}
		newFeatureConfig := EthtoolFeatures{}
		for offload, newState := range ethtoolFeatures {
			if _, ok := features[offload]; ok {
				curFeatureConfig[offload] = features[offload]
				newFeatureConfig[offload] = newState
			}
		}

		oldIfaceEthtoolConfig[ifaceName] = EthtoolConfig{
			Features: curFeatureConfig,
		}

		if err = ethtool.Change(ifaceName, newFeatureConfig); err != nil {
			return oldIfaceEthtoolConfig, errors.Wrapf(
				err,
				"Couldn't set features for %v",
				ifaceName,
			)
		}

		// Handle coalesce config

		curCoalesce, err := ethtool.GetCoalesce(ifaceName)
		if err != nil {
			return oldIfaceEthtoolConfig, errors.Wrapf(
				err,
				"Couldn't get coalesce configuration for %v",
				ifaceName,
			)
		}

		oldIfaceEthtoolConfig[ifaceName] = EthtoolConfig{
			Features: curFeatureConfig,
			Coalesce: curCoalesce,
		}

		newCoalesce := curCoalesce

		for config, value := range ethtoolCoalesceConfig {
			switch config {
			case "rx-usecs":
				newCoalesce.RxCoalesceUsecs = value
			case "tx-usecs":
				newCoalesce.TxCoalesceUsecs = value
			}
		}

		if _, err := ethtool.SetCoalesce(ifaceName, newCoalesce); err != nil {
			slog.Error(
				"Couldn't set coalesce configuration",
				"interface",
				ifaceName,
				"error",
				err,
			)
		}
	}

	return oldIfaceEthtoolConfig, nil
}

func restoreNic(oldIfaceEthtoolConfig map[string]EthtoolConfig) {
	ethtool, err := ethtool.NewEthtool()
	if err != nil {
		slog.Error("Couldn't create new ethtool", "error", err.Error())
	}
	defer ethtool.Close()

	for ifaceName, ethtoolConfig := range oldIfaceEthtoolConfig {
		if err = ethtool.Change(ifaceName, ethtoolConfig.Features); err != nil {
			slog.Error("Couldn't set features", "interface", ifaceName)
		}

		if _, err = ethtool.SetCoalesce(ifaceName, ethtoolConfig.Coalesce); err != nil {
			slog.Error(
				"Couldn't set coalesce configuration",
				"interface",
				ifaceName,
				"error",
				err,
			)
		}
	}
}

func disableXps() (map[string]TxQueueXpsConfig, error) {
	ifaces := append(*internetIfaceNames, *clientIfaceNames...)

	oldXpsMasks := make(map[string]TxQueueXpsConfig, len(ifaces))

	for _, ifaceName := range ifaces {
		txQueues, err := getIfaceQueues(ifaceName, "tx")
		if err != nil {
			return oldXpsMasks, errors.Wrapf(
				err,
				"Couldn't get TX queues for %v",
				ifaceName,
			)
		}

		oldXpsMasks[ifaceName] = make(TxQueueXpsConfig, len(txQueues))

		for id, queue := range txQueues {
			xpsCpusFile := path.Join(
				"/sys/class/net", ifaceName, "queues", queue, "xps_cpus",
			)

			mask, err := os.ReadFile(xpsCpusFile)
			if err != nil {
				return oldXpsMasks, err
			}
			oldXpsMasks[ifaceName][id] = mask

			// Disable XPS
			newMask := XpsMask{0}

			if err := os.WriteFile(xpsCpusFile, newMask, 0644); err != nil {
				return oldXpsMasks, errors.Wrapf(
					err,
					"Couldn't disable XPS on %v %v",
					ifaceName,
					queue,
				)
			}
		}
	}

	return oldXpsMasks, nil
}

func restoreXps(oldXpsMasks map[string]TxQueueXpsConfig) {
	for ifaceName, queues := range oldXpsMasks {
		for queue, mask := range queues {
			xpsCpusFile := path.Join(
				"/sys/class/net", ifaceName, "queues", queue, "xps_cpus",
			)

			if err := os.WriteFile(xpsCpusFile, mask, 0644); err != nil {
				slog.Error(
					"Couldn't restore original XPS mask",
					"interface",
					ifaceName,
					"queue",
					queue,
					"mask",
					string(mask),
				)
			}
		}
	}
}

func irqAffinity() (map[string]string, error) {
	ifaces := append(*internetIfaceNames, *clientIfaceNames...)

	oldIrqAffinities := make(map[string]string, len(ifaces))

	irqs := []string{}
	for _, ifaceName := range ifaces {
		symlink, err := filepath.EvalSymlinks(fmt.Sprintf("/sys/class/net/%s", ifaceName))
		if err != nil {
			return oldIrqAffinities, errors.Wrapf(
				err,
				"Couldn't find %v in /sys",
				ifaceName,
			)
		}
		irqsDir := fmt.Sprintf(
			"%s/msi_irqs",
			strings.Join(strings.Split(symlink, "/")[0:6], "/"),
		)
		irqsGlob := path.Join(irqsDir, "*")
		irqFiles, err := filepath.Glob(irqsGlob)
		if err != nil {
			return oldIrqAffinities, errors.Wrapf(
				err,
				"Couldn't find msi_irqs for %v",
				ifaceName,
			)
		}

		for _, irqFile := range irqFiles {
			irq := filepath.Base(irqFile)

			buf, err := os.ReadFile(
				path.Join("/sys/kernel/irq", irq, "actions"),
			)
			irqActions := string(buf)
			if err != nil {
				return oldIrqAffinities, errors.Wrapf(
					err,
					"Couldn't read actions for IRQ %v",
					irq,
				)
			}

			if strings.Contains(irqActions, "async") ||
				strings.Contains(irqActions, "fdir") {
				// Skip certain types of NIC IRQs
				continue
			}

			irqs = append(irqs, irq)
		}
	}

	for i, irq := range irqs {
		affinityListFile := path.Join("/proc/irq", irq, "smp_affinity_list")
		buf, err := os.ReadFile(affinityListFile)
		if err != nil {
			return oldIrqAffinities, errors.Wrapf(
				err,
				"Couldn't read smp_affinity_list for IRQ %v",
				irq,
			)
		}

		oldIrqAffinities[irq] = string(buf)

		var cpuList string
		switch *rxCpuIrqStrategy {
		case "all":
			cpuList = strings.Join(*rxCpus, ",")
		case "round-robin":
			cpuList = (*rxCpus)[i%len(*rxCpus)]
		}

		if err := os.WriteFile(affinityListFile, []byte(cpuList), 0644); err != nil {
			return oldIrqAffinities, errors.Wrapf(
				err,
				"Couldn't write smp_affinity_list for IRQ %v",
				irq,
			)
		}
	}

	return oldIrqAffinities, nil
}

func restoreIrqAffinity(oldIrqAffinities map[string]string) {
	for irq, affinity := range oldIrqAffinities {
		affinityListFile := path.Join("/proc/irq", irq, "smp_affinity_list")
		if err := os.WriteFile(affinityListFile, []byte(affinity), 0644); err != nil {
			slog.Error(
				"Couldn't restore original CPU affinity",
				"irq",
				irq,
				"affinity",
				affinity,
			)
		}
	}
}

func main() {
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

	slog.Info(
		"Starting tc_cpumap",
		"version",
		version,
		"build_context",
		fmt.Sprintf(
			"go=%s, platform=%s",
			runtime.Version(),
			runtime.GOOS+"/"+runtime.GOARCH,
		),
	)

	// Variables used for cleanup
	var (
		oldIfaceEthtoolConfig map[string]EthtoolConfig
		oldXpsMasks           = map[string]TxQueueXpsConfig{}
		oldIrqAffinities      = map[string]string{}
		bpfObjs               = bpf.BpfObjects{}
		links                 = []link.Link{}
	)

	slog.Info("Configuring NIC")

	oldIfaceEthtoolConfig, err = configureNic(nicOffloads, nicCoalesce)
	if err != nil {
		slog.Error("Couldn't configure NIC", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			oldIrqAffinities,
			bpfObjs,
			links,
		)
		os.Exit(1)
	}

	slog.Info("Disabling XPS")

	oldXpsMasks, err = disableXps()
	if err != nil {
		slog.Error("Couldn't disable XPS", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			oldIrqAffinities,
			bpfObjs,
			links,
		)
		os.Exit(1)
	}

	if len(*rxCpus) > 0 {
		slog.Info("Configuring RX CPU cores")

		oldIrqAffinities, err = irqAffinity()
		if err != nil {
			slog.Error("Couldn't set IRQ affinity", "error", err.Error())
			cleanup(
				oldIfaceEthtoolConfig,
				oldXpsMasks,
				oldIrqAffinities,
				bpfObjs,
				links,
			)
			os.Exit(1)
		}
	}

	slog.Info("Loading eBPF programs and maps")

	bpfObjs, err = loadBpf()
	if err != nil {
		slog.Error("Couldn't load BPF objects", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			oldIrqAffinities,
			bpfObjs,
			links,
		)
		os.Exit(1)
	}

	slog.Info("Attaching eBPF programs to interfaces")

	if links, err = attachBpf(bpfObjs); err != nil {
		slog.Error("Couldn't attach BPF objects", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			oldIrqAffinities,
			bpfObjs,
			links,
		)
		os.Exit(1)
	}

	slog.Info("Press Ctrl-C to exit and remove the program")

	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)
	<-exitSignal
	// On exit clean up
	cleanup(
		oldIfaceEthtoolConfig,
		oldXpsMasks,
		oldIrqAffinities,
		bpfObjs,
		links,
	)
}
