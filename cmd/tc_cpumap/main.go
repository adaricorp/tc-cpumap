package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"slices"
	"syscall"

	"git.adari.cloud/adari/tc_cpumap/bpf"

	"golang.org/x/sys/unix"

	"github.com/carlmjohnson/versioninfo"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/danjacques/gofslock/fslock"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/pkg/errors"
	"github.com/safchain/ethtool"
)

var (
	lockPath           = "/var/lock/tc_cpumap"
	internetIfaceNames *[]string
	clientIfaceNames   *[]string
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
	fmt.Printf("tc_cpumap %s\n", versioninfo.Short())
	os.Exit(0)
}

func init() {
	fs := ff.NewFlagSet("tc_cpumap")
	internetIfaceNames = fs.StringSetLong("wan", "Internet interface(s) to attach to")
	clientIfaceNames = fs.StringSetLong("lan", "Client interface(s) to attach to")
	logLevel = fs.StringEnumLong(
		"log-level",
		"Log level: debug, info, warn, error",
		"info",
		"debug",
		"error",
		"warn",
	)
	version := fs.BoolLong("version", "Print version")
	bpfDebug = fs.BoolLong("bpf-debug", "Run eBPF in debugging mode")

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("TC_CPUMAP"),
		ff.WithEnvVarSplit(" "),
	)
	if err != nil {
		printUsage(fs)
	}

	if *version {
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

func attachTc(
	tcnl *tc.Tc,
	objs bpf.BpfObjects,
	iface *net.Interface,
) (tc.Object, error) {
	// Create a qdisc/clsact object that will be attached to the ingress part
	// of the networking interface.
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}

	// Attach the qdisc/clsact to the networking interface.
	// This TC clsact may already exist if we didn't cleanly shutdown or some other program
	// has created a clsact on this interface, if that is the case write an error to stderr,
	// delete the old clsact and create our own
	tcSuccess := false
	for retries := 1; retries <= 2; retries++ {
		if err := tcnl.Qdisc().Add(&qdisc); err != nil {
			slog.Error(
				"Couldn't assign TC clsact",
				"interface",
				iface.Name,
				"error",
				err.Error(),
			)

			if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
				slog.Error(
					"Couldn't delete TC clsact",
					"interface",
					iface.Name,
					"error",
					err.Error(),
				)
			}
		} else {
			tcSuccess = true
			break
		}
	}

	if !tcSuccess {
		return qdisc, errors.New(
			fmt.Sprintf("Couldn't create new TC clsact for for %v", iface.Name),
		)
	}

	fd := uint32(objs.TcProg.FD())
	flags := uint32(0x1)

	// Create a tc/filter object that will attach the eBPF program to the qdisc/clsact.
	filter := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fd,
				Flags: &flags,
			},
		},
	}

	// Attach the tc/filter object with the eBPF program to the qdisc/clsact.
	if err := tcnl.Filter().Add(&filter); err != nil {
		return qdisc, errors.Wrapf(
			err,
			"Couldn't attach TC filter for eBPF program to %v",
			iface.Name,
		)
	}

	slog.Info("Attached TC eBPF program", "interface", iface.Name, "index", iface.Index)

	return qdisc, nil
}

// Detatch eBPF programs, unload eBPF objects, restore XPS masks and close TC netlink connection
func cleanup(
	oldIfaceEthtoolConfig map[string]EthtoolConfig,
	oldXpsMasks map[string]TxQueueXpsConfig,
	objs bpf.BpfObjects,
	links []link.Link,
	tcnl *tc.Tc,
	tcQdiscs []tc.Object,
) {
	for _, l := range links {
		if err := l.Close(); err != nil {
			slog.Error("Couldn't detach eBPF program from link", "error", err.Error())
		}
	}

	for _, qdisc := range tcQdiscs {
		if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
			slog.Error("Couldn't remove TC clsact", "error", err.Error())
		}
	}

	// Unload eBPF objects
	if err := objs.Close(); err != nil {
		slog.Error("Couldn't unload eBPF objects", "error", err.Error())
	}

	// Restore XPS masks for NIC queues back to what they were
	restoreXps(oldXpsMasks)

	// Restore NIC ethtool settings back to what they were
	restoreNic(oldIfaceEthtoolConfig)

	if tcnl != nil {
		if err := tcnl.Close(); err != nil {
			slog.Error("Couldn't close rtnetlink socket", "error", err.Error())
		}
	}
}

func loadBpf() (bpf.BpfObjects, error) {
	bpfSpec, err := bpf.LoadBpf()
	if err != nil {
		return bpf.BpfObjects{}, errors.Wrap(err, "Parsing BPF ELF file failed")
	}

	bpfProgOpts := ebpf.ProgramOptions{}
	if *bpfDebug {
		// Enable debug logging
		slogLevel.Set(slog.LevelDebug)

		// Turn on verifier instruction level debugging
		bpfProgOpts.LogLevel = ebpf.LogLevelInstruction
		bpfProgOpts.LogSize = 1000000000

		// Rewrite BPF program to enable per-packet debug logging to
		// /sys/kernel/debug/tracing/trace_pipe
		if err := bpfSpec.RewriteConstants(map[string]interface{}{
			"DEBUG": bool(true),
		}); err != nil {
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

func attachBpf(tcnl *tc.Tc, objs bpf.BpfObjects) ([]link.Link, []tc.Object, error) {
	links := []link.Link{}
	tcQdiscs := []tc.Object{}

	for _, ifaceName := range append(*internetIfaceNames, *clientIfaceNames...) {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, tcQdiscs, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		link, err := attachXdp(objs, iface)
		if err != nil {
			return links, tcQdiscs, errors.Wrapf(
				err, "Couldn't attach XDP eBPF program to interface %v", ifaceName,
			)
		}
		links = append(links, link)

		qdisc, err := attachTc(tcnl, objs, iface)
		if err != nil {
			return links, tcQdiscs, errors.Wrapf(
				err, "Couldn't attach TC eBPF program to interface %v", ifaceName,
			)
		}
		tcQdiscs = append(tcQdiscs, qdisc)
	}

	for _, ifaceName := range *internetIfaceNames {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, tcQdiscs, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		if err := objs.MapIfindexDirection.Update(
			uint32(iface.Index),
			uint32(bpf.DirectionInternet),
			ebpf.UpdateAny,
		); err != nil {
			return links, tcQdiscs, errors.Wrap(err, "Failed to write to map")
		}
	}

	for _, ifaceName := range *clientIfaceNames {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return links, tcQdiscs, errors.Wrapf(
				err, "Couldn't find network interface %v", ifaceName,
			)
		}

		if err := objs.MapIfindexDirection.Update(
			int32(iface.Index),
			int32(bpf.DirectionClient),
			ebpf.UpdateAny,
		); err != nil {
			return links, tcQdiscs, errors.Wrap(err, "Failed to write to map")
		}
	}

	return links, tcQdiscs, nil
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
		if err != nil {
			return map[string]string{}, err
		}
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
			mask, err := os.ReadFile(
				path.Join("/sys/class/net", ifaceName, "queues", queue, "xps_cpus"),
			)
			if err != nil {
				return oldXpsMasks, err
			}
			oldXpsMasks[ifaceName][id] = mask

			// Disable XPS
			newMask := XpsMask{0}

			if err := os.WriteFile(
				path.Join("/sys/class/net", ifaceName, "queues", queue, "xps_cpus"),
				newMask,
				0644,
			); err != nil {
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
			if err := os.WriteFile(
				path.Join("/sys/class/net", ifaceName, "queues", queue, "xps_cpus"),
				mask,
				0644,
			); err != nil {
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

	slog.Info("Configuring NIC")

	oldIfaceEthtoolConfig, err := configureNic(nicOffloads, nicCoalesce)
	if err != nil {
		slog.Error("Couldn't configure NIC", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			map[string]TxQueueXpsConfig{},
			bpf.BpfObjects{},
			[]link.Link{},
			nil,
			[]tc.Object{},
		)
		os.Exit(1)
	}

	slog.Info("Disabling XPS")

	oldXpsMasks, err := disableXps()
	if err != nil {
		slog.Error("Couldn't disable XPS", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			bpf.BpfObjects{},
			[]link.Link{},
			nil,
			[]tc.Object{},
		)
		os.Exit(1)
	}

	slog.Info("Loading eBPF programs and maps")

	objs, err := loadBpf()
	if err != nil {
		slog.Error("Couldn't load BPF objects", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			objs,
			[]link.Link{},
			nil,
			[]tc.Object{},
		)
		os.Exit(1)
	}

	// Open a netlink/tc connection to the Linux kernel. This connection is
	// used to manage the tc/qdisc and tc/filter to which
	// the eBPF program will be attached
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		slog.Error("Couldn't open rtnetlink socket", "error", err.Error())
		cleanup(
			oldIfaceEthtoolConfig,
			oldXpsMasks,
			objs,
			[]link.Link{},
			tcnl,
			[]tc.Object{},
		)
		os.Exit(1)
	}

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel.
	//
	// If not supported, `unix.ENOPROTOOPT` is returned.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		slog.Error(
			"Could not enable netlink ExtendedAcknowledge option",
			"error",
			err.Error(),
		)
	}

	slog.Info("Attaching eBPF programs to interfaces")

	var links []link.Link
	var tcQdiscs []tc.Object
	if links, tcQdiscs, err = attachBpf(tcnl, objs); err != nil {
		slog.Error("Couldn't attach BPF objects", "error", err.Error())
		cleanup(oldIfaceEthtoolConfig, oldXpsMasks, objs, links, tcnl, tcQdiscs)
		os.Exit(1)
	}

	slog.Info("Press Ctrl-C to exit and remove the program")

	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)
	<-exitSignal
	// On exit clean up
	cleanup(oldIfaceEthtoolConfig, oldXpsMasks, objs, links, tcnl, tcQdiscs)
}
