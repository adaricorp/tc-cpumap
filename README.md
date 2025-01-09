# tc\_cpumap

In normal operation, TC is limited to a single classful qdisc per interface
and because TC qdiscs require a global lock to operate this effectively
limits TC to a single CPU core. This is known as the qdisc locking problem.

One solution to this problem is to build independent classful
qdiscs per CPU core and map packets to these CPU cores (e.g. by IP prefix).
The eBPF XDP cpumap feature is used to redirect packets to the right CPU core
based on IP prefix, eBPF is also used to set the appropriate NIC TX queue
and TC class ID for each packet.

This project is largely based on the work of the following projects:

   * https://github.com/xdp-project/xdp-cpumap-tc/
   * https://github.com/LibreQoE/LibreQoS/

## Features

 * Supports handling SNAT traffic
 * Supports multiple LAN interfaces
 * Capture basic traffic statistics (byte and packet counters)

## Requirements

 * Minimum of 2 network interfaces (1x WAN and 1x LAN)
 * Network interfaces must have multiple TX and RX queues
 * Linux 6.6+

## Downloading

Download prebuilt binaries from [GitHub](https://github.com/adaricorp/tc-cpumap/releases/latest).

## Building

Binaries can be compiled from source by using the following instructions:

### Install build dependencies

First, install the build dependencies:

#### Ubuntu

```
apt install clang curl linux-tools-common linux-tools-$(uname -r) llvm
```

#### Debian

```
apt install bpftool clang curl llvm
```

### Build

Second, build binaries with GoReleaser:

```
./build.sh
```

## Running

To load the eBPF programs into the kernel and attach to the network interfaces, run:

```
sudo tc_cpumap --wan eno1 --lan eno2
```

It is also possible to configure tc\_cpumap by using envionment variables:

```
sudo TC_CPUMAP_WAN="eno1" TC_CPUMAP_LAN="eno2 eno3" tc_cpumap
```

## Configuring

First, load the TC qdiscs and classes, xdp-cpumap-tc provides an
[example script](https://github.com/xdp-project/xdp-cpumap-tc/blob/master/bin/tc_mq_htb_setup_example.sh)
that shows how to do this.

Second, prepare a configuration file that maps IP prefixes to CPUs and TC classes, an
[example config](https://github.com/adaricorp/tc-cpumap/blob/main/sample-configs/tc-cpumap.yml)
is provided to show the format.

Third, load the configuration file to activate the system.

```
sudo tc_cpumap_config update --config tc-cpumap.yml
```

## Traffic statistics

Current traffic statistics can be printed by running the following command:

```
sudo tc_cpumap_trafficstats
```
