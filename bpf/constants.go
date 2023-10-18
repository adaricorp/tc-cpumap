package bpf

const (
	/* Interface (ifindex) direction type */
	DirectionNone     = 0
	DirectionInternet = 1
	DirectionClient   = 2

	/* This ifindex limit is an artifical limit that can easily be bumped.
	 * The reason for this is allowing to use a faster BPF_MAP_TYPE_ARRAY
	 * in fast-path lookups.
	 */
	MaxIfindex = 256

	// Maximum number of client IPs we are tracking
	MaxTrackedIps = 64000

	// Maximum number of TC class mappings to support
	IpHashEntriesMax = 64000

	// Maximum number of supported CPUs
	MaxCpus = 1024

	// Maximum number of TCP flows to track at once
	MaxFlows = IpHashEntriesMax * 2

	// Maximum number of packet pairs to track per flow.
	MaxPackets = MaxFlows

	CpuAvailable    = 0xffffffff
	CpuNotAvailable = 0

	MapPinPath = "/sys/fs/bpf"
)
