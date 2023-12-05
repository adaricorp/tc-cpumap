package main

import "github.com/safchain/ethtool"

type EthtoolFeatures map[string]bool

type EthtoolCoalesceConfig map[string]uint32

type EthtoolConfig struct {
	Features EthtoolFeatures
	Coalesce ethtool.Coalesce
}

type XpsMask []byte

type TxQueueXpsConfig map[string]XpsMask
