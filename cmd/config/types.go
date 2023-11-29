package main

type YamlConfig struct {
	Qsize int `yaml:"qsize"`
	Cpus  []struct {
		Cpu          int `yaml:"cpu"`
		QueueMapping int `yaml:"queue_mapping"`
		TcMajor      int `yaml:"tc_major"`
	} `yaml:"cpus"`
	Prefixes []struct {
		Prefix  string `yaml:"prefix"`
		Cpu     int    `yaml:"cpu"`
		TcMinor int    `yaml:"tc_minor"`
	} `yaml:"prefixes"`
}

type PrefixMapping struct {
	Cpu     int
	TcMinor int
}

type Mode int
