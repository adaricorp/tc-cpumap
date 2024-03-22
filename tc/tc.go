package tc

import (
	"encoding/csv"
	"fmt"
	"os"
)

const (
	TC_H_MAJ_MASK = uint32(0xFFFF0000)
	TC_H_MIN_MASK = uint32(0x0000FFFF)
	TC_CLASS_FILE = "/etc/iproute2/tc_cls"
)

type TcHandleNames map[string]string

func TcHandleMake(major int, minor int) uint32 {
	return ((uint32(major) << 16) & TC_H_MAJ_MASK) | (uint32(minor) & TC_H_MIN_MASK)
}

func TcHandleString(handle uint32) string {
	major := (handle & TC_H_MAJ_MASK) >> 16
	minor := (handle & TC_H_MIN_MASK)
	return fmt.Sprintf("0x%x:0x%x", major, minor)
}

func ParseTcClassFile(filename string) (TcHandleNames, error) {
	names := make(TcHandleNames)

	file, err := os.Open(filename)
	if err != nil {
		return names, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// TC class file is space-separated
	reader.Comma = ' '

	records, err := reader.ReadAll()
	if err != nil {
		return names, err
	}

	for _, record := range records {
		if len(record) != 2 {
			continue
		}
		names[record[0]] = record[1]
	}

	return names, nil
}
