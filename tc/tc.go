package tc

import "fmt"

const (
	TC_H_MAJ_MASK = uint32(0xFFFF0000)
	TC_H_MIN_MASK = uint32(0x0000FFFF)
)

func TcHandleMake(major int, minor int) uint32 {
	return ((uint32(major) << 16) & TC_H_MAJ_MASK) | (uint32(minor) & TC_H_MIN_MASK)
}

func TcHandleString(handle uint32) string {
	major := (handle & TC_H_MAJ_MASK) >> 16
	minor := (handle & TC_H_MIN_MASK)
	return fmt.Sprintf("0x%x:0x%x", major, minor)
}
