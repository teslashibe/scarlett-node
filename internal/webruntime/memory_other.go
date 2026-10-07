//go:build unix && !darwin && !linux

package webruntime

import "errors"

func processTable() ([]procInfo, error) { return nil, errors.New("process table unsupported") }
func treeMemory(tree []procInfo) uint64 { return sumBytes(tree) }
func physicalMemory() (uint64, error)   { return 0, errors.New("physical memory unsupported") }
