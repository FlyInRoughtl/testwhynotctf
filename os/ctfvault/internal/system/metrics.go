package system

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	CPUPercent  float64
	MemUsedMB   int
	MemTotalMB  int
}

func Snapshot() (Metrics, error) {
	if runtime.GOOS != "linux" {
		return Metrics{}, errors.New("metrics: linux only")
	}
	cpu1, err := readCPU()
	if err != nil {
		return Metrics{}, err
	}
	time.Sleep(120 * time.Millisecond)
	cpu2, err := readCPU()
	if err != nil {
		return Metrics{}, err
	}
	deltaTotal := cpu2.total - cpu1.total
	deltaIdle := cpu2.idle - cpu1.idle
	cpuPercent := 0.0
	if deltaTotal > 0 {
		cpuPercent = (1.0 - float64(deltaIdle)/float64(deltaTotal)) * 100
	}

	memTotal, memFree, err := readMem()
	if err != nil {
		return Metrics{}, err
	}
	used := memTotal - memFree
	return Metrics{
		CPUPercent: cpuPercent,
		MemUsedMB:  used / 1024,
		MemTotalMB: memTotal / 1024,
	}, nil
}

func FormatMetrics(m Metrics) string {
	return fmt.Sprintf("CPU: %.1f%%\nRAM: %dMB / %dMB", m.CPUPercent, m.MemUsedMB, m.MemTotalMB)
}

type cpuSample struct {
	total uint64
	idle  uint64
}

func readCPU() (cpuSample, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "cpu ") {
			parts := strings.Fields(line)
			if len(parts) < 5 {
				break
			}
			var vals []uint64
			for _, p := range parts[1:] {
				n, err := strconv.ParseUint(p, 10, 64)
				if err != nil {
					n = 0
				}
				vals = append(vals, n)
			}
			var total uint64
			for _, v := range vals {
				total += v
			}
			idle := uint64(0)
			if len(vals) > 3 {
				idle = vals[3]
			}
			return cpuSample{total: total, idle: idle}, nil
		}
	}
	return cpuSample{}, errors.New("cpu stats not found")
}

func readMem() (totalKB int, freeKB int, err error) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(data), "\n")
	mem := map[string]int{}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, _ := strconv.Atoi(parts[1])
		mem[key] = val
	}
	total := mem["MemTotal"]
	free := mem["MemAvailable"]
	if free == 0 {
		free = mem["MemFree"]
	}
	if total == 0 {
		return 0, 0, errors.New("mem stats not found")
	}
	return total, free, nil
}
