package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// Stat represents a single statistic entry.
type Stat struct {
	Name  string `json:"name"`
	Value int64  `json:"value,omitempty"`
}

// StatsFile represents the structure of the stats file.
type StatsFile struct {
	Stat []Stat `json:"stat"`
}

// readStatsFile reads and parses the JSON stats file.
func readStatsFile(filePath string) (*StatsFile, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	byteValue, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var stats StatsFile
	if err := json.Unmarshal(byteValue, &stats); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return &stats, nil
}

// restoreStatistics restores statistics from a JSON file to the server's stats manager.
// It reads the stats from the specified file, registers the counters and sets their values.
//
// Parameters:
// - server: The Xray server instance.
// - filePath: The path to the JSON file containing the statistics.
func RestoreStatistics(server core.Server, filePath string) {
	inst, ok := server.(*core.Instance)
	if !ok {
		fmt.Println("Failed to restore stats: server is not an instance")
		return
	}

	statsManager := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	if statsManager == nil {
		fmt.Println("Failed to restore stats: statsManager is nil")
		return
	}

	statsFile, err := readStatsFile(filePath)
	if err != nil {
		fmt.Println("Error reading stats file:", err)
		return
	}

	registeredCounters := 0
	for _, stat := range statsFile.Stat {
		c := statsManager.GetCounter(stat.Name)
		if c == nil {
			c, err = statsManager.RegisterCounter(stat.Name)
			if err != nil {
				fmt.Println("Error registering counter \""+stat.Name+"\":", err)
				continue
			}
		}

		if stat.Value > 0 {
			c.Set(stat.Value)
			registeredCounters++
		}
	}

	msg := fmt.Sprintf("Read stat entries: %d; Counters registered: %d.",
		len(statsFile.Stat), registeredCounters)
	fmt.Println(msg)
}
