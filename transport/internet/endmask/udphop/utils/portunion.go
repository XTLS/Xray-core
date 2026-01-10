package utils

import (
	"sort"
	"strconv"
	"strings"
)

// PortUnion is a collection of multiple port ranges.
type PortUnion []PortRange

// PortRange represents a range of ports.
// Start and End are inclusive. [Start, End]
type PortRange struct {
	Start, End uint16
}

// ParsePortUnion parses a string of comma-separated port ranges (or single ports) into a PortUnion.
// Returns nil if the input is invalid.
// The returned PortUnion is guaranteed to be normalized.
func ParsePortUnion(s string) PortUnion {
	if s == "all" || s == "*" {
		// Wildcard special case
		return PortUnion{PortRange{0, 65535}}
	}
	var result PortUnion
	portStrs := strings.Split(s, ",")
	for _, portStr := range portStrs {
		if strings.Contains(portStr, "-") {
			// Port range
			portRange := strings.Split(portStr, "-")
			if len(portRange) != 2 {
				return nil
			}
			start, err := strconv.ParseUint(portRange[0], 10, 16)
			if err != nil {
				return nil
			}
			end, err := strconv.ParseUint(portRange[1], 10, 16)
			if err != nil {
				return nil
			}
			if start > end {
				start, end = end, start
			}
			result = append(result, PortRange{uint16(start), uint16(end)})
		} else {
			// Single port
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return nil
			}
			result = append(result, PortRange{uint16(port), uint16(port)})
		}
	}
	if result == nil {
		return nil
	}
	return result.Normalize()
}

// Normalize normalizes a PortUnion.
// No overlapping ranges, ranges are sorted from low to high.
func (u PortUnion) Normalize() PortUnion {
	if len(u) == 0 {
		return u
	}
	sort.Slice(u, func(i, j int) bool {
		if u[i].Start == u[j].Start {
			return u[i].End < u[j].End
		}
		return u[i].Start < u[j].Start
	})
	normalized := PortUnion{u[0]}
	for _, current := range u[1:] {
		last := &normalized[len(normalized)-1]
		if uint32(current.Start) <= uint32(last.End)+1 {
			if current.End > last.End {
				last.End = current.End
			}
		} else {
			normalized = append(normalized, current)
		}
	}
	return normalized
}

// Ports returns all ports in the PortUnion as a slice.
func (u PortUnion) Ports() []uint16 {
	var ports []uint16
	for _, r := range u {
		for i := uint32(r.Start); i <= uint32(r.End); i++ {
			ports = append(ports, uint16(i))
		}
	}
	return ports
}

// Contains returns true if the PortUnion contains the given port.
func (u PortUnion) Contains(port uint16) bool {
	for _, r := range u {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}
