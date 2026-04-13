package numa

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Node represents a single NUMA node with its CPU list.
type Node struct {
	ID   int
	CPUs []int // sorted
}

// Topology represents the system's NUMA topology.
type Topology struct {
	Nodes []Node
}

// AllCPUs returns all CPUs across all NUMA nodes, sorted.
func (t *Topology) AllCPUs() []int {
	var all []int
	for _, n := range t.Nodes {
		all = append(all, n.CPUs...)
	}
	sort.Ints(all)
	return all
}

// TotalCPUs returns the total number of CPUs across all NUMA nodes.
func (t *Topology) TotalCPUs() int {
	n := 0
	for _, node := range t.Nodes {
		n += len(node.CPUs)
	}
	return n
}

// NodeByID returns the node with the given ID, or nil if not found.
func (t *Topology) NodeByID(id int) *Node {
	for i := range t.Nodes {
		if t.Nodes[i].ID == id {
			return &t.Nodes[i]
		}
	}
	return nil
}

// DetectTopology reads NUMA topology from sysfs.
// Returns a single-node topology with all CPUs on non-NUMA systems.
func DetectTopology() (*Topology, error) {
	onlineData, err := os.ReadFile("/sys/devices/system/node/online")
	if err != nil {
		return detectFallbackTopology()
	}

	nodeIDs, err := ParseCPUList(strings.TrimSpace(string(onlineData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse online nodes: %w", err)
	}

	var nodes []Node
	for _, nodeID := range nodeIDs {
		cpulistPath := fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", nodeID)
		cpuData, err := os.ReadFile(cpulistPath)
		if err != nil {
			continue
		}
		cpus, err := ParseCPUList(strings.TrimSpace(string(cpuData)))
		if err != nil {
			continue
		}
		if len(cpus) > 0 {
			nodes = append(nodes, Node{ID: nodeID, CPUs: cpus})
		}
	}

	if len(nodes) == 0 {
		return detectFallbackTopology()
	}

	return &Topology{Nodes: nodes}, nil
}

func detectFallbackTopology() (*Topology, error) {
	cpuData, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, fmt.Errorf("failed to read online CPUs: %w", err)
	}
	cpus, err := ParseCPUList(strings.TrimSpace(string(cpuData)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse online CPUs: %w", err)
	}
	return &Topology{
		Nodes: []Node{{ID: 0, CPUs: cpus}},
	}, nil
}

// DetectNICNode returns the NUMA node ID for a network device.
// Returns -1 if the device has no NUMA affinity or the info is unavailable.
func DetectNICNode(deviceName string) int {
	data, err := os.ReadFile(filepath.Join("/sys/class/net", deviceName, "device/numa_node"))
	if err != nil {
		return -1
	}
	node, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return -1
	}
	return node
}

func sequentialCPUs(n int) []int {
	cpus := make([]int, n)
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

// SelectCPUs picks CPUs based on mode, parallelism, and device name.
func SelectCPUs(mode string, parallelism int, deviceName string) ([]int, error) {
	parsedMode, nodeArg, explicitCPUs, err := ParseCPUMode(mode)
	if err != nil {
		return nil, err
	}

	if parsedMode == "" {
		return sequentialCPUs(parallelism), nil
	}

	if parsedMode == "list" {
		return explicitCPUs, nil
	}

	topo, err := DetectTopology()
	if err != nil {
		if parsedMode == "auto" {
			return sequentialCPUs(parallelism), nil
		}
		return nil, fmt.Errorf("failed to detect NUMA topology: %w", err)
	}

	nicNode := DetectNICNode(deviceName)
	if parsedMode == "node" {
		nicNode = nodeArg
	}
	return selectCPUsFromTopology(topo, parsedMode, parallelism, nicNode)
}

func selectCPUsFromTopology(topo *Topology, mode string, parallelism int, nicNode int) ([]int, error) {
	switch mode {
	case "auto":
		return selectAuto(topo, parallelism, nicNode)
	case "local":
		return selectLocal(topo, parallelism, nicNode)
	case "node":
		return selectNode(topo, parallelism, nicNode)
	case "balanced":
		return selectBalanced(topo, parallelism)
	default:
		return nil, fmt.Errorf("unknown CPU mode: %q", mode)
	}
}

// firstNCPUs returns the first n CPUs from all nodes. Used as fallback when no NUMA affinity.
func firstNCPUs(topo *Topology, parallelism int) ([]int, error) {
	all := topo.AllCPUs()
	if parallelism > len(all) {
		return nil, fmt.Errorf("requested parallelism (%d) exceeds available CPUs (%d)", parallelism, len(all))
	}
	return all[:parallelism], nil
}

func selectAuto(topo *Topology, parallelism int, nicNode int) ([]int, error) {
	if nicNode < 0 {
		return firstNCPUs(topo, parallelism)
	}

	node := topo.NodeByID(nicNode)
	if node == nil {
		return firstNCPUs(topo, parallelism)
	}

	if parallelism <= len(node.CPUs) {
		return node.CPUs[:parallelism], nil
	}

	// Need more CPUs: start with local node, then fill from others
	selected := make([]int, 0, parallelism)
	selected = append(selected, node.CPUs...)

	for _, n := range topo.Nodes {
		if n.ID == nicNode {
			continue
		}
		for _, cpu := range n.CPUs {
			selected = append(selected, cpu)
			if len(selected) >= parallelism {
				sort.Ints(selected)
				return selected[:parallelism], nil
			}
		}
	}

	return nil, fmt.Errorf("requested parallelism (%d) exceeds available CPUs (%d)", parallelism, len(selected))
}

func selectLocal(topo *Topology, parallelism int, nicNode int) ([]int, error) {
	if nicNode < 0 {
		return firstNCPUs(topo, parallelism)
	}

	node := topo.NodeByID(nicNode)
	if node == nil {
		return nil, fmt.Errorf("NIC NUMA node %d not found in topology", nicNode)
	}

	if parallelism > len(node.CPUs) {
		return nil, fmt.Errorf("requested parallelism (%d) exceeds CPUs on NUMA node %d (%d CPUs available)", parallelism, nicNode, len(node.CPUs))
	}

	return node.CPUs[:parallelism], nil
}

func selectNode(topo *Topology, parallelism int, nodeID int) ([]int, error) {
	node := topo.NodeByID(nodeID)
	if node == nil {
		return nil, fmt.Errorf("NUMA node %d not found in topology", nodeID)
	}

	if parallelism > len(node.CPUs) {
		return nil, fmt.Errorf("requested parallelism (%d) exceeds CPUs on NUMA node %d (%d CPUs available)", parallelism, nodeID, len(node.CPUs))
	}

	return node.CPUs[:parallelism], nil
}

func selectBalanced(topo *Topology, parallelism int) ([]int, error) {
	if parallelism > topo.TotalCPUs() {
		return nil, fmt.Errorf("requested parallelism (%d) exceeds available CPUs (%d)", parallelism, topo.TotalCPUs())
	}

	selected := make([]int, 0, parallelism)
	nodeIndices := make([]int, len(topo.Nodes))

	for len(selected) < parallelism {
		added := false
		for i := range topo.Nodes {
			if nodeIndices[i] < len(topo.Nodes[i].CPUs) {
				selected = append(selected, topo.Nodes[i].CPUs[nodeIndices[i]])
				nodeIndices[i]++
				added = true
				if len(selected) >= parallelism {
					break
				}
			}
		}
		if !added {
			break
		}
	}

	sort.Ints(selected)
	return selected, nil
}

// ParseCPUMode parses the --cpu-mode flag value.
// Returns (mode, nodeArg, explicitCPUs, error).
//
// Examples:
//
//	""          -> ("", -1, nil, nil)           // legacy sequential
//	"auto"      -> ("auto", -1, nil, nil)
//	"local"     -> ("local", -1, nil, nil)
//	"balanced"  -> ("balanced", -1, nil, nil)
//	"node:2"    -> ("node", 2, nil, nil)
//	"0,2,4,6"   -> ("list", -1, [0,2,4,6], nil)
func ParseCPUMode(s string) (mode string, nodeArg int, explicitCPUs []int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", -1, nil, nil
	}

	switch s {
	case "auto", "local", "balanced":
		return s, -1, nil, nil
	}

	if nodeStr, ok := strings.CutPrefix(s, "node:"); ok {
		n, err := strconv.Atoi(nodeStr)
		if err != nil {
			return "", -1, nil, fmt.Errorf("invalid node ID in %q: %w", s, err)
		}
		if n < 0 {
			return "", -1, nil, fmt.Errorf("node ID must be non-negative, got %d", n)
		}
		return "node", n, nil, nil
	}

	cpus, err := ParseCPUList(s)
	if err != nil {
		return "", -1, nil, fmt.Errorf("invalid cpu-mode %q: must be auto, local, balanced, node:<N>, or a CPU list (e.g., 0,2,4,6): %w", s, err)
	}
	if len(cpus) == 0 {
		return "", -1, nil, fmt.Errorf("empty CPU list in %q", s)
	}
	return "list", -1, cpus, nil
}

// ParseCPUList parses a Linux cpulist format string into a sorted slice of CPU IDs.
// Supports formats like "0-7", "0,2,4,6", "0-3,8", "0-7,16-23".
func ParseCPUList(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	var cpus []int
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid CPU range start %q: %w", bounds[0], err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid CPU range end %q: %w", bounds[1], err)
			}
			if start < 0 || end < 0 {
				return nil, fmt.Errorf("CPU IDs must be non-negative, got range %d-%d", start, end)
			}
			if start > end {
				return nil, fmt.Errorf("invalid CPU range: %d > %d", start, end)
			}
			for i := start; i <= end; i++ {
				cpus = append(cpus, i)
			}
		} else {
			cpu, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CPU ID %q: %w", part, err)
			}
			if cpu < 0 {
				return nil, fmt.Errorf("CPU ID must be non-negative, got %d", cpu)
			}
			cpus = append(cpus, cpu)
		}
	}

	sort.Ints(cpus)
	return cpus, nil
}
