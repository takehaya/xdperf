package numa

import (
	"reflect"
	"testing"
)

func TestParseCPUList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"empty", "", nil, false},
		{"single", "0", []int{0}, false},
		{"multiple", "0,2,4,6", []int{0, 2, 4, 6}, false},
		{"range", "0-3", []int{0, 1, 2, 3}, false},
		{"range_and_single", "0-3,8", []int{0, 1, 2, 3, 8}, false},
		{"multi_range", "0-7,16-23", []int{0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23}, false},
		{"whitespace", " 0 , 2 , 4 ", []int{0, 2, 4}, false},
		{"unsorted", "4,1,3,2", []int{1, 2, 3, 4}, false},
		{"single_large", "127", []int{127}, false},
		{"invalid_char", "abc", nil, true},
		{"negative", "-1", nil, true},
		{"inverted_range", "5-3", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCPUList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCPUList(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCPUList(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseCPUMode(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantMode     string
		wantNodeArg  int
		wantCPUs     []int
		wantErr      bool
	}{
		{"empty", "", "", -1, nil, false},
		{"auto", "auto", "auto", -1, nil, false},
		{"local", "local", "local", -1, nil, false},
		{"balanced", "balanced", "balanced", -1, nil, false},
		{"node_0", "node:0", "node", 0, nil, false},
		{"node_1", "node:1", "node", 1, nil, false},
		{"cpu_list", "0,2,4,6", "list", -1, []int{0, 2, 4, 6}, false},
		{"cpu_range", "0-3", "list", -1, []int{0, 1, 2, 3}, false},
		{"node_negative", "node:-1", "", -1, nil, true},
		{"node_invalid", "node:abc", "", -1, nil, true},
		{"invalid_mode", "foobar", "", -1, nil, true},
		{"whitespace", " auto ", "auto", -1, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, nodeArg, cpus, err := ParseCPUMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCPUMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if mode != tt.wantMode {
					t.Errorf("ParseCPUMode(%q) mode = %q, want %q", tt.input, mode, tt.wantMode)
				}
				if nodeArg != tt.wantNodeArg {
					t.Errorf("ParseCPUMode(%q) nodeArg = %d, want %d", tt.input, nodeArg, tt.wantNodeArg)
				}
				if !reflect.DeepEqual(cpus, tt.wantCPUs) {
					t.Errorf("ParseCPUMode(%q) cpus = %v, want %v", tt.input, cpus, tt.wantCPUs)
				}
			}
		})
	}
}

// Helper to build a 2-node topology for testing.
func twoNodeTopology() *Topology {
	return &Topology{
		Nodes: []Node{
			{ID: 0, CPUs: []int{0, 1, 2, 3, 4, 5, 6, 7}},
			{ID: 1, CPUs: []int{8, 9, 10, 11, 12, 13, 14, 15}},
		},
	}
}

func singleNodeTopology() *Topology {
	return &Topology{
		Nodes: []Node{
			{ID: 0, CPUs: []int{0, 1, 2, 3}},
		},
	}
}

func TestSelectCPUsFromTopology_Auto(t *testing.T) {
	topo := twoNodeTopology()

	tests := []struct {
		name        string
		parallelism int
		nicNode     int
		want        []int
		wantErr     bool
	}{
		{"nic_node0_4cpus", 4, 0, []int{0, 1, 2, 3}, false},
		{"nic_node1_4cpus", 4, 1, []int{8, 9, 10, 11}, false},
		{"nic_node0_all_local", 8, 0, []int{0, 1, 2, 3, 4, 5, 6, 7}, false},
		{"nic_node0_spill", 10, 0, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, false},
		{"no_numa_affinity", 4, -1, []int{0, 1, 2, 3}, false},
		{"too_many_cpus", 20, 0, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCPUsFromTopology(topo, "auto", tt.parallelism, tt.nicNode)
			if (err != nil) != tt.wantErr {
				t.Errorf("auto(%d, nicNode=%d) error = %v, wantErr %v", tt.parallelism, tt.nicNode, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("auto(%d, nicNode=%d) = %v, want %v", tt.parallelism, tt.nicNode, got, tt.want)
			}
		})
	}
}

func TestSelectCPUsFromTopology_Local(t *testing.T) {
	topo := twoNodeTopology()

	tests := []struct {
		name        string
		parallelism int
		nicNode     int
		want        []int
		wantErr     bool
	}{
		{"local_node0_4cpus", 4, 0, []int{0, 1, 2, 3}, false},
		{"local_node1_4cpus", 4, 1, []int{8, 9, 10, 11}, false},
		{"local_too_many", 10, 0, nil, true},
		{"local_no_affinity", 4, -1, []int{0, 1, 2, 3}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCPUsFromTopology(topo, "local", tt.parallelism, tt.nicNode)
			if (err != nil) != tt.wantErr {
				t.Errorf("local(%d, nicNode=%d) error = %v, wantErr %v", tt.parallelism, tt.nicNode, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("local(%d, nicNode=%d) = %v, want %v", tt.parallelism, tt.nicNode, got, tt.want)
			}
		})
	}
}

func TestSelectCPUsFromTopology_Node(t *testing.T) {
	topo := twoNodeTopology()

	tests := []struct {
		name        string
		parallelism int
		nodeID      int
		want        []int
		wantErr     bool
	}{
		{"node0_4cpus", 4, 0, []int{0, 1, 2, 3}, false},
		{"node1_4cpus", 4, 1, []int{8, 9, 10, 11}, false},
		{"node_not_found", 4, 99, nil, true},
		{"node_too_many", 10, 0, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCPUsFromTopology(topo, "node", tt.parallelism, tt.nodeID)
			if (err != nil) != tt.wantErr {
				t.Errorf("node(%d, node=%d) error = %v, wantErr %v", tt.parallelism, tt.nodeID, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("node(%d, node=%d) = %v, want %v", tt.parallelism, tt.nodeID, got, tt.want)
			}
		})
	}
}

func TestSelectCPUsFromTopology_Balanced(t *testing.T) {
	topo := twoNodeTopology()

	tests := []struct {
		name        string
		parallelism int
		want        []int
		wantErr     bool
	}{
		{"balanced_4cpus", 4, []int{0, 1, 8, 9}, false},
		{"balanced_2cpus", 2, []int{0, 8}, false},
		{"balanced_6cpus", 6, []int{0, 1, 2, 8, 9, 10}, false},
		{"balanced_too_many", 20, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectCPUsFromTopology(topo, "balanced", tt.parallelism, -1)
			if (err != nil) != tt.wantErr {
				t.Errorf("balanced(%d) error = %v, wantErr %v", tt.parallelism, err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("balanced(%d) = %v, want %v", tt.parallelism, got, tt.want)
			}
		})
	}
}

func TestSelectCPUsFromTopology_SingleNode(t *testing.T) {
	topo := singleNodeTopology()

	// On single-node systems, all modes should work normally
	modes := []string{"auto", "local", "balanced"}
	for _, mode := range modes {
		t.Run(mode+"_single_node", func(t *testing.T) {
			got, err := selectCPUsFromTopology(topo, mode, 2, 0)
			if err != nil {
				t.Errorf("%s on single node: unexpected error: %v", mode, err)
				return
			}
			if !reflect.DeepEqual(got, []int{0, 1}) {
				t.Errorf("%s on single node = %v, want [0, 1]", mode, got)
			}
		})
	}
}

func TestTopology_AllCPUs(t *testing.T) {
	topo := twoNodeTopology()
	got := topo.AllCPUs()
	want := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllCPUs() = %v, want %v", got, want)
	}
}

func TestTopology_NodeByID(t *testing.T) {
	topo := twoNodeTopology()

	node := topo.NodeByID(0)
	if node == nil || node.ID != 0 {
		t.Errorf("NodeByID(0) = %v, want node 0", node)
	}

	node = topo.NodeByID(99)
	if node != nil {
		t.Errorf("NodeByID(99) = %v, want nil", node)
	}
}

func TestValidateCPUsInTopology(t *testing.T) {
	topo := twoNodeTopology() // CPUs 0-15 across two nodes

	tests := []struct {
		name    string
		cpus    []int
		wantErr bool
	}{
		{"all_valid_node0", []int{0, 1, 2, 3}, false},
		{"all_valid_spanning_nodes", []int{0, 8, 15}, false},
		{"single_valid", []int{7}, false},
		{"empty", nil, false},
		{"out_of_range_high", []int{4096}, true},
		{"just_past_end", []int{16}, true},
		{"one_invalid_among_valid", []int{0, 1, 99}, true},
		{"negative", []int{-1}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCPUsInTopology(tt.cpus, topo)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCPUsInTopology(%v) error = %v, wantErr %v", tt.cpus, err, tt.wantErr)
			}
		})
	}
}
