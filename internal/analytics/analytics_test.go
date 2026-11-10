package analytics

import (
	"math"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestAssociationRules(t *testing.T) {
	// 5× {modbus,s7}, 1× {modbus,http}, 4× {http}  (n=10)
	txns := [][]string{}
	for i := 0; i < 5; i++ {
		txns = append(txns, []string{"modbus", "s7"})
	}
	txns = append(txns, []string{"modbus", "http"})
	for i := 0; i < 4; i++ {
		txns = append(txns, []string{"http"})
	}
	rules := AssociationRules(txns, 0.1, 0.5, 50)
	if len(rules) == 0 {
		t.Fatal("no rules mined")
	}
	// Both directions of modbus<->s7 have lift 1.6667; s7->modbus has confidence 1.
	var s7ToModbus *Rule
	for i := range rules {
		r := rules[i]
		if len(r.Antecedent) == 1 && r.Antecedent[0] == "s7" && r.Consequent == "modbus" {
			s7ToModbus = &rules[i]
		}
	}
	if s7ToModbus == nil {
		t.Fatalf("expected s7->modbus rule; got %+v", rules)
	}
	if !approx(s7ToModbus.Confidence, 1.0) {
		t.Errorf("s7->modbus confidence = %v; want 1.0", s7ToModbus.Confidence)
	}
	if !approx(s7ToModbus.Lift, 1.0/0.6) {
		t.Errorf("s7->modbus lift = %v; want %v", s7ToModbus.Lift, 1.0/0.6)
	}
	if s7ToModbus.Count != 5 {
		t.Errorf("s7->modbus count = %d; want 5", s7ToModbus.Count)
	}
	// Rules are sorted by lift desc, so the top rule's lift is the max.
	if rules[0].Lift < s7ToModbus.Lift-1e-9 {
		t.Errorf("rules not sorted by lift: top=%v", rules[0].Lift)
	}
}

func TestAssociationRulesTripleAntecedent(t *testing.T) {
	// 6× {a,b,c}, plus noise, so {a,b}->c is minable with high confidence.
	txns := [][]string{}
	for i := 0; i < 6; i++ {
		txns = append(txns, []string{"a", "b", "c"})
	}
	txns = append(txns, []string{"a", "b"}, []string{"a"}, []string{"d"})
	rules := AssociationRules(txns, 0.2, 0.5, 100)
	found := false
	for _, r := range rules {
		if len(r.Antecedent) == 2 && r.Consequent == "c" {
			found = true
			// {a,b} count 7, {a,b,c} count 6 => confidence 6/7.
			if !approx(r.Confidence, 6.0/7.0) {
				t.Errorf("{a,b}->c confidence = %v; want %v", r.Confidence, 6.0/7.0)
			}
		}
	}
	if !found {
		t.Errorf("expected a 2-item antecedent rule ->c; rules=%+v", rules)
	}
}

func TestCoOccurrence(t *testing.T) {
	txns := [][]string{}
	for i := 0; i < 5; i++ {
		txns = append(txns, []string{"modbus", "s7"})
	}
	txns = append(txns, []string{"modbus", "http"})
	for i := 0; i < 4; i++ {
		txns = append(txns, []string{"http"})
	}
	pairs := CoOccurrence(txns, 1, 20)
	if len(pairs) == 0 {
		t.Fatal("no pairs")
	}
	top := pairs[0]
	if top.A != "modbus" || top.B != "s7" || top.Count != 5 {
		t.Errorf("top pair = %+v; want modbus/s7 count 5", top)
	}
	if !approx(top.Lift, (0.5)/(0.6*0.5)) {
		t.Errorf("lift = %v; want %v", top.Lift, (0.5)/(0.6*0.5))
	}
	if !approx(top.Jaccard, 5.0/6.0) {
		t.Errorf("jaccard = %v; want %v", top.Jaccard, 5.0/6.0)
	}
}

func TestDiversityIndices(t *testing.T) {
	uniform := map[string]int{"a": 1, "b": 1}
	if !approx(Shannon(uniform), math.Ln2) {
		t.Errorf("Shannon(uniform2) = %v; want ln2", Shannon(uniform))
	}
	if !approx(ShannonEvenness(uniform), 1.0) {
		t.Errorf("evenness(uniform2) = %v; want 1", ShannonEvenness(uniform))
	}
	if !approx(Simpson(uniform), 0.5) {
		t.Errorf("Simpson(uniform2) = %v; want 0.5", Simpson(uniform))
	}
	if !approx(Gini(uniform), 0.0) {
		t.Errorf("Gini(uniform2) = %v; want 0", Gini(uniform))
	}
	// Single category: no diversity.
	one := map[string]int{"a": 7}
	if Shannon(one) != 0 || ShannonEvenness(one) != 0 || Simpson(one) != 0 || Gini(one) != 0 {
		t.Errorf("single-category diversity should be 0: H=%v E=%v S=%v G=%v",
			Shannon(one), ShannonEvenness(one), Simpson(one), Gini(one))
	}
	// Concentrated distribution has high Gini, low evenness.
	skew := map[string]int{"a": 97, "b": 1, "c": 1, "d": 1}
	if Gini(skew) < 0.6 {
		t.Errorf("Gini(skew) = %v; want > 0.6", Gini(skew))
	}
	if ShannonEvenness(skew) > 0.3 {
		t.Errorf("evenness(skew) = %v; want < 0.3", ShannonEvenness(skew))
	}
	if Shannon(nil) != 0 {
		t.Error("Shannon(nil) should be 0")
	}
}

func TestGraphPathBetweenness(t *testing.T) {
	g := NewGraph()
	g.AddEdge("a", "b")
	g.AddEdge("b", "c")
	g.AddEdge("c", "d")
	if !g.Compute(0) {
		t.Fatal("Compute should have run betweenness")
	}
	bw := map[string]float64{}
	deg := map[string]int{}
	for _, n := range g.Nodes(0) {
		bw[n.ID] = n.Betweenness
		deg[n.ID] = n.Degree
	}
	// Path a-b-c-d: internal nodes b,c have betweenness 2; endpoints 0.
	if !approx(bw["b"], 2) || !approx(bw["c"], 2) {
		t.Errorf("path betweenness b=%v c=%v; want 2,2", bw["b"], bw["c"])
	}
	if !approx(bw["a"], 0) || !approx(bw["d"], 0) {
		t.Errorf("endpoint betweenness a=%v d=%v; want 0,0", bw["a"], bw["d"])
	}
	if deg["b"] != 2 || deg["a"] != 1 {
		t.Errorf("degrees wrong: b=%d a=%d", deg["b"], deg["a"])
	}
}

func TestGraphStarBetweennessAndPrune(t *testing.T) {
	g := NewGraph()
	g.AddNode("hub", "hub", "asn")
	for _, leaf := range []string{"x", "y", "z"} {
		g.AddEdge("hub", leaf)
	}
	g.Compute(0)
	nodes := g.Nodes(1)
	if nodes[0].ID != "hub" {
		t.Errorf("most central node = %s; want hub", nodes[0].ID)
	}
	// Star with 3 leaves: center betweenness = C(3,2) = 3.
	if !approx(nodes[0].Betweenness, 3) {
		t.Errorf("hub betweenness = %v; want 3", nodes[0].Betweenness)
	}
	if nodes[0].Kind != "asn" {
		t.Errorf("hub kind = %q; want asn", nodes[0].Kind)
	}
	// Prune degree-1 leaves: only the hub (now degree 0) is left, then it too drops.
	g2 := NewGraph()
	g2.AddEdge("hub", "x")
	g2.AddEdge("hub", "y")
	g2.AddEdge("hub", "z")
	g2.AddEdge("hub2", "x") // x now has degree 2 (a real bridge)
	removed := g2.Prune(2)
	if removed == 0 {
		t.Error("prune should have removed the degree-1 leaves y,z,hub2")
	}
	for _, n := range g2.Nodes(0) {
		if n.ID == "y" || n.ID == "z" || n.ID == "hub2" {
			t.Errorf("degree-1 node %s survived prune", n.ID)
		}
	}
}

func TestPruneFuncKindAware(t *testing.T) {
	// A hub entity shared by 3 leaf sources: entities need degree>=2, sources >=1,
	// so the hub and its three leaves all survive (a star, not emptied).
	g := NewGraph()
	g.AddNode("fp", "ja4:x", "fp")
	for _, ip := range []string{"a", "b", "c"} {
		g.AddNode(ip, ip, "source")
		g.AddEdge(ip, "fp")
	}
	// A lone source touching a non-shared entity: both must be pruned.
	g.AddNode("fp2", "ja4:y", "fp")
	g.AddNode("d", "d", "source")
	g.AddEdge("d", "fp2") // fp2 shared by only 1 source

	g.PruneFunc(func(n Node, deg int) bool {
		if n.Kind == "source" {
			return deg >= 1
		}
		return deg >= 2
	})
	ids := map[string]bool{}
	for _, n := range g.Nodes(0) {
		ids[n.ID] = true
	}
	for _, want := range []string{"fp", "a", "b", "c"} {
		if !ids[want] {
			t.Errorf("expected %q to survive the kind-aware prune", want)
		}
	}
	for _, gone := range []string{"fp2", "d"} {
		if ids[gone] {
			t.Errorf("expected %q (shared by <2 sources) to be pruned", gone)
		}
	}
}

func TestComponents(t *testing.T) {
	// Two disjoint stars => two components; add a bridge => one component.
	g := NewGraph()
	g.AddEdge("a", "h1")
	g.AddEdge("b", "h1")
	g.AddEdge("c", "h2")
	g.AddEdge("d", "h2")
	g.Compute(0)
	comps := g.Components()
	if len(comps) != 2 {
		t.Fatalf("expected 2 components, got %d", len(comps))
	}
	// Each component has 3 nodes (hub + 2 leaves).
	for _, c := range comps {
		if len(c) != 3 {
			t.Errorf("component size = %d; want 3", len(c))
		}
	}

	g.AddEdge("h1", "h2") // bridge the two hubs
	g.Compute(0)
	comps = g.Components()
	if len(comps) != 1 {
		t.Fatalf("after bridge: expected 1 component, got %d", len(comps))
	}
	if len(comps[0]) != 6 {
		t.Errorf("merged component size = %d; want 6", len(comps[0]))
	}
	// The most central node (a hub on the bridge) sorts first.
	if comps[0][0].ID != "h1" && comps[0][0].ID != "h2" {
		t.Errorf("most central node = %s; want a bridging hub", comps[0][0].ID)
	}
}

func TestGraphBetweennessSkippedWhenTooBig(t *testing.T) {
	g := NewGraph()
	g.AddEdge("a", "b")
	g.AddEdge("b", "c")
	if g.Compute(2) { // 3 nodes > cap 2
		t.Error("betweenness should be skipped above the node cap")
	}
	for _, n := range g.Nodes(0) {
		if n.Betweenness != 0 {
			t.Errorf("betweenness should be 0 when skipped: %s=%v", n.ID, n.Betweenness)
		}
		if n.Degree == 0 {
			t.Errorf("degree should still be computed: %s", n.ID)
		}
	}
}
