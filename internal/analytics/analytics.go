// Package analytics provides deterministic (non-ML) relational and statistical
// analytics over honeypot events: association-rule / co-occurrence mining,
// an infrastructure pivot graph with degree and betweenness centrality, and
// ecological diversity indices. Everything here is pure — it takes plain
// transactions / counts / edges and returns results — so it is engine- and
// UI-agnostic and fully unit-testable.
package analytics

import (
	"math"
	"sort"
)

// ---------------------------------------------------------------------------
// Association-rule / co-occurrence mining (Apriori up to 3-itemsets)
// ---------------------------------------------------------------------------

// Rule is a mined association rule Antecedent -> Consequent over itemset
// transactions (e.g. "a source that uses tool X and hits port 445 also probes
// CVE-Y"). Support is the fraction of transactions containing the whole rule;
// Confidence is P(consequent | antecedent); Lift is Confidence divided by the
// consequent's own support (>1 = positively associated, 1 = independent).
type Rule struct {
	Antecedent []string
	Consequent string
	Count      int
	Support    float64
	Confidence float64
	Lift       float64
}

// Pair is a symmetric item co-occurrence with its lift and Jaccard overlap.
type Pair struct {
	A, B    string
	Count   int
	Lift    float64
	Jaccard float64
}

// normalizeTxns de-duplicates each transaction into a set and drops empties.
func normalizeTxns(txns [][]string) []map[string]bool {
	out := make([]map[string]bool, 0, len(txns))
	for _, t := range txns {
		s := make(map[string]bool, len(t))
		for _, it := range t {
			if it != "" {
				s[it] = true
			}
		}
		if len(s) > 0 {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(s map[string]bool) []string {
	ks := make([]string, 0, len(s))
	for k := range s {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// frequentItemsSorted returns s's items that pass the L1 frequency filter, sorted
// so pair/triple keys are canonical (A < B < C).
func frequentItemsSorted(s map[string]bool, freq1 map[string]int) []string {
	items := make([]string, 0, len(s))
	for it := range s {
		if _, ok := freq1[it]; ok {
			items = append(items, it)
		}
	}
	sort.Strings(items)
	return items
}

// AssociationRules mines rules with antecedent size 1 and 2 from itemset
// transactions using Apriori up to 3-itemsets. minSupport and minConfidence are
// fractions in [0,1]. Returns up to maxRules rules sorted by lift, then
// confidence, then support (all descending). Transactions are de-duplicated and
// empties ignored; item order within a transaction does not matter.
func AssociationRules(txns [][]string, minSupport, minConfidence float64, maxRules int) []Rule {
	sets := normalizeTxns(txns)
	n := len(sets)
	if n == 0 {
		return nil
	}
	minCount := int(math.Ceil(minSupport * float64(n)))
	if minCount < 1 {
		minCount = 1
	}

	// L1: frequent single items.
	c1 := map[string]int{}
	for _, s := range sets {
		for it := range s {
			c1[it]++
		}
	}
	freq1 := map[string]int{}
	for it, c := range c1 {
		if c >= minCount {
			freq1[it] = c
		}
	}

	// L2: frequent pairs among frequent items.
	pairCount := map[[2]string]int{}
	for _, s := range sets {
		items := frequentItemsSorted(s, freq1)
		for i := 0; i < len(items); i++ {
			for j := i + 1; j < len(items); j++ {
				pairCount[[2]string{items[i], items[j]}]++
			}
		}
	}
	freq2 := map[[2]string]int{}
	for p, c := range pairCount {
		if c >= minCount {
			freq2[p] = c
		}
	}

	// L3: frequent triples whose three sub-pairs are all frequent (Apriori prune).
	tripleCount := map[[3]string]int{}
	for _, s := range sets {
		items := frequentItemsSorted(s, freq1)
		for i := 0; i < len(items); i++ {
			for j := i + 1; j < len(items); j++ {
				if freq2[[2]string{items[i], items[j]}] < minCount {
					continue
				}
				for k := j + 1; k < len(items); k++ {
					if freq2[[2]string{items[i], items[k]}] < minCount || freq2[[2]string{items[j], items[k]}] < minCount {
						continue
					}
					tripleCount[[3]string{items[i], items[j], items[k]}]++
				}
			}
		}
	}

	var rules []Rule
	add := func(ant []string, cons string, joint, antCount, consCount int) {
		if antCount == 0 || consCount == 0 {
			return
		}
		conf := float64(joint) / float64(antCount)
		if conf < minConfidence {
			return
		}
		rules = append(rules, Rule{
			Antecedent: append([]string(nil), ant...),
			Consequent: cons,
			Count:      joint,
			Support:    float64(joint) / float64(n),
			Confidence: conf,
			Lift:       conf / (float64(consCount) / float64(n)),
		})
	}
	// Size-1 antecedents from pairs (both directions).
	for p, c := range freq2 {
		add([]string{p[0]}, p[1], c, freq1[p[0]], freq1[p[1]])
		add([]string{p[1]}, p[0], c, freq1[p[1]], freq1[p[0]])
	}
	// Size-2 antecedents from triples.
	for tp, c := range tripleCount {
		if c < minCount {
			continue
		}
		a, b, cc := tp[0], tp[1], tp[2]
		add([]string{a, b}, cc, c, freq2[[2]string{a, b}], freq1[cc])
		add([]string{a, cc}, b, c, freq2[[2]string{a, cc}], freq1[b])
		add([]string{b, cc}, a, c, freq2[[2]string{b, cc}], freq1[a])
	}

	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Lift != rules[j].Lift {
			return rules[i].Lift > rules[j].Lift
		}
		if rules[i].Confidence != rules[j].Confidence {
			return rules[i].Confidence > rules[j].Confidence
		}
		if rules[i].Support != rules[j].Support {
			return rules[i].Support > rules[j].Support
		}
		return ruleKey(rules[i]) < ruleKey(rules[j])
	})
	if maxRules > 0 && len(rules) > maxRules {
		rules = rules[:maxRules]
	}
	return rules
}

func ruleKey(r Rule) string {
	k := r.Consequent + "<="
	for _, a := range r.Antecedent {
		k += a + ","
	}
	return k
}

// CoOccurrence returns item pairs that co-occur in at least minCount
// transactions, with their lift and Jaccard overlap, sorted by count (then
// name) descending, capped at maxPairs. Unlike AssociationRules this is symmetric
// and keeps all pairs (no L1 prune), for a co-occurrence matrix / chord view.
func CoOccurrence(txns [][]string, minCount, maxPairs int) []Pair {
	sets := normalizeTxns(txns)
	n := len(sets)
	if n == 0 {
		return nil
	}
	c1 := map[string]int{}
	for _, s := range sets {
		for it := range s {
			c1[it]++
		}
	}
	pc := map[[2]string]int{}
	for _, s := range sets {
		items := sortedKeys(s)
		for i := 0; i < len(items); i++ {
			for j := i + 1; j < len(items); j++ {
				pc[[2]string{items[i], items[j]}]++
			}
		}
	}
	var out []Pair
	for p, c := range pc {
		if c < minCount {
			continue
		}
		ca, cb := c1[p[0]], c1[p[1]]
		lift := (float64(c) / float64(n)) / ((float64(ca) / float64(n)) * (float64(cb) / float64(n)))
		jac := 0.0
		if d := ca + cb - c; d > 0 {
			jac = float64(c) / float64(d)
		}
		out = append(out, Pair{A: p[0], B: p[1], Count: c, Lift: lift, Jaccard: jac})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].A+"|"+out[i].B < out[j].A+"|"+out[j].B
	})
	if maxPairs > 0 && len(out) > maxPairs {
		out = out[:maxPairs]
	}
	return out
}

// ---------------------------------------------------------------------------
// Diversity indices
// ---------------------------------------------------------------------------

func total(counts map[string]int) (sum, k int) {
	for _, c := range counts {
		if c > 0 {
			sum += c
			k++
		}
	}
	return
}

// Shannon returns the Shannon entropy H = -Σ p·ln p (in nats) of a category
// count distribution; 0 for an empty or single-category distribution.
func Shannon(counts map[string]int) float64 {
	sum, _ := total(counts)
	if sum == 0 {
		return 0
	}
	h := 0.0
	for _, c := range counts {
		if c <= 0 {
			continue
		}
		p := float64(c) / float64(sum)
		h -= p * math.Log(p)
	}
	if h < 0 {
		h = 0
	}
	return h
}

// ShannonEvenness is Pielou's evenness H / ln(k) in [0,1]: 1 = perfectly spread
// across its k categories, →0 = concentrated in one. 0 when k<=1.
func ShannonEvenness(counts map[string]int) float64 {
	_, k := total(counts)
	if k <= 1 {
		return 0
	}
	return Shannon(counts) / math.Log(float64(k))
}

// Simpson returns the Gini-Simpson index 1 - Σ p² in [0,1): the probability that
// two draws fall in different categories. 0 for empty/single-category.
func Simpson(counts map[string]int) float64 {
	sum, _ := total(counts)
	if sum == 0 {
		return 0
	}
	s := 0.0
	for _, c := range counts {
		if c <= 0 {
			continue
		}
		p := float64(c) / float64(sum)
		s += p * p
	}
	return 1 - s
}

// Gini returns the Gini coefficient in [0,1] of the count distribution: 0 =
// perfectly even, →1 = all mass in one category (concentration/inequality).
func Gini(counts map[string]int) float64 {
	xs := make([]float64, 0, len(counts))
	for _, c := range counts {
		if c > 0 {
			xs = append(xs, float64(c))
		}
	}
	n := len(xs)
	if n == 0 {
		return 0
	}
	sort.Float64s(xs)
	var sum, cum float64
	for i, x := range xs {
		sum += x
		cum += float64(i+1) * x
	}
	if sum == 0 {
		return 0
	}
	return (2*cum)/(float64(n)*sum) - float64(n+1)/float64(n)
}

// ---------------------------------------------------------------------------
// Infrastructure pivot graph + centrality
// ---------------------------------------------------------------------------

// Node is a vertex of the pivot graph (an IP, ASN, fingerprint, domain, cred, …)
// with its computed degree and betweenness centrality.
type Node struct {
	ID          string
	Label       string
	Kind        string
	Degree      int
	Betweenness float64
}

// Edge is an undirected link with a multiplicity weight.
type Edge struct {
	From, To string
	Weight   int
}

// Graph is an undirected multigraph-collapsed-to-weighted pivot graph.
type Graph struct {
	nodes map[string]*Node
	order []string
	adj   map[string]map[string]int
}

func NewGraph() *Graph {
	return &Graph{nodes: map[string]*Node{}, adj: map[string]map[string]int{}}
}

// AddNode adds a vertex (idempotent; fills a blank label/kind on re-add).
func (g *Graph) AddNode(id, label, kind string) {
	if nd, ok := g.nodes[id]; ok {
		if nd.Label == "" {
			nd.Label = label
		}
		if nd.Kind == "" {
			nd.Kind = kind
		}
		return
	}
	g.nodes[id] = &Node{ID: id, Label: label, Kind: kind}
	g.order = append(g.order, id)
	g.adj[id] = map[string]int{}
}

// AddEdge adds/strengthens an undirected edge, creating endpoints as needed.
func (g *Graph) AddEdge(a, b string) {
	if a == b || a == "" || b == "" {
		return
	}
	g.AddNode(a, a, "")
	g.AddNode(b, b, "")
	g.adj[a][b]++
	g.adj[b][a]++
}

func (g *Graph) NodeCount() int { return len(g.order) }

// Prune removes every vertex whose degree is below minDegree (repeatedly, so a
// chain of now-isolated nodes also drops), keeping the graph to its connective
// core. Returns the number of vertices removed.
func (g *Graph) Prune(minDegree int) int {
	removed := 0
	for {
		var drop []string
		for id, nbrs := range g.adj {
			if len(nbrs) < minDegree {
				drop = append(drop, id)
			}
		}
		if len(drop) == 0 {
			break
		}
		for _, id := range drop {
			for nb := range g.adj[id] {
				delete(g.adj[nb], id)
			}
			delete(g.adj, id)
			delete(g.nodes, id)
		}
		removed += len(drop)
	}
	// Rebuild order to drop removed ids (preserve insertion order).
	kept := g.order[:0]
	for _, id := range g.order {
		if _, ok := g.nodes[id]; ok {
			kept = append(kept, id)
		}
	}
	g.order = kept
	return removed
}

// PruneFunc repeatedly removes every vertex for which keep(node, currentDegree)
// is false, until the graph is stable (so a node that becomes isolated after its
// neighbors are dropped is removed too). Returns the number of vertices removed.
// Use it for kind-aware pruning, e.g. "entities need degree ≥2 but source IPs
// need only ≥1", which keeps a shared hub and the leaf sources around it.
func (g *Graph) PruneFunc(keep func(n Node, degree int) bool) int {
	removed := 0
	for {
		var drop []string
		for id, nbrs := range g.adj {
			if !keep(*g.nodes[id], len(nbrs)) {
				drop = append(drop, id)
			}
		}
		if len(drop) == 0 {
			break
		}
		for _, id := range drop {
			for nb := range g.adj[id] {
				delete(g.adj[nb], id)
			}
			delete(g.adj, id)
			delete(g.nodes, id)
		}
		removed += len(drop)
	}
	kept := g.order[:0]
	for _, id := range g.order {
		if _, ok := g.nodes[id]; ok {
			kept = append(kept, id)
		}
	}
	g.order = kept
	return removed
}

// Compute fills Degree for every node and, when the graph has at most
// maxBetweennessNodes vertices, Betweenness via Brandes' algorithm. Above that
// size betweenness is skipped (left 0) to bound cost; degree is always filled.
// Returns true if betweenness was computed.
func (g *Graph) Compute(maxBetweennessNodes int) bool {
	for id, nbrs := range g.adj {
		g.nodes[id].Degree = len(nbrs)
	}
	if maxBetweennessNodes > 0 && len(g.order) > maxBetweennessNodes {
		return false
	}
	g.brandes()
	return true
}

// brandes computes unweighted betweenness centrality (Brandes 2001) and stores
// it per node, halved for the undirected graph.
func (g *Graph) brandes() {
	cb := make(map[string]float64, len(g.order))
	for _, s := range g.order {
		stack := make([]string, 0, len(g.order))
		pred := make(map[string][]string, len(g.order))
		sigma := make(map[string]float64, len(g.order))
		dist := make(map[string]int, len(g.order))
		for _, v := range g.order {
			dist[v] = -1
		}
		sigma[s] = 1
		dist[s] = 0
		queue := []string{s}
		for len(queue) > 0 {
			v := queue[0]
			queue = queue[1:]
			stack = append(stack, v)
			for w := range g.adj[v] {
				if dist[w] < 0 {
					dist[w] = dist[v] + 1
					queue = append(queue, w)
				}
				if dist[w] == dist[v]+1 {
					sigma[w] += sigma[v]
					pred[w] = append(pred[w], v)
				}
			}
		}
		delta := make(map[string]float64, len(g.order))
		for i := len(stack) - 1; i >= 0; i-- {
			w := stack[i]
			for _, v := range pred[w] {
				delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
			}
			if w != s {
				cb[w] += delta[w]
			}
		}
	}
	for _, v := range g.order {
		g.nodes[v].Betweenness = cb[v] / 2 // undirected: each shortest path counted twice
	}
}

// Nodes returns a copy of all vertices sorted by betweenness, then degree, then
// id (all descending except id). limit<=0 returns all.
func (g *Graph) Nodes(limit int) []Node {
	out := make([]Node, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, *g.nodes[id])
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Betweenness != out[j].Betweenness {
			return out[i].Betweenness > out[j].Betweenness
		}
		if out[i].Degree != out[j].Degree {
			return out[i].Degree > out[j].Degree
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Components returns the connected components of the (undirected) graph, each as
// a node slice sorted by betweenness then degree then id (so the most central
// node of a component comes first), with the components themselves sorted by
// size descending. On the pivot graph a component with ≥2 source IPs is a
// campaign cluster: sources tied together by shared infrastructure.
func (g *Graph) Components() [][]Node {
	visited := make(map[string]bool, len(g.order))
	var comps [][]Node
	for _, start := range g.order {
		if visited[start] {
			continue
		}
		visited[start] = true
		queue := []string{start}
		var comp []Node
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			comp = append(comp, *g.nodes[id])
			for nb := range g.adj[id] {
				if !visited[nb] {
					visited[nb] = true
					queue = append(queue, nb)
				}
			}
		}
		sort.Slice(comp, func(i, j int) bool {
			if comp[i].Betweenness != comp[j].Betweenness {
				return comp[i].Betweenness > comp[j].Betweenness
			}
			if comp[i].Degree != comp[j].Degree {
				return comp[i].Degree > comp[j].Degree
			}
			return comp[i].ID < comp[j].ID
		})
		comps = append(comps, comp)
	}
	sort.Slice(comps, func(i, j int) bool {
		if len(comps[i]) != len(comps[j]) {
			return len(comps[i]) > len(comps[j])
		}
		return comps[i][0].ID < comps[j][0].ID
	})
	return comps
}

// Edges returns a copy of all undirected edges (each pair once), sorted.
func (g *Graph) Edges() []Edge {
	seen := map[[2]string]bool{}
	var out []Edge
	for _, a := range g.order {
		for b, w := range g.adj[a] {
			key := [2]string{a, b}
			if a > b {
				key = [2]string{b, a}
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Edge{From: key[0], To: key[1], Weight: w})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		return out[i].To < out[j].To
	})
	return out
}
