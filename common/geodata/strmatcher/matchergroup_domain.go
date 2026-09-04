package strmatcher

type trieNode struct {
	values   []uint32
	children map[string]*trieNode
}

// DomainMatcherGroup is an implementation of MatcherGroup.
// It uses trie to optimize both memory consumption and lookup speed. Trie node is domain label based.
type DomainMatcherGroup struct {
	root *trieNode
}

func NewDomainMatcherGroup() *DomainMatcherGroup {
	return &DomainMatcherGroup{
		root: new(trieNode),
	}
}

// AddDomainMatcher implements MatcherGroupForDomain.AddDomainMatcher.
func (g *DomainMatcherGroup) AddDomainMatcher(matcher DomainMatcher, value uint32) {
	node := g.root
	pattern := matcher.Pattern()
	for i := len(pattern); i > 0; {
		var part string
		for j := i - 1; ; j-- {
			if pattern[j] == '.' {
				part = pattern[j+1 : i]
				i = j
				break
			}
			if j == 0 {
				part = pattern[j:i]
				i = j
				break
			}
		}
		if node.children == nil {
			node.children = make(map[string]*trieNode)
		}
		next := node.children[part]
		if next == nil {
			next = new(trieNode)
			node.children[part] = next
		}
		node = next
	}

	node.values = append(node.values, value)
}

// Match implements MatcherGroup.Match.
func (g *DomainMatcherGroup) Match(input string) []uint32 {
	matches := make([][]uint32, 0, 5)
	node := g.root
	for i := len(input); i > 0; {
		for j := i - 1; ; j-- {
			if input[j] == '.' { // Domain label found
				node = node.children[input[j+1:i]]
				i = j
				break
			}
			if j == 0 { // The last part of domain label
				node = node.children[input[j:i]]
				i = j
				break
			}
		}
		if node == nil { // No more match if no trie edge transition
			break
		}
		if len(node.values) > 0 { // Found matched matchers
			matches = append(matches, node.values)
		}
		if node.children == nil { // No more match if leaf node reached
			break
		}
	}
	return CompositeMatchesReverse(matches)
}

// MatchAny implements MatcherGroup.MatchAny.
func (g *DomainMatcherGroup) MatchAny(input string) bool {
	node := g.root
	for i := len(input); i > 0; {
		for j := i - 1; ; j-- {
			if input[j] == '.' {
				node = node.children[input[j+1:i]]
				i = j
				break
			}
			if j == 0 {
				node = node.children[input[j:i]]
				i = j
				break
			}
		}
		if node == nil {
			return false
		}
		if len(node.values) > 0 {
			return true
		}
		if node.children == nil {
			return false
		}
	}
	return false
}
