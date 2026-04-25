package strmatcher

type trieNode2 struct {
	matched  bool
	children map[string]*trieNode2
}

// DomainMatcherSet is an implementation of MatcherSet.
// It uses trie to optimize both memory consumption and lookup speed. Trie node is domain label based.
type DomainMatcherSet struct {
	root *trieNode2
}

func NewDomainMatcherSet() *DomainMatcherSet {
	return &DomainMatcherSet{
		root: new(trieNode2),
	}
}

// AddDomainMatcher implements MatcherSetForDomain.AddDomainMatcher.
func (s *DomainMatcherSet) AddDomainMatcher(matcher DomainMatcher) {
	node := s.root
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
			node.children = make(map[string]*trieNode2)
		}
		next := node.children[part]
		if next == nil {
			next = new(trieNode2)
			node.children[part] = next
		}
		node = next
	}

	node.matched = true
}

// MatchAny implements MatcherSet.MatchAny.
func (s *DomainMatcherSet) MatchAny(input string) bool {
	node := s.root
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
		if node.matched {
			return true
		}
		if node.children == nil {
			return false
		}
	}
	return false
}
