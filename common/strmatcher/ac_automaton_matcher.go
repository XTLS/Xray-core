package strmatcher

import (
	"container/list"
)

const validCharCount = 53

type MatchType struct {
	matchType Type
	exist     bool
}

const (
	TrieEdge bool = true
	FailEdge bool = false
)

type Edge struct {
	edgeType bool
	nextNode int
}

type ACAutomaton struct {
	trie   [][validCharCount]Edge
	fail   []int
	exists []MatchType
	count  int
}

func newNode() [validCharCount]Edge {
	var s [validCharCount]Edge
	for i := range s {
		s[i] = Edge{
			edgeType: FailEdge,
			nextNode: 0,
		}
	}
	return s
}

var char2Index = []int{
	'A':  0,
	'a':  0,
	'B':  1,
	'b':  1,
	'C':  2,
	'c':  2,
	'D':  3,
	'd':  3,
	'E':  4,
	'e':  4,
	'F':  5,
	'f':  5,
	'G':  6,
	'g':  6,
	'H':  7,
	'h':  7,
	'I':  8,
	'i':  8,
	'J':  9,
	'j':  9,
	'K':  10,
	'k':  10,
	'L':  11,
	'l':  11,
	'M':  12,
	'm':  12,
	'N':  13,
	'n':  13,
	'O':  14,
	'o':  14,
	'P':  15,
	'p':  15,
	'Q':  16,
	'q':  16,
	'R':  17,
	'r':  17,
	'S':  18,
	's':  18,
	'T':  19,
	't':  19,
	'U':  20,
	'u':  20,
	'V':  21,
	'v':  21,
	'W':  22,
	'w':  22,
	'X':  23,
	'x':  23,
	'Y':  24,
	'y':  24,
	'Z':  25,
	'z':  25,
	'!':  26,
	'$':  27,
	'&':  28,
	'\'': 29,
	'(':  30,
	')':  31,
	'*':  32,
	'+':  33,
	',':  34,
	';':  35,
	'=':  36,
	':':  37,
	'%':  38,
	'-':  39,
	'.':  40,
	'_':  41,
	'~':  42,
	'0':  43,
	'1':  44,
	'2':  45,
	'3':  46,
	'4':  47,
	'5':  48,
	'6':  49,
	'7':  50,
	'8':  51,
	'9':  52,
}

func NewACAutomaton() *ACAutomaton {
	var ac = new(ACAutomaton)
	ac.trie = append(ac.trie, newNode())
	ac.fail = append(ac.fail, 0)
	ac.exists = append(ac.exists, MatchType{
		matchType: Full,
		exist:     false,
	})
	return ac
}

func (ac *ACAutomaton) Add(domain string, t Type) {
	var node = 0
	for i := len(domain) - 1; i >= 0; i-- {
		var idx = char2Index[domain[i]]
		if ac.trie[node][idx].nextNode == 0 {
			ac.count++
			if len(ac.trie) < ac.count+1 {
				ac.trie = append(ac.trie, newNode())
				ac.fail = append(ac.fail, 0)
				ac.exists = append(ac.exists, MatchType{
					matchType: Full,
					exist:     false,
				})
			}
			ac.trie[node][idx] = Edge{
				edgeType: TrieEdge,
				nextNode: ac.count,
			}
		}
		node = ac.trie[node][idx].nextNode
	}
	ac.exists[node] = MatchType{
		matchType: t,
		exist:     true,
	}
	switch t {
	case Domain:
		ac.exists[node] = MatchType{
			matchType: Full,
			exist:     true,
		}
		var idx = char2Index['.']
		if ac.trie[node][idx].nextNode == 0 {
			ac.count++
			if len(ac.trie) < ac.count+1 {
				ac.trie = append(ac.trie, newNode())
				ac.fail = append(ac.fail, 0)
				ac.exists = append(ac.exists, MatchType{
					matchType: Full,
					exist:     false,
				})
			}
			ac.trie[node][idx] = Edge{
				edgeType: TrieEdge,
				nextNode: ac.count,
			}
		}
		node = ac.trie[node][idx].nextNode
		ac.exists[node] = MatchType{
			matchType: t,
			exist:     true,
		}
	default:
		break
	}
}

func (ac *ACAutomaton) Build() {
	var queue = list.New()
	for i := 0; i < validCharCount; i++ {
		if ac.trie[0][i].nextNode != 0 {
			queue.PushBack(ac.trie[0][i])
		}
	}
	for {
		var front = queue.Front()
		if front == nil {
			break
		} else {
			var node = front.Value.(Edge).nextNode
			queue.Remove(front)
			for i := 0; i < validCharCount; i++ {
				if ac.trie[node][i].nextNode != 0 {
					ac.fail[ac.trie[node][i].nextNode] = ac.trie[ac.fail[node]][i].nextNode
					queue.PushBack(ac.trie[node][i])
				} else {
					ac.trie[node][i] = Edge{
						edgeType: FailEdge,
						nextNode: ac.trie[ac.fail[node]][i].nextNode,
					}
				}
			}
		}
	}
}

func (ac *ACAutomaton) Match(s string) bool {
	var node = 0
	var fullMatch = true
	// 1. the match string is all through trie edge. FULL MATCH or DOMAIN
	// 2. the match string is through a fail edge. NOT FULL MATCH
	// 2.1 Through a fail edge, but there exists a valid node. SUBSTR
	for i := len(s) - 1; i >= 0; i-- {
		var idx = char2Index[s[i]]
		fullMatch = fullMatch && ac.trie[node][idx].edgeType
		node = ac.trie[node][idx].nextNode
		switch ac.exists[node].matchType {
		case Substr:
			return true
		case Domain:
			if fullMatch {
				return true
			}
		default:
			break
		}
	}
	return fullMatch && ac.exists[node].exist
}
