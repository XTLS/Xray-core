package strmatcher

// LinearAnyMatcher is an implementation of AnyMatcher.
type LinearAnyMatcher struct {
	full   *FullMatcherSet
	domain *DomainMatcherSet
	substr *SubstrMatcherSet
	regex  *SimpleMatcherSet
}

func NewLinearAnyMatcher() *LinearAnyMatcher {
	return new(LinearAnyMatcher)
}

// Add implements AnyMatcher.Add.
func (s *LinearAnyMatcher) Add(matcher Matcher) {
	switch matcher := matcher.(type) {
	case FullMatcher:
		if s.full == nil {
			s.full = NewFullMatcherSet()
		}
		s.full.AddFullMatcher(matcher)
	case DomainMatcher:
		if s.domain == nil {
			s.domain = NewDomainMatcherSet()
		}
		s.domain.AddDomainMatcher(matcher)
	case SubstrMatcher:
		if s.substr == nil {
			s.substr = new(SubstrMatcherSet)
		}
		s.substr.AddSubstrMatcher(matcher)
	default:
		if s.regex == nil {
			s.regex = new(SimpleMatcherSet)
		}
		s.regex.AddMatcher(matcher)
	}
}

// MatchAny implements AnyMatcher.MatchAny.
func (s *LinearAnyMatcher) MatchAny(input string) bool {
	if s.full != nil && s.full.MatchAny(input) {
		return true
	}
	if s.domain != nil && s.domain.MatchAny(input) {
		return true
	}
	if s.substr != nil && s.substr.MatchAny(input) {
		return true
	}
	return s.regex != nil && s.regex.MatchAny(input)
}
