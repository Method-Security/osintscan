package cctld

import (
	"strings"
	"unicode"
)

// commonStopwords is a small set of very common English tokens to drop before
// computing Jaccard similarity.  This is best-effort signal; keeping it small
// avoids over-filtering pages in non-English languages.
var commonStopwords = map[string]struct{}{
	"the": {}, "and": {}, "for": {}, "are": {}, "but": {}, "not": {},
	"you": {}, "all": {}, "can": {}, "her": {}, "was": {}, "one": {},
	"our": {}, "out": {}, "get": {}, "has": {}, "him": {}, "his": {},
	"how": {}, "its": {}, "may": {}, "new": {}, "now": {}, "old": {},
	"see": {}, "two": {}, "way": {}, "who": {}, "did": {}, "had": {},
	"let": {}, "put": {}, "say": {}, "she": {}, "too": {}, "use": {},
}

// tokenize splits HTML body text into a lowercase token set, dropping tokens
// shorter than minLen and very common stopwords.
func tokenize(text string) map[string]struct{} {
	const minLen = 3
	tokens := make(map[string]struct{})
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	for _, w := range words {
		if len(w) < minLen {
			continue
		}
		if _, stop := commonStopwords[w]; stop {
			continue
		}
		tokens[w] = struct{}{}
	}
	return tokens
}

// jaccardSimilarity computes the Jaccard index between two token sets.
// Returns 0.0 when both sets are empty.
func jaccardSimilarity(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0.0
	}
	intersect := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersect++
		}
	}
	union := len(a) + len(b) - intersect
	if union == 0 {
		return 0.0
	}
	return float64(intersect) / float64(union)
}

// SimilarityScore tokenizes both body strings and returns their Jaccard similarity.
func SimilarityScore(baseline, candidate string) float64 {
	return jaccardSimilarity(tokenize(baseline), tokenize(candidate))
}
