package ipintel

import (
	"encoding/json"
	"sort"
)

var crawlerCategories = map[string]bool{
	"search_crawler": true,
	"ai_crawler":     true,
}

// crawlerMatches extracts zero-weight crawler matches from evidence. Groups is
// the union of category names and the source group (for example "crawlers"),
// so callers can allowlist either spelling. Verdict and Categories from
// scoreEvidence are deliberately left untouched.
func crawlerMatches(evidence []Evidence) (groups []string, crawlers []CrawlerMatch) {
	seenGroups := map[string]bool{}
	seenMatches := map[string]bool{}

	addGroup := func(group string) {
		if group == "" || seenGroups[group] {
			return
		}
		seenGroups[group] = true
		groups = append(groups, group)
	}

	for _, e := range evidence {
		if !e.Matched {
			continue
		}
		if categoryWeights[e.Category] != 0 {
			continue
		}
		var detail struct {
			Group    string `json:"group"`
			Operator string `json:"operator"`
			Bot      string `json:"bot"`
		}
		if len(e.Detail) > 0 {
			_ = json.Unmarshal(e.Detail, &detail)
		}
		if !crawlerCategories[e.Category] && detail.Group == "" {
			continue
		}
		match := CrawlerMatch{
			Category: e.Category,
			Group:    detail.Group,
			Operator: detail.Operator,
			Bot:      detail.Bot,
		}
		key := match.Category + "|" + match.Group + "|" + match.Operator + "|" + match.Bot
		if !seenMatches[key] {
			seenMatches[key] = true
			crawlers = append(crawlers, match)
		}
		addGroup(match.Category)
		addGroup(match.Group)
	}

	sort.Strings(groups)
	sort.SliceStable(crawlers, func(i, j int) bool {
		if crawlers[i].Category != crawlers[j].Category {
			return crawlers[i].Category < crawlers[j].Category
		}
		if crawlers[i].Operator != crawlers[j].Operator {
			return crawlers[i].Operator < crawlers[j].Operator
		}
		return crawlers[i].Bot < crawlers[j].Bot
	})
	return groups, crawlers
}
