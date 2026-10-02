package x

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// TrendOption configures ScrapeTimelineTrends.
type TrendOption func(*trendOptions)

type trendOptions struct {
	maxTweets int
	topN      int
	stopWords []string
}

// WithTrendMaxTweets caps the total tweets fetched for trend analysis. Default: 200.
func WithTrendMaxTweets(n int) TrendOption {
	return func(o *trendOptions) { o.maxTweets = n }
}

// WithTrendTopN sets the number of top keywords, hashtags, and mentions returned. Default: 20.
func WithTrendTopN(n int) TrendOption {
	return func(o *trendOptions) { o.topN = n }
}

// WithTrendStopWords appends domain-specific stop words to the bundled English
// stop list before keyword extraction.
func WithTrendStopWords(words []string) TrendOption {
	return func(o *trendOptions) { o.stopWords = append(o.stopWords, words...) }
}

// ScrapeTimelineTrends paginates through a user's tweets and produces a TrendReport.
// If ctx is cancelled mid-scrape, a partial report is returned alongside ErrPartialResult.
func (c *Client) ScrapeTimelineTrends(ctx context.Context, userID string, opts ...TrendOption) (*TrendReport, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: userID must not be empty", ErrInvalidParams)
	}

	to := &trendOptions{maxTweets: 200, topN: 20}
	for _, o := range opts {
		o(to)
	}

	stopSet := buildStopSet(to.stopWords)
	report := &TrendReport{}

	hourCounts := make(map[int]int, 24)
	authorCounts := make(map[string]*AuthorActivity)
	termFreq := make(map[string]int)
	hashFreq := make(map[string]int)
	mentionFreq := make(map[string]int)
	var totalEngagement float64

	page, err := c.UserTweets(ctx, userID, 20)
	if err != nil {
		return nil, err
	}

	var partial bool
	for {
		for _, tw := range page.Tweets {
			if report.TweetsAnalyzed >= to.maxTweets {
				goto done
			}
			report.TweetsAnalyzed++
			totalEngagement += float64(tw.LikeCount + tw.RetweetCount + tw.ReplyCount + tw.QuoteCount)

			if !tw.CreatedAt.IsZero() {
				hourCounts[tw.CreatedAt.UTC().Hour()]++
			}

			if tw.AuthorID != "" {
				if a, ok := authorCounts[tw.AuthorID]; ok {
					a.TweetCount++
				} else {
					authorCounts[tw.AuthorID] = &AuthorActivity{
						AuthorID:   tw.AuthorID,
						ScreenName: tw.AuthorScreenName,
						TweetCount: 1,
					}
				}
			}

			extractTweetTerms(tw.Text, stopSet, termFreq, hashFreq, mentionFreq)
			for _, h := range tw.Hashtags {
				hashFreq[strings.ToLower(h)]++
			}
			for _, m := range tw.MentionedUsers {
				mentionFreq[strings.ToLower(m)]++
			}
		}

		if !page.HasNext || page.NextCursor == "" {
			break
		}

		select {
		case <-ctx.Done():
			partial = true
			goto done
		default:
		}

		page, err = c.UserTweetsPage(ctx, userID, 20, page.NextCursor)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				partial = true
				goto done
			}
			return nil, err
		}
	}

done:
	if report.TweetsAnalyzed > 0 {
		report.AvgEngagement = totalEngagement / float64(report.TweetsAnalyzed)
	}

	report.TopKeywords = topN(termFreq, to.topN)
	report.TopHashtags = topN(hashFreq, to.topN)
	report.TopMentions = topN(mentionFreq, to.topN)
	report.PeakHours = peakHours(hourCounts)
	report.ActiveAuthors = topAuthors(authorCounts, 10)

	if partial {
		return report, fmt.Errorf("%w after %d tweets", ErrPartialResult, report.TweetsAnalyzed)
	}
	return report, nil
}

// ---------------------------------------------------------------------------
// Text analysis helpers
// ---------------------------------------------------------------------------

var (
	reHashtag = regexp.MustCompile(`#([A-Za-z]\w*)`)
	reMention = regexp.MustCompile(`@([A-Za-z_]\w*)`)
	reWord    = regexp.MustCompile(`[A-Za-z]{3,}`)
)

func extractTweetTerms(text string, stopSet map[string]struct{}, terms, hashes, mentions map[string]int) {
	for _, m := range reHashtag.FindAllStringSubmatch(text, -1) {
		hashes[strings.ToLower(m[1])]++
	}
	for _, m := range reMention.FindAllStringSubmatch(text, -1) {
		mentions[strings.ToLower(m[1])]++
	}

	clean := reHashtag.ReplaceAllString(text, " ")
	clean = reMention.ReplaceAllString(clean, " ")

	var words []string
	for _, w := range reWord.FindAllString(clean, -1) {
		lw := strings.ToLower(w)
		if _, stop := stopSet[lw]; stop {
			continue
		}
		if !isPunctuation(lw) {
			words = append(words, lw)
		}
	}

	for _, w := range words {
		terms[w]++
	}
	for i := 0; i+1 < len(words); i++ {
		terms[words[i]+" "+words[i+1]]++
	}
}

func isPunctuation(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func topN(freq map[string]int, n int) []KeywordFreq {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(freq))
	for k, v := range freq {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	if n > len(all) {
		n = len(all)
	}
	out := make([]KeywordFreq, n)
	for i := 0; i < n; i++ {
		out[i] = KeywordFreq{Term: all[i].k, Count: all[i].v}
	}
	return out
}

func peakHours(counts map[int]int) []int {
	type hv struct {
		h int
		v int
	}
	all := make([]hv, 0, len(counts))
	for h, v := range counts {
		all = append(all, hv{h, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].h < all[j].h
	})
	out := make([]int, len(all))
	for i, x := range all {
		out[i] = x.h
	}
	return out
}

func topAuthors(m map[string]*AuthorActivity, n int) []AuthorActivity {
	all := make([]AuthorActivity, 0, len(m))
	for _, a := range m {
		all = append(all, *a)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].TweetCount != all[j].TweetCount {
			return all[i].TweetCount > all[j].TweetCount
		}
		return all[i].ScreenName < all[j].ScreenName
	})
	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

func buildStopSet(extra []string) map[string]struct{} {
	set := make(map[string]struct{}, len(defaultStopWords)+len(extra))
	for _, w := range defaultStopWords {
		set[w] = struct{}{}
	}
	for _, w := range extra {
		set[strings.ToLower(w)] = struct{}{}
	}
	return set
}

// Bundled English stop-word list (~200 words).
var defaultStopWords = []string{
	"a", "about", "above", "after", "again", "against", "ago", "all", "also",
	"am", "an", "and", "any", "are", "aren", "as", "at",
	"be", "because", "been", "before", "being", "below", "between", "both",
	"but", "by",
	"can", "cannot", "could", "couldn",
	"did", "didn", "do", "does", "doesn", "doing", "don", "done", "down",
	"during",
	"each", "either", "else", "ever", "every",
	"few", "for", "from", "further",
	"get", "got",
	"had", "hadn", "has", "hasn", "have", "haven", "having", "he", "her",
	"here", "hers", "herself", "him", "himself", "his", "how",
	"i", "if", "in", "into", "is", "isn", "it", "its", "itself",
	"just",
	"know",
	"let", "like",
	"ma", "me", "might", "mightn", "more", "most", "must", "mustn", "my",
	"myself",
	"needn", "no", "nor", "not", "now",
	"of", "off", "on", "once", "only", "or", "other", "our", "ours",
	"ourselves", "out", "over", "own",
	"re", "really",
	"s", "same", "shan", "she", "should", "shouldn", "so", "some", "such",
	"t", "than", "that", "the", "their", "theirs", "them", "themselves",
	"then", "there", "these", "they", "this", "those", "through", "to",
	"too",
	"under", "until", "up",
	"us",
	"ve", "very",
	"was", "wasn", "we", "were", "weren", "what", "when", "where", "which",
	"while", "who", "whom", "why", "will", "with", "won", "would", "wouldn",
	"y", "you", "your", "yours", "yourself", "yourselves",
	"http", "https", "www", "com", "org", "net", "amp", "rt",
}
