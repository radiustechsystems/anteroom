package crawler

import _ "embed"

const commonCrawlRangesURL = "https://index.commoncrawl.org/ccbot.json"

// Sources of truth (UA and verification): https://commoncrawl.org/ccbot
// Published ranges: https://index.commoncrawl.org/ccbot.json

//go:embed ccbot.json
var commonCrawlJSON []byte

var commonCrawl = provider{
	name:        "ccbot",
	uaProducts:  []string{"CCBot/"},
	ptrSuffixes: []string{".crawl.commoncrawl.org"},
	rangeJSON:   commonCrawlJSON,
	rangeSource: commonCrawlRangesURL,
	dnsIPv4Only: true,
}
