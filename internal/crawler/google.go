package crawler

import _ "embed"

const googleCommonCrawlersURL = "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"

// Sources of truth:
//   - UAs: https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers
//   - verification: https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
//   - ranges: https://developers.google.com/static/crawling/ipranges/common-crawlers.json

//go:embed google_common_crawlers.json
var googleCommonCrawlersJSON []byte

var googlebot = provider{
	name:        "googlebot",
	uaProducts:  []string{"Googlebot/", "Googlebot-Image/", "Googlebot-Video/", "Google-InspectionTool/"},
	ptrSuffixes: []string{".googlebot.com", ".google.com"},
	rangeJSON:   googleCommonCrawlersJSON,
	rangeSource: googleCommonCrawlersURL,
}
