package crawler

import _ "embed"

const bingbotRangesURL = "https://www.bing.com/toolbox/bingbot.json"

// Sources of truth:
//   - UAs: https://www.bing.com/webmasters/help/help/which-crawlers-does-bing-use-8c184ec0
//   - verification: https://www.bing.com/webmasters/help/how-to-verify-bingbot-3905dc26
//   - ranges: https://www.bing.com/toolbox/bingbot.json

//go:embed bingbot.json
var bingbotJSON []byte

var bingbot = provider{
	name:        "bingbot",
	uaProducts:  []string{"bingbot/"},
	ptrSuffixes: []string{".search.msn.com"},
	rangeJSON:   bingbotJSON,
	rangeSource: bingbotRangesURL,
}
