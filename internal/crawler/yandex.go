package crawler

// Source of truth (UAs and verification):
// https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots.html?lang=en
//
// Yandex says its addresses change frequently and does not publish a list, so
// this provider intentionally relies only on forward-confirmed reverse DNS.
var yandexbot = provider{
	name: "yandexbot",
	uaProducts: []string{
		"YandexBot/", "YandexImages/", "YandexVideo/", "YandexFavicons/",
		"YandexMobileBot/", "YandexRenderResourcesBot/", "YandexWebmaster/",
		"YandexPagechecker/",
	},
	ptrSuffixes: []string{".yandex.ru", ".yandex.net", ".yandex.com"},
}
