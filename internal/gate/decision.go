package gate

// decision is the closed vocabulary for the one rung that ended a request.
// Its label and behavioral properties live together so a new branch cannot
// silently disappear from metrics or byte attribution.
type decision uint8

const (
	decisionNonCanonicalPath decision = iota
	decisionUnknownAuthority
	decisionOwnEndpoint
	decisionBypassPath
	decisionBypassIP
	decisionCORSPreflight
	decisionPassPoW
	decisionPassPaid
	decisionBypassCrawler
	decisionCrawlerVerificationUnavailable
	decisionCrawlerUnverified
	decisionPaymentRequired
	decisionPayMethodRefused
	decisionPayUpgradeRefused
	decisionPayMalformed
	decisionPayUnidentified
	decisionPayUnoffered
	decisionPayReplay
	decisionPayStateUnavailable
	decisionPayInflight
	decisionPayRateLimited
	decisionPayPending
	decisionPayGrantFailed
	decisionPayGrantConflict
	decisionPayRejected
	decisionPayAmbiguous
	decisionPayInfra
	decisionWaitPage
	decisionRefusal
	decisionCount
)

const (
	decisionUpstream uint8 = 1 << iota
	decisionWalled
)

type decisionInfo struct {
	name  string
	flags uint8
}

var decisionInfos = [decisionCount]decisionInfo{
	decisionNonCanonicalPath:               {name: "non-canonical-path"},
	decisionUnknownAuthority:               {name: "unknown-authority"},
	decisionOwnEndpoint:                    {name: "own-endpoint"},
	decisionBypassPath:                     {name: "bypass-path", flags: decisionUpstream},
	decisionBypassIP:                       {name: "bypass-ip", flags: decisionUpstream},
	decisionCORSPreflight:                  {name: "cors-preflight", flags: decisionUpstream},
	decisionPassPoW:                        {name: "pass-pow", flags: decisionUpstream},
	decisionPassPaid:                       {name: "pass-paid", flags: decisionUpstream},
	decisionBypassCrawler:                  {name: "bypass-crawler", flags: decisionUpstream},
	decisionCrawlerVerificationUnavailable: {name: "crawler-verification-unavailable"},
	decisionCrawlerUnverified:              {name: "crawler-unverified", flags: decisionWalled},
	decisionPaymentRequired:                {name: "payment-required", flags: decisionWalled},
	decisionPayMethodRefused:               {name: "pay-method-refused"},
	decisionPayUpgradeRefused:              {name: "pay-upgrade-refused"},
	decisionPayMalformed:                   {name: "pay-malformed"},
	decisionPayUnidentified:                {name: "pay-unidentified"},
	decisionPayUnoffered:                   {name: "pay-unoffered"},
	decisionPayReplay:                      {name: "pay-replay"},
	decisionPayStateUnavailable:            {name: "pay-state-unavailable"},
	decisionPayInflight:                    {name: "pay-inflight"},
	decisionPayRateLimited:                 {name: "pay-rate-limited"},
	decisionPayPending:                     {name: "pay-pending"},
	decisionPayGrantFailed:                 {name: "pay-grant-failed"},
	decisionPayGrantConflict:               {name: "pay-grant-conflict"},
	decisionPayRejected:                    {name: "pay-rejected"},
	decisionPayAmbiguous:                   {name: "pay-ambiguous"},
	decisionPayInfra:                       {name: "pay-infra"},
	decisionWaitPage:                       {name: "wait-page", flags: decisionWalled},
	decisionRefusal:                        {name: "refusal", flags: decisionWalled},
}

func (d decision) String() string {
	if d >= decisionCount {
		return "unknown"
	}
	return decisionInfos[d].name
}

func decisionLabels() []string {
	labels := make([]string, decisionCount)
	for d := decision(0); d < decisionCount; d++ {
		labels[d] = d.String()
	}
	return labels
}

func (d decision) upstream() bool {
	return d < decisionCount && decisionInfos[d].flags&decisionUpstream != 0
}

func (d decision) walled() bool {
	return d < decisionCount && decisionInfos[d].flags&decisionWalled != 0
}
