package hosted

import _ "embed"

const googleAgentURL = "https://developers.google.com/static/crawling/ipranges/user-triggered-agents.json"

// Source of truth:
// https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers

//go:embed google_user_triggered_agents.json
var googleAgentJSON []byte
