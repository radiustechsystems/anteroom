package hosted

import _ "embed"

const claudeBotsURL = "https://claude.com/crawling/bots.json"
const claudeOutboundURL = "https://platform.claude.com/docs/en/api/ip-addresses"

// Anteroom accepts Claude-User from both Anthropic's published bot ranges and
// its stable outbound service range. The latter covers web-fetch and MCP tool
// calls and has no machine-readable feed.
// Sources of truth:
//   - https://support.claude.com/en/articles/8896518
//   - https://platform.claude.com/docs/en/api/ip-addresses

//go:embed claude_bots.json
var claudeBotsJSON []byte

//go:embed claude_outbound.json
var claudeOutboundJSON []byte
