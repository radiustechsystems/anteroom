package hosted

import _ "embed"

const chatGPTUserURL = "https://openai.com/chatgpt-user.json"

// Source of truth: https://developers.openai.com/api/docs/bots

//go:embed chatgpt_user.json
var chatGPTUserJSON []byte
