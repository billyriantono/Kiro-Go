package config

import "strconv"

// settingsFrom flattens the scalar server settings + global stats of a Config
// into the key/value rows persisted in the settings table. Entity collections
// (accounts, api_keys, prompt_filter_rules) are handled by their own tables and
// are intentionally excluded here.
//
// Legacy-only fields (ApiKey, RequireApiKey, SanitizeClaudeCodePrompt,
// LegacyAllowOverage) are migrated into the current model in config.Load before
// the store ever sees them, so they are not persisted here.
func settingsFrom(c *Config) map[string]string {
	m := map[string]string{
		"password":                c.Password,
		"port":                    strconv.Itoa(c.Port),
		"host":                    c.Host,
		"kiro_version":            c.KiroVersion,
		"system_version":          c.SystemVersion,
		"node_version":            c.NodeVersion,
		"thinking_suffix":         c.ThinkingSuffix,
		"openai_thinking_format":  c.OpenAIThinkingFormat,
		"claude_thinking_format":  c.ClaudeThinkingFormat,
		"preferred_endpoint":      c.PreferredEndpoint,
		"proxy_url":               c.ProxyURL,
		"relay_enabled":           boolStr(c.RelayEnabled),
		"relay_url":               c.RelayURL,
		"relay_secret":            c.RelaySecret,
		"log_level":               c.LogLevel,
		"allow_over_usage":        boolStr(c.AllowOverUsage),
		"filter_claude_code":      boolStr(c.FilterClaudeCode),
		"filter_env_noise":        boolStr(c.FilterEnvNoise),
		"filter_strip_boundaries": boolStr(c.FilterStripBoundaries),
		"require_api_key":         boolStr(c.RequireApiKey),
		"total_requests":          strconv.Itoa(c.TotalRequests),
		"success_requests":        strconv.Itoa(c.SuccessRequests),
		"failed_requests":         strconv.Itoa(c.FailedRequests),
		"total_tokens":            strconv.Itoa(c.TotalTokens),
		"total_credits":           strconv.FormatFloat(c.TotalCredits, 'f', -1, 64),
	}
	// EndpointFallback is a tri-state pointer (nil = default true); only persist
	// when explicitly set so Load can preserve the "unset" meaning.
	if c.EndpointFallback != nil {
		m["endpoint_fallback"] = boolStr(*c.EndpointFallback)
	}
	return m
}

// applySettings populates the scalar fields of c from the settings key/value map.
func applySettings(c *Config, m map[string]string) {
	c.Password = m["password"]
	c.Port = atoiOr(m["port"], 8080)
	c.Host = m["host"]
	c.KiroVersion = m["kiro_version"]
	c.SystemVersion = m["system_version"]
	c.NodeVersion = m["node_version"]
	c.ThinkingSuffix = m["thinking_suffix"]
	c.OpenAIThinkingFormat = m["openai_thinking_format"]
	c.ClaudeThinkingFormat = m["claude_thinking_format"]
	c.PreferredEndpoint = m["preferred_endpoint"]
	c.ProxyURL = m["proxy_url"]
	c.RelayEnabled = m["relay_enabled"] == "1"
	c.RelayURL = m["relay_url"]
	c.RelaySecret = m["relay_secret"]
	c.LogLevel = m["log_level"]
	c.AllowOverUsage = m["allow_over_usage"] == "1"
	c.FilterClaudeCode = m["filter_claude_code"] == "1"
	c.FilterEnvNoise = m["filter_env_noise"] == "1"
	c.FilterStripBoundaries = m["filter_strip_boundaries"] == "1"
	c.RequireApiKey = m["require_api_key"] == "1"
	c.TotalRequests = atoiOr(m["total_requests"], 0)
	c.SuccessRequests = atoiOr(m["success_requests"], 0)
	c.FailedRequests = atoiOr(m["failed_requests"], 0)
	c.TotalTokens = atoiOr(m["total_tokens"], 0)
	if f, err := strconv.ParseFloat(m["total_credits"], 64); err == nil {
		c.TotalCredits = f
	}
	if v, ok := m["endpoint_fallback"]; ok {
		b := v == "1"
		c.EndpointFallback = &b
	}
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}
