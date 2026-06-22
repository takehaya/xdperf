package plugin

// PluginMetadata はプラグインメタデータ
type PluginMetadata struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Author       string            `json:"author"`
	Description  string            `json:"description"`
	License      string            `json:"license"`
	Type         string            `json:"type"` // "generator", "verifier"
	Capabilities map[string]bool   `json:"capabilities"`
	Requirements map[string]string `json:"requirements"`
}
