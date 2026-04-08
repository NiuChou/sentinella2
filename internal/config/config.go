// Package config provides project-level configuration loading for sentinella2.
// It reads .sentinella2.yaml from a target directory and falls back to
// sensible defaults when the file is absent.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all sentinella2 project configuration.
type Config struct {
	Scan          ScanConfig          `yaml:"scan"`
	Audit         AuditConfig         `yaml:"audit"`
	DefenseLayers DefenseLayersConfig `yaml:"defense_layers"`
	Knowledge     KnowledgeConfig     `yaml:"knowledge"`
	Feedback      FeedbackConfig      `yaml:"feedback"`
	Feeds         FeedsConfig         `yaml:"feeds"`
	RuleLifecycle RuleLifecycleConfig `yaml:"rule_lifecycle"`
}

// ScanConfig controls deterministic (Tier 1) scanning behavior.
type ScanConfig struct {
	Exclude      []string `yaml:"exclude"`
	DisableRules []string `yaml:"disable_rules"`
}

// AuditConfig controls LLM-powered (Tier 2-3) audit behavior.
type AuditConfig struct {
	Provider string `yaml:"provider"`
	BaseURL  string `yaml:"base_url"`
	Model    string `yaml:"model"`
}

// DefenseLayersConfig controls the 6-layer defense-in-depth assessment.
type DefenseLayersConfig struct {
	Disable []string `yaml:"disable"`
}

// KnowledgeConfig controls knowledge base resolution and learning.
type KnowledgeConfig struct {
	Sources       []SourceConfig `yaml:"sources"`
	MergeStrategy string         `yaml:"merge_strategy"` // "overlay", "strict", "additive"
	AutoUpdate    bool           `yaml:"auto_update"`     // auto-sync feeds on scan
}

// SourceConfig describes a knowledge source.
type SourceConfig struct {
	Type string `yaml:"type"` // "builtin", "local", "project", "remote"
	Path string `yaml:"path"`
}

// FeedbackConfig controls the feedback system.
type FeedbackConfig struct {
	Dir         string  `yaml:"dir"`          // feedback store directory
	AutoTune    bool    `yaml:"auto_tune"`    // apply tuning on scan
	MinFeedback int     `yaml:"min_feedback"` // min entries before tuning
	FPThreshold float64 `yaml:"fp_threshold"` // false positive rate threshold
}

// FeedsConfig controls feed synchronization.
type FeedsConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Schedule string   `yaml:"schedule"` // default schedule: "weekly"
	Sources  []string `yaml:"sources"`  // feed IDs to enable: ["nvd", "freebsd-sa", "github-advisory"]
}

// RuleLifecycleConfig controls automatic promotion and deprecation of pattern rules.
type RuleLifecycleConfig struct {
	PromoteToTesting PromotionConfig `yaml:"promote_to_testing"`
	PromoteToStable  PromotionConfig `yaml:"promote_to_stable"`
	AutoDeprecate    DeprecateConfig `yaml:"auto_deprecate"`
}

// PromotionConfig holds the thresholds required to promote a pattern to the next status.
type PromotionConfig struct {
	MinScans         int     `yaml:"min_scans"`
	MinTruePositives int     `yaml:"min_true_positives"`
	MinConfidence    float64 `yaml:"min_confidence,omitempty"` // only for stable
}

// DeprecateConfig holds the thresholds for automatically deprecating a pattern.
type DeprecateConfig struct {
	MaxFalsePositiveRate float64 `yaml:"max_false_positive_rate"`
	MinSamples           int     `yaml:"min_samples"`
}

const configFileName = ".sentinella2.yaml"

// Default returns the default configuration with sensible zero-config values.
func Default() Config {
	return Config{
		Scan: ScanConfig{
			Exclude: []string{
				"vendor/**",
				"node_modules/**",
				".git/**",
			},
			DisableRules: nil,
		},
		Audit: AuditConfig{},
		DefenseLayers: DefenseLayersConfig{
			Disable: nil,
		},
		Knowledge: KnowledgeConfig{
			Sources: []SourceConfig{
				{Type: "builtin", Path: ""},
			},
			MergeStrategy: "overlay",
			AutoUpdate:    false,
		},
		Feedback: FeedbackConfig{
			Dir:         "",
			AutoTune:    false,
			MinFeedback: 5,
			FPThreshold: 0.3,
		},
		Feeds: FeedsConfig{
			Enabled:  false,
			Schedule: "weekly",
			Sources:  []string{"nvd", "freebsd-sa", "github-advisory"},
		},
		RuleLifecycle: RuleLifecycleConfig{
			PromoteToTesting: PromotionConfig{
				MinScans:         5,
				MinTruePositives: 3,
			},
			PromoteToStable: PromotionConfig{
				MinScans:         20,
				MinConfidence:    0.70,
				MinTruePositives: 10,
			},
			AutoDeprecate: DeprecateConfig{
				MaxFalsePositiveRate: 0.95,
				MinSamples:           20,
			},
		},
	}
}

// Load reads .sentinella2.yaml from the given directory and merges it with
// defaults. Returns the default configuration if the file does not exist.
// Returns an error only if the file exists but cannot be read or parsed.
func Load(dir string) (Config, error) {
	cfg := Default()

	path := filepath.Join(dir, configFileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("failed to read config %s: %w", path, err)
	}

	if len(data) == 0 {
		return cfg, nil
	}

	var fileCfg Config
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return Config{}, fmt.Errorf("failed to parse config %s: %w", path, err)
	}

	return merge(cfg, fileCfg), nil
}

// merge overlays file-sourced values on top of defaults. Only non-zero
// file values override the defaults, preserving default exclude patterns
// when the user does not specify any.
func merge(base, overlay Config) Config {
	result := base

	if len(overlay.Scan.Exclude) > 0 {
		result.Scan.Exclude = overlay.Scan.Exclude
	}
	if len(overlay.Scan.DisableRules) > 0 {
		result.Scan.DisableRules = overlay.Scan.DisableRules
	}

	if overlay.Audit.Provider != "" {
		result.Audit.Provider = overlay.Audit.Provider
	}
	if overlay.Audit.BaseURL != "" {
		result.Audit.BaseURL = overlay.Audit.BaseURL
	}
	if overlay.Audit.Model != "" {
		result.Audit.Model = overlay.Audit.Model
	}

	if len(overlay.DefenseLayers.Disable) > 0 {
		result.DefenseLayers.Disable = overlay.DefenseLayers.Disable
	}

	// Knowledge config.
	if len(overlay.Knowledge.Sources) > 0 {
		result.Knowledge.Sources = overlay.Knowledge.Sources
	}
	if overlay.Knowledge.MergeStrategy != "" {
		result.Knowledge.MergeStrategy = overlay.Knowledge.MergeStrategy
	}
	if overlay.Knowledge.AutoUpdate {
		result.Knowledge.AutoUpdate = true
	}

	// Feedback config.
	if overlay.Feedback.Dir != "" {
		result.Feedback.Dir = overlay.Feedback.Dir
	}
	if overlay.Feedback.AutoTune {
		result.Feedback.AutoTune = true
	}
	if overlay.Feedback.MinFeedback > 0 {
		result.Feedback.MinFeedback = overlay.Feedback.MinFeedback
	}
	if overlay.Feedback.FPThreshold > 0 {
		result.Feedback.FPThreshold = overlay.Feedback.FPThreshold
	}

	// Feeds config.
	if overlay.Feeds.Enabled {
		result.Feeds.Enabled = true
	}
	if overlay.Feeds.Schedule != "" {
		result.Feeds.Schedule = overlay.Feeds.Schedule
	}
	if len(overlay.Feeds.Sources) > 0 {
		result.Feeds.Sources = overlay.Feeds.Sources
	}

	// RuleLifecycle config.
	if overlay.RuleLifecycle.PromoteToTesting.MinScans > 0 {
		result.RuleLifecycle.PromoteToTesting.MinScans = overlay.RuleLifecycle.PromoteToTesting.MinScans
	}
	if overlay.RuleLifecycle.PromoteToTesting.MinTruePositives > 0 {
		result.RuleLifecycle.PromoteToTesting.MinTruePositives = overlay.RuleLifecycle.PromoteToTesting.MinTruePositives
	}
	if overlay.RuleLifecycle.PromoteToStable.MinScans > 0 {
		result.RuleLifecycle.PromoteToStable.MinScans = overlay.RuleLifecycle.PromoteToStable.MinScans
	}
	if overlay.RuleLifecycle.PromoteToStable.MinConfidence > 0 {
		result.RuleLifecycle.PromoteToStable.MinConfidence = overlay.RuleLifecycle.PromoteToStable.MinConfidence
	}
	if overlay.RuleLifecycle.PromoteToStable.MinTruePositives > 0 {
		result.RuleLifecycle.PromoteToStable.MinTruePositives = overlay.RuleLifecycle.PromoteToStable.MinTruePositives
	}
	if overlay.RuleLifecycle.AutoDeprecate.MaxFalsePositiveRate > 0 {
		result.RuleLifecycle.AutoDeprecate.MaxFalsePositiveRate = overlay.RuleLifecycle.AutoDeprecate.MaxFalsePositiveRate
	}
	if overlay.RuleLifecycle.AutoDeprecate.MinSamples > 0 {
		result.RuleLifecycle.AutoDeprecate.MinSamples = overlay.RuleLifecycle.AutoDeprecate.MinSamples
	}

	return result
}
