/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"sigs.k8s.io/yaml"
)

const (
	ModeConvert  = "convert"
	ModeCoexist  = "coexist"
	SplitInfraApp = "infra,app"
	SplitNone     = "none"

	CoexistHTTPSPassthrough = "passthrough"
	CoexistHTTPSReencrypt   = "reencrypt"

	DefaultMaxPassthroughListeners = 32
)

// Config holds Shturval migration settings from flags and optional YAML file.
type Config struct {
	Mode                     string   `yaml:"mode"`
	GatewayClassName         string   `yaml:"gatewayClassName"`
	GatewayName              string   `yaml:"gatewayName"`
	GatewayNamespace         string   `yaml:"gatewayNamespace"`
	DefaultTLSSecret         string   `yaml:"defaultTLSSecret"`
	NginxService             string   `yaml:"nginxService"`
	NginxNamespace           string   `yaml:"nginxNamespace"`
	NginxHTTPPort            int32    `yaml:"nginxHTTPPort"`
	NginxHTTPSPort           int32    `yaml:"nginxHTTPSPort"`
	CoexistHTTPS             string   `yaml:"coexistHTTPS"`
	MaxPassthroughListeners  int      `yaml:"maxPassthroughListeners"`
	OwnHosts                 []string `yaml:"ownHosts"`
	RetainHosts              []string `yaml:"retainHosts"`
	Providers                []string `yaml:"providers"`
	EmitCertificates         bool     `yaml:"emitCertificates"`
	Split                    string   `yaml:"split"`
	StrictPreflight          bool     `yaml:"strictPreflight"`
	CheckShturvalCRDs        bool     `yaml:"checkShturvalCRDs"`
	Force                    bool     `yaml:"force"`
	ReportFormat             string   `yaml:"reportFormat"`
	OutputDir                string   `yaml:"outputDir"`
	InputFile                []string `yaml:"inputFile"`
	Namespace                string   `yaml:"namespace"`
	AllNamespaces            bool     `yaml:"allNamespaces"`
	Emitter                  string   `yaml:"emitter"`
	AllowExperimentalGWAPI   bool     `yaml:"allowExperimentalGatewayAPI"`
	OutputFormat             string   `yaml:"outputFormat"`
	ReencryptValidationHost  string   `yaml:"coexistBackendTLSValidationHostname"`
	ReencryptCARef           string   `yaml:"coexistBackendTLSCARef"`
	ReencryptSystemCA        bool     `yaml:"coexistBackendTLSWellKnownSystemCA"`
	NginxDefaultSSLCert      string   `yaml:"nginxDefaultSSLCertificate"`
}

// Defaults returns configuration defaults for Shturval migration.
func Defaults() Config {
	return Config{
		Mode:                    ModeConvert,
		GatewayName:             "shturval-gateway",
		GatewayNamespace:        "gateway-system",
		GatewayClassName:        "cilium",
		NginxService:            "ingress-nginx-controller",
		NginxNamespace:          "ingress-nginx",
		NginxHTTPPort:           80,
		NginxHTTPSPort:          443,
		CoexistHTTPS:            CoexistHTTPSPassthrough,
		MaxPassthroughListeners: DefaultMaxPassthroughListeners,
		Providers:               []string{"ingress-nginx"},
		Emitter:                 "standard",
		Split:                   SplitInfraApp,
		StrictPreflight:         true,
		ReportFormat:            "markdown",
		OutputFormat:            "yaml",
	}
}

// LoadYAML merges file values over defaults.
func LoadYAML(path string, base Config) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return base, err
	}
	if err := yaml.Unmarshal(data, &base); err != nil {
		return base, fmt.Errorf("parse config %q: %w", path, err)
	}
	return base, nil
}

// Validate checks required fields and enum values.
func (c Config) Validate() error {
	switch c.Mode {
	case ModeConvert, ModeCoexist:
	default:
		return fmt.Errorf("mode must be %q or %q, got %q", ModeConvert, ModeCoexist, c.Mode)
	}
	switch c.CoexistHTTPS {
	case CoexistHTTPSPassthrough, CoexistHTTPSReencrypt:
	default:
		return fmt.Errorf("coexistHTTPS must be passthrough or reencrypt, got %q", c.CoexistHTTPS)
	}
	switch c.Split {
	case SplitInfraApp, SplitNone:
	default:
		return fmt.Errorf("split must be %q or %q, got %q", SplitInfraApp, SplitNone, c.Split)
	}
	switch c.ReportFormat {
	case "markdown", "json":
	default:
		return fmt.Errorf("reportFormat must be markdown or json, got %q", c.ReportFormat)
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("at least one provider is required")
	}
	if c.Mode == ModeCoexist && c.NginxService == "" {
		return fmt.Errorf("nginx service is required in coexist mode")
	}
	if c.CoexistHTTPS == CoexistHTTPSReencrypt && c.NginxDefaultSSLCert == "" {
		return fmt.Errorf("nginxDefaultSSLCertificate is required for reencrypt coexist")
	}
	return nil
}

// SharedGatewayOptions maps to upstream i2gw post-process options.
func (c Config) SharedGatewayOptions() i2gw.SharedGatewayOptions {
	return i2gw.SharedGatewayOptions{
		GatewayName:      c.GatewayName,
		GatewayNamespace: c.GatewayNamespace,
		GatewayClassName: c.GatewayClassName,
		DefaultTLSSecret: c.DefaultTLSSecret,
	}
}

// HostInOwn returns true when hostname is explicitly gateway-owned.
func (c Config) HostInOwn(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, o := range c.OwnHosts {
		if strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o), ".")) == h {
			return true
		}
	}
	return false
}

// HostInRetain returns true when hostname is explicitly ingress-retained.
func (c Config) HostInRetain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, r := range c.RetainHosts {
		if strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r), ".")) == h {
			return true
		}
	}
	return false
}
