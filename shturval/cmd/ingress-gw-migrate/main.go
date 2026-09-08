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

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/emitout"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/manifest"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/pipeline"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/preflight"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"

	_ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitters/standard"
	_ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/ingressnginx"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		if code, ok := err.(exitCodeError); ok {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(emitout.ExitInputError)
	}
}

type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", int(e)) }

func newRoot() *cobra.Command {
	cfg := config.Defaults()
	cmd := &cobra.Command{
		Use:   "ingress-gw-migrate",
		Short: "Shturval Ingress to Gateway migration tool",
	}
	cmd.AddCommand(preflightCmd(&cfg), printCmd(&cfg), convertCmd(&cfg), verifyCmd(&cfg))
	bindGlobalFlags(cmd, &cfg)
	return cmd
}

func bindGlobalFlags(cmd *cobra.Command, cfg *config.Config) {
	cmd.PersistentFlags().StringVar(&cfg.Mode, "mode", cfg.Mode, "Migration mode: convert|coexist")
	cmd.PersistentFlags().StringVar(&cfg.GatewayClassName, "gateway-class-name", cfg.GatewayClassName, "GatewayClass name")
	cmd.PersistentFlags().StringVar(&cfg.GatewayName, "gateway-name", cfg.GatewayName, "Shared Gateway name")
	cmd.PersistentFlags().StringVar(&cfg.GatewayNamespace, "gateway-namespace", cfg.GatewayNamespace, "Shared Gateway namespace")
	cmd.PersistentFlags().StringVar(&cfg.DefaultTLSSecret, "default-tls-secret", cfg.DefaultTLSSecret, "Default TLS secret namespace/name")
	cmd.PersistentFlags().StringVar(&cfg.NginxService, "nginx-service", cfg.NginxService, "Retained nginx Service name")
	cmd.PersistentFlags().StringVar(&cfg.NginxNamespace, "nginx-namespace", cfg.NginxNamespace, "Retained nginx Service namespace")
	cmd.PersistentFlags().Int32Var(&cfg.NginxHTTPPort, "nginx-http-port", cfg.NginxHTTPPort, "Retained nginx HTTP port")
	cmd.PersistentFlags().Int32Var(&cfg.NginxHTTPSPort, "nginx-https-port", cfg.NginxHTTPSPort, "Retained nginx HTTPS port")
	cmd.PersistentFlags().StringVar(&cfg.CoexistHTTPS, "coexist-https", cfg.CoexistHTTPS, "Coexist HTTPS mode: passthrough|reencrypt")
	cmd.PersistentFlags().IntVar(&cfg.MaxPassthroughListeners, "max-passthrough-listeners", cfg.MaxPassthroughListeners, "Warn threshold for retained passthrough listeners")
	cmd.PersistentFlags().StringSliceVar(&cfg.OwnHosts, "own-host", cfg.OwnHosts, "Hostnames owned by Gateway")
	cmd.PersistentFlags().StringSliceVar(&cfg.RetainHosts, "retain-host", cfg.RetainHosts, "Hostnames retained on nginx")
	cmd.PersistentFlags().StringSliceVar(&cfg.Providers, "providers", cfg.Providers, "Ingress providers")
	cmd.PersistentFlags().BoolVar(&cfg.EmitCertificates, "emit-certificates", cfg.EmitCertificates, "Emit cert-manager Certificate CRs")
	cmd.PersistentFlags().StringVar(&cfg.Split, "split", cfg.Split, "Output split: infra,app|none")
	cmd.PersistentFlags().BoolVar(&cfg.StrictPreflight, "strict-preflight", cfg.StrictPreflight, "Treat preflight warnings as blockers where applicable")
	cmd.PersistentFlags().BoolVar(&cfg.CheckShturvalCRDs, "check-shturval-crds", cfg.CheckShturvalCRDs, "Soft-check Shturval CRDs via unstructured API")
	cmd.PersistentFlags().BoolVar(&cfg.Force, "force", cfg.Force, "Overwrite existing output files")
	cmd.PersistentFlags().StringVar(&cfg.ReportFormat, "report-format", cfg.ReportFormat, "Report format: markdown|json")
	cmd.PersistentFlags().StringVar(&cfg.OutputDir, "output-dir", cfg.OutputDir, "Output directory for split manifests")
	cmd.PersistentFlags().StringSliceVar(&cfg.InputFile, "input-file", cfg.InputFile, "Input manifest files")
	cmd.PersistentFlags().StringVar(&cfg.Namespace, "namespace", cfg.Namespace, "Namespace filter")
	cmd.PersistentFlags().BoolVar(&cfg.AllNamespaces, "all-namespaces", cfg.AllNamespaces, "All namespaces")
	cmd.PersistentFlags().StringVar(&cfg.Emitter, "emitter", cfg.Emitter, "Emitter name")
	cmd.PersistentFlags().BoolVar(&cfg.AllowExperimentalGWAPI, "allow-experimental-gw-api", cfg.AllowExperimentalGWAPI, "Allow experimental Gateway API fields")
	cmd.PersistentFlags().StringVar(&cfg.NginxDefaultSSLCert, "nginx-default-ssl-certificate", cfg.NginxDefaultSSLCert, "nginx default SSL certificate for reencrypt")
}

func preflightCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "preflight",
		Short: "Run migration preflight checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.Validate(); err != nil {
				return err
			}
			objects, err := loadObjects(cfg)
			if err != nil {
				return err
			}
			report, err := pipeline.PreflightOnly(*cfg, objects)
			if err != nil {
				return err
			}
			renderReport(cfg, report)
			if report.HasBlockers() {
				return exitCodeError(emitout.ExitBlockers)
			}
			return nil
		},
	}
}

func printCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "print",
		Short: "Generate Gateway API manifests",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(cmd.Context(), cfg, false)
		},
	}
}

func convertCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "convert",
		Short: "Preflight then generate manifests (exit 2 on blockers)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConvert(cmd.Context(), cfg, true)
		},
	}
}

func verifyCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify applied Gateway API resources (read-only)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "verify: cluster checks not implemented in offline mode; use preflight against live cluster in a future release")
			return nil
		},
	}
}

func runConvert(ctx context.Context, cfg *config.Config, strictBlockers bool) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	objects, err := loadObjects(cfg)
	if err != nil {
		return err
	}
	result, err := pipeline.Convert(ctx, *cfg, objects)
	if err != nil {
		return err
	}
	renderReport(cfg, result.Report)
	if result.ExitCode == emitout.ExitBlockers {
		if strictBlockers {
			return exitCodeError(emitout.ExitBlockers)
		}
		return exitCodeError(emitout.ExitBlockers)
	}
	if cfg.OutputDir != "" {
		writer := emitout.Writer{
			OutputDir:     cfg.OutputDir,
			Force:         cfg.Force,
			SplitInfraApp: cfg.Split == config.SplitInfraApp,
			Report:        result.Report,
			ReportFormat:  cfg.ReportFormat,
		}
		if err := writer.WriteSplit(result.Bundle); err != nil {
			return err
		}
	}
	return nil
}

func loadObjects(cfg *config.Config) ([]runtime.Object, error) {
	if len(cfg.InputFile) == 0 {
		return nil, fmt.Errorf("--input-file is required")
	}
	return manifest.LoadFromFiles(cfg.InputFile)
}

func renderReport(cfg *config.Config, report preflight.Report) {
	switch cfg.ReportFormat {
	case "json":
		data, err := report.RenderJSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Fprintln(os.Stderr, string(data))
	default:
		fmt.Fprint(os.Stderr, report.RenderMarkdown())
	}
}
