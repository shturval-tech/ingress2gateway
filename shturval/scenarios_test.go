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

package shturval_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/emitout"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/manifest"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/pipeline"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/preflight"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func baseCfg(mode, caseDir string) config.Config {
	cfg := config.Defaults()
	cfg.Mode = mode
	cfg.InputFile = []string{filepath.Join(caseDir, "input.yaml")}
	cfg.EmitCertificates = true
	return cfg
}

func loadCase(t *testing.T, caseID string) ([]runtime.Object, string) {
	t.Helper()
	dir := filepath.Join("testdata", caseID)
	objs, err := manifest.LoadFromFiles([]string{filepath.Join(dir, "input.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	return objs, dir
}

func TestPreflightMatrix(t *testing.T) {
	cases := []struct {
		id        string
		mode      string
		wantBlock bool
		wantID    string
		maxPass   int
	}{
		{id: "P1", mode: config.ModeConvert, wantBlock: true, wantID: "P1"},
		{id: "P1b", mode: config.ModeCoexist, wantBlock: false, wantID: "P1b"},
		{id: "P2", mode: config.ModeConvert, wantBlock: false, wantID: "P2"},
		{id: "P2b", mode: config.ModeConvert, wantBlock: true, wantID: "P2b"},
		{id: "X5", mode: config.ModeCoexist, wantBlock: true, wantID: "X5"},
		{id: "S1", mode: config.ModeCoexist, wantBlock: false, wantID: "S1", maxPass: 3},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			objs, dir := loadCase(t, tc.id)
			cfg := baseCfg(tc.mode, dir)
			if tc.maxPass > 0 {
				cfg.MaxPassthroughListeners = tc.maxPass
			}
			report, err := pipeline.PreflightOnly(cfg, objs)
			if err != nil {
				t.Fatal(err)
			}
			if report.HasBlockers() != tc.wantBlock {
				t.Fatalf("blockers=%v want=%v: %+v", report.HasBlockers(), tc.wantBlock, report.Blockers)
			}
			if tc.wantID != "" && !hasEntry(report, tc.wantID) {
				t.Fatalf("missing entry %s: blockers=%v warnings=%v skipped=%v", tc.wantID, report.Blockers, report.Warnings, report.Skipped)
			}
		})
	}
}

func hasEntry(r preflight.Report, id string) bool {
	for _, e := range append(append(r.Blockers, r.Warnings...), r.Skipped...) {
		if e.ID == id {
			return true
		}
	}
	return false
}

func TestCoexistGeneration(t *testing.T) {
	cases := []struct {
		id      string
		ownHost []string
		nginxNS string
		assert  func(t *testing.T, bundle emitout.Bundle)
	}{
		{
			id: "X1",
			assert: func(t *testing.T, bundle emitout.Bundle) {
				if !containsKind(bundle.Infra, "TLSRoute") {
					t.Fatal("expected TLSRoute in infra")
				}
				if hasCatchAllTLSListener(bundle) {
					t.Fatal("must not create catch-all TLS listener")
				}
			},
		},
		{
			id: "X2",
			assert: func(t *testing.T, bundle emitout.Bundle) {
				if containsKind(bundle.Infra, "TLSRoute") {
					t.Fatal("http-plain should not emit TLSRoute")
				}
				if !containsKind(bundle.Infra, "HTTPRoute") {
					t.Fatal("expected HTTP catch-all route")
				}
			},
		},
		{
			id: "X3",
			assert: func(t *testing.T, bundle emitout.Bundle) {
				if !containsKind(bundle.Infra, "HTTPRoute") || !containsKind(bundle.Infra, "TLSRoute") {
					t.Fatal("expected both HTTP catch-all and TLSRoute")
				}
			},
		},
		{
			id:      "X4",
			ownHost: []string{"own.example.com"},
			assert: func(t *testing.T, bundle emitout.Bundle) {
				if !containsKind(bundle.Infra, "TLSRoute") {
					t.Fatal("expected retained TLSRoute in infra")
				}
			},
		},
		{
			id:      "R1",
			nginxNS: "other-ns",
			assert: func(t *testing.T, bundle emitout.Bundle) {
				if !containsKind(bundle.Infra, "ReferenceGrant") {
					t.Fatal("expected cross-namespace ReferenceGrant")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			objs, dir := loadCase(t, tc.id)
			cfg := baseCfg(config.ModeCoexist, dir)
			cfg.OwnHosts = tc.ownHost
			if tc.nginxNS != "" {
				cfg.NginxNamespace = tc.nginxNS
			}
			resources, _, err := pipeline.GenerateCoexistOnly(cfg, objs)
			if err != nil {
				t.Fatal(err)
			}
			bundle := emitout.SplitResources(resources, nil)
			tc.assert(t, bundle)
		})
	}
}

func TestConvertMatrix(t *testing.T) {
	cases := []struct {
		id   string
		mode string
	}{
		{id: "C1", mode: config.ModeConvert},
		{id: "C2", mode: config.ModeConvert},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			objs, dir := loadCase(t, tc.id)
			cfg := baseCfg(tc.mode, dir)
			result, err := pipeline.Convert(context.Background(), cfg, objs)
			if err != nil {
				t.Fatal(err)
			}
			if result.ExitCode != emitout.ExitOK {
				t.Fatalf("exit=%d blockers=%v", result.ExitCode, result.Report.Blockers)
			}
			if tc.id == "C2" {
				if containsKind(result.Bundle.App, "Certificate") || containsKind(result.Bundle.Infra, "TLSRoute") {
					t.Fatal("http-plain should not emit TLS artifacts")
				}
			}
			if tc.id == "C1" && len(result.Bundle.App) == 0 && len(result.Bundle.Infra) == 0 {
				t.Fatal("expected generated resources for C1")
			}
		})
	}
}

func TestEmitoutSplitP3(t *testing.T) {
	objs, dir := loadCase(t, "X2")
	cfg := baseCfg(config.ModeCoexist, dir)
	resources, _, err := pipeline.GenerateCoexistOnly(cfg, objs)
	if err != nil {
		t.Fatal(err)
	}
	bundle := emitout.SplitResources(resources, nil)
	if len(bundle.Infra) == 0 {
		t.Fatal("expected infra objects")
	}
	if len(bundle.App) != 0 {
		t.Fatalf("retained-only should leave app/ empty, got %d", len(bundle.App))
	}
}

func TestCLIExitCodes(t *testing.T) {
	t.Run("blockers", func(t *testing.T) {
		objs, dir := loadCase(t, "X5")
		cfg := baseCfg(config.ModeCoexist, dir)
		report, err := pipeline.PreflightOnly(cfg, objs)
		if err != nil {
			t.Fatal(err)
		}
		if !report.HasBlockers() {
			t.Fatal("expected blockers")
		}
	})
	t.Run("no overwrite", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		w := emitout.Writer{OutputDir: dir, Force: false, SplitInfraApp: false, Report: preflight.Report{}, ReportFormat: "markdown"}
		if err := w.WriteSplit(emitout.Bundle{}); err == nil {
			t.Fatal("expected overwrite error")
		}
	})
}

func containsKind(objects []runtime.Object, kind string) bool {
	for _, obj := range objects {
		switch o := obj.(type) {
		case *gatewayv1.Gateway:
			if kind == "Gateway" {
				return true
			}
		case *gatewayv1.HTTPRoute:
			if kind == "HTTPRoute" {
				return true
			}
		case *gatewayv1.TLSRoute:
			if kind == "TLSRoute" {
				return true
			}
		case *gatewayv1beta1.ReferenceGrant:
			if kind == "ReferenceGrant" {
				return true
			}
		case *unstructured.Unstructured:
			if o.GetKind() == kind {
				return true
			}
		}
	}
	return false
}

func hasCatchAllTLSListener(bundle emitout.Bundle) bool {
	for _, obj := range bundle.Infra {
		gw, ok := obj.(*gatewayv1.Gateway)
		if !ok {
			continue
		}
		for _, l := range gw.Spec.Listeners {
			if l.Protocol == gatewayv1.TLSProtocolType && l.Hostname == nil {
				return true
			}
		}
	}
	return false
}
