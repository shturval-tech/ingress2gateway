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

package pipeline

import (
	"context"
	"fmt"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/classify"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/coexist"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/emitout"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/manifest"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/overlay"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/preflight"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	// Register upstream providers and emitters used by convert/print.
	_ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/emitters/standard"
	_ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/cilium"
	_ "github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw/providers/ingressnginx"
)

// Result is the output of convert/print pipeline.
type Result struct {
	Report   preflight.Report
	Bundle   emitout.Bundle
	ExitCode int
}

// Convert runs preflight then generates split manifests.
func Convert(ctx context.Context, cfg config.Config, objects []runtime.Object) (Result, error) {
	res := Result{ExitCode: emitout.ExitOK}
	report, err := PreflightOnly(cfg, objects)
	if err != nil {
		return res, err
	}
	res.Report = report
	if report.HasBlockers() {
		res.ExitCode = emitout.ExitBlockers
		return res, nil
	}

	hosts := report.Hosts
	ingresses := manifest.Ingresses(objects)
	if len(hosts) == 0 && len(ingresses) > 0 {
		classifier := classify.Classifier{Mode: cfg.Mode, OwnHosts: cfg.OwnHosts, RetainHosts: cfg.RetainHosts}
		hosts, err = classifier.ClassifyIngresses(ingresses)
		if err != nil {
			return res, err
		}
	}

	reader, err := manifest.Reader(cfg.InputFile)
	if err != nil {
		return res, fmt.Errorf("input: %w", err)
	}

	gwResources, _, err := i2gw.ToGatewayAPIResourcesWithOptions(ctx, cfg.Namespace, reader, cfg.Providers, cfg.Emitter, nil, cfg.AllowExperimentalGWAPI, true, cfg.SharedGatewayOptions())
	if err != nil {
		return res, err
	}
	if len(gwResources) == 0 {
		return res, fmt.Errorf("no gateway resources emitted")
	}
	merged := mergeResources(gwResources)
	if cfg.Mode == config.ModeCoexist {
		if err := coexist.Apply(&merged, cfg, hosts, overlay.RouteNamespace(cfg)); err != nil {
			return res, err
		}
	}
	overlayResult := overlay.Apply(&merged, cfg, hosts)
	res.Bundle = emitout.SplitResources(merged, overlayResult.Certificates)
	return res, nil
}

// PreflightOnly runs analysis without conversion.
func PreflightOnly(cfg config.Config, objects []runtime.Object) (preflight.Report, error) {
	classify.ResetListenerNameCache()
	store := newStore(objects)
	runner := preflight.Runner{
		Config:    cfg,
		Ingresses: manifest.Ingresses(objects),
		Gateways:  manifest.Gateways(objects),
		Cluster:   store,
		CRDs:      store.crdChecker(),
	}
	return runner.Run()
}

type clusterStore struct {
	objects []runtime.Object
}

func newStore(objects []runtime.Object) *clusterStore {
	return &clusterStore{objects: objects}
}

func (s *clusterStore) ListIngresses() ([]networkingv1.Ingress, error) {
	return manifest.Ingresses(s.objects), nil
}

func (s *clusterStore) ListGateways() ([]gatewayv1.Gateway, error) {
	return manifest.Gateways(s.objects), nil
}

func (s *clusterStore) GetIssuer(name, kind string) (map[string]any, bool) {
	for _, obj := range manifest.UnstructuredByKind(s.objects, kind) {
		if obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *clusterStore) GetService(namespace, name string) (map[string]any, bool) {
	for _, obj := range manifest.UnstructuredByKind(s.objects, "Service") {
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *clusterStore) GetUnstructured(gvk, namespace, name string) (map[string]any, bool) {
	for _, obj := range manifest.UnstructuredByKind(s.objects, gvk) {
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *clusterStore) HasCRD(group, version, resource string) bool {
	want := group + "/" + version + "/" + resource
	for _, obj := range manifest.UnstructuredByKind(s.objects, "CustomResourceDefinition") {
		spec, _ := obj.Object["spec"].(map[string]any)
		if spec == nil {
			continue
		}
		g, _ := spec["group"].(string)
		names, _ := spec["names"].(map[string]any)
		plural, _ := names["plural"].(string)
		for _, ver := range crdVersions(spec) {
			if g+"/"+ver+"/"+plural == want {
				return true
			}
		}
	}
	return false
}

func (s *clusterStore) crdChecker() preflight.CRDChecker {
	// Offline/file mode fixtures rarely embed CRDs. Assume public CRDs are present
	// unless the fixture explicitly includes CustomResourceDefinition objects.
	offline := !s.hasAnyCRDObject()
	return staticCRDs{
		gateway: offline || s.HasCRD("gateway.networking.k8s.io", "v1", "gateways") || len(manifest.Gateways(s.objects)) > 0,
		tls:     offline || s.HasCRD("gateway.networking.k8s.io", "v1", "tlsroutes"),
		btls:    s.HasCRD("gateway.networking.k8s.io", "v1", "backendtlspolicies"),
		cm:      offline || s.HasCRD("cert-manager.io", "v1", "certificates") || s.hasCertManagerObjects(),
	}
}

func (s *clusterStore) hasAnyCRDObject() bool {
	return len(manifest.UnstructuredByKind(s.objects, "CustomResourceDefinition")) > 0
}

func (s *clusterStore) hasCertManagerObjects() bool {
	return len(manifest.UnstructuredByKind(s.objects, "ClusterIssuer")) > 0 ||
		len(manifest.UnstructuredByKind(s.objects, "Issuer")) > 0
}

type staticCRDs struct {
	gateway, tls, btls, cm bool
}

func (s staticCRDs) HasGatewayAPI() bool         { return s.gateway }
func (s staticCRDs) HasTLSRouteV1() bool         { return s.tls }
func (s staticCRDs) HasBackendTLSPolicyV1() bool { return s.btls }
func (s staticCRDs) HasCertManager() bool        { return s.cm }
func (s staticCRDs) CertManagerReady() bool      { return s.cm }

func crdVersions(spec map[string]any) []string {
	vers, _ := spec["versions"].([]any)
	out := make([]string, 0, len(vers))
	for _, v := range vers {
		vm, _ := v.(map[string]any)
		if name, _ := vm["name"].(string); name != "" {
			out = append(out, name)
		}
	}
	return out
}

func mergeResources(list []i2gw.GatewayResources) i2gw.GatewayResources {
	if len(list) == 1 {
		return list[0]
	}
	out := i2gw.GatewayResources{
		Gateways:           map[types.NamespacedName]gatewayv1.Gateway{},
		HTTPRoutes:         map[types.NamespacedName]gatewayv1.HTTPRoute{},
		TLSRoutes:          map[types.NamespacedName]gatewayv1.TLSRoute{},
		ReferenceGrants:    map[types.NamespacedName]gatewayv1beta1.ReferenceGrant{},
		BackendTLSPolicies: map[types.NamespacedName]gatewayv1.BackendTLSPolicy{},
	}
	for _, gr := range list {
		for k, v := range gr.Gateways {
			out.Gateways[k] = v
		}
		for k, v := range gr.HTTPRoutes {
			out.HTTPRoutes[k] = v
		}
		for k, v := range gr.TLSRoutes {
			out.TLSRoutes[k] = v
		}
		for k, v := range gr.ReferenceGrants {
			out.ReferenceGrants[k] = v
		}
		for k, v := range gr.BackendTLSPolicies {
			out.BackendTLSPolicies[k] = v
		}
	}
	return out
}

// GenerateCoexistOnly builds coexist resources without i2gw (unit tests).
func GenerateCoexistOnly(cfg config.Config, objects []runtime.Object) (i2gw.GatewayResources, []classify.HostRecord, error) {
	classify.ResetListenerNameCache()
	ingresses := manifest.Ingresses(objects)
	classifier := classify.Classifier{Mode: cfg.Mode, OwnHosts: cfg.OwnHosts, RetainHosts: cfg.RetainHosts}
	hosts, err := classifier.ClassifyIngresses(ingresses)
	if err != nil {
		return i2gw.GatewayResources{}, nil, err
	}
	resources := i2gw.GatewayResources{
		Gateways:           map[types.NamespacedName]gatewayv1.Gateway{},
		HTTPRoutes:         map[types.NamespacedName]gatewayv1.HTTPRoute{},
		TLSRoutes:          map[types.NamespacedName]gatewayv1.TLSRoute{},
		ReferenceGrants:    map[types.NamespacedName]gatewayv1beta1.ReferenceGrant{},
		BackendTLSPolicies: map[types.NamespacedName]gatewayv1.BackendTLSPolicy{},
	}
	if err := coexist.Apply(&resources, cfg, hosts, overlay.RouteNamespace(cfg)); err != nil {
		return resources, hosts, err
	}
	return resources, hosts, nil
}
