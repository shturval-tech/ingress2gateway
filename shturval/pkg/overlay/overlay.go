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

package overlay

import (
	"fmt"
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/classify"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

const (
	LabelPrefix            = "migration.shturval.tech/"
	LabelManaged           = LabelPrefix + "managed"
	LabelMode              = LabelPrefix + "mode"
	LabelHostname          = LabelPrefix + "hostname"
	LabelIngressKind       = LabelPrefix + "ingress-kind"
	LabelOwnership         = LabelPrefix + "ownership"
	LabelSourceIngress     = LabelPrefix + "source-ingress"
	AnnotationLegacyIngress = "shturval.tech/legacy-ingress"
)

// Result holds overlay sidecar objects such as Certificates.
type Result struct {
	Certificates []unstructured.Unstructured
}

// Apply adds Shturval labels/names and optional Certificate CRs.
func Apply(resources *i2gw.GatewayResources, cfg config.Config, hosts []classify.HostRecord) Result {
	out := Result{}
	if resources == nil {
		return out
	}
	labels := baseLabels(cfg)
	for key, gw := range resources.Gateways {
		mergeLabels(&gw.ObjectMeta, labels)
		resources.Gateways[key] = gw
	}
	labelRoutes(resources, hosts, labels)
	if cfg.EmitCertificates {
		out.Certificates = emitCertificates(hosts)
	}
	return out
}

func baseLabels(cfg config.Config) map[string]string {
	return map[string]string{
		LabelManaged: "true",
		LabelMode:    cfg.Mode,
	}
}

func labelRoutes(resources *i2gw.GatewayResources, hosts []classify.HostRecord, base map[string]string) {
	hostByName := map[string]classify.HostRecord{}
	for _, h := range hosts {
		hostByName[h.Hostname] = h
	}
	for key, route := range resources.HTTPRoutes {
		l := copyLabels(base)
		annotateRoute(&route.ObjectMeta, l, hostByName, route.Spec.Hostnames)
		resources.HTTPRoutes[key] = route
	}
	for key, route := range resources.TLSRoutes {
		l := copyLabels(base)
		annotateRoute(&route.ObjectMeta, l, hostByName, route.Spec.Hostnames)
		resources.TLSRoutes[key] = route
	}
}

func annotateRoute(meta *metav1.ObjectMeta, labels map[string]string, hosts map[string]classify.HostRecord, hostnames []gatewayv1.Hostname) {
	mergeLabels(meta, labels)
	if len(hostnames) > 0 {
		h := string(hostnames[0])
		labels[LabelHostname] = h
		if rec, ok := hosts[h]; ok {
			labels[LabelIngressKind] = rec.IngressKind
			labels[LabelOwnership] = rec.Ownership
			labels[LabelSourceIngress] = rec.IngressNamespace + "/" + rec.IngressName
		}
	}
	mergeLabels(meta, labels)
}

func copyLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeLabels(meta *metav1.ObjectMeta, labels map[string]string) {
	if meta.Labels == nil {
		meta.Labels = map[string]string{}
	}
	for k, v := range labels {
		meta.Labels[k] = v
	}
}

func emitCertificates(hosts []classify.HostRecord) []unstructured.Unstructured {
	var certs []unstructured.Unstructured
	for _, h := range hosts {
		if h.IngressKind == classify.IngressKindHTTPPlain {
			continue
		}
		if !h.ACME.HasIssuer {
			continue
		}
		name := sanitizeName(h.Hostname) + "-tls"
		issuerRef := map[string]any{"name": h.ACME.IssuerName}
		if h.ACME.IssuerKind == "ClusterIssuer" {
			issuerRef["kind"] = "ClusterIssuer"
		}
		obj := unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cert-manager.io/v1",
			"kind":       "Certificate",
			"metadata": map[string]any{
				"name":      name,
				"namespace": h.IngressNamespace,
				"labels": map[string]any{
					LabelManaged:   "true",
					LabelHostname:  h.Hostname,
					LabelOwnership: h.Ownership,
				},
			},
			"spec": map[string]any{
				"secretName": name,
				"dnsNames":   []any{h.Hostname},
				"issuerRef":  issuerRef,
			},
		}}
		certs = append(certs, obj)
	}
	return certs
}

func sanitizeName(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	host = strings.ReplaceAll(host, "*.", "wildcard-")
	host = strings.ReplaceAll(host, ".", "-")
	if len(host) > 50 {
		host = host[:50]
	}
	return host
}

// GatewayKey returns the namespaced name for the configured shared gateway.
func GatewayKey(cfg config.Config) types.NamespacedName {
	return types.NamespacedName{Namespace: cfg.GatewayNamespace, Name: cfg.GatewayName}
}

// RouteNamespace picks namespace for coexist retained routes.
func RouteNamespace(cfg config.Config) string {
	if cfg.GatewayNamespace != "" {
		return cfg.GatewayNamespace
	}
	return "default"
}

// CertificateNames returns deterministic certificate object names for hosts.
func CertificateNames(hosts []classify.HostRecord) []string {
	names := make([]string, 0)
	for _, h := range hosts {
		if h.ACME.HasIssuer && h.IngressKind != classify.IngressKindHTTPPlain {
			names = append(names, fmt.Sprintf("%s-tls", sanitizeName(h.Hostname)))
		}
	}
	return names
}
