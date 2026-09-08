/*
Copyright 2026 The Kubernetes Authors.

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

package i2gw

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestApplyMergeAndParentRefs(t *testing.T) {
	resources := &GatewayResources{
		Gateways: map[types.NamespacedName]gatewayv1.Gateway{
			{Namespace: "apps", Name: "app-a"}: {
				ObjectMeta: metav1.ObjectMeta{Name: "app-a", Namespace: "apps"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "example-proxy",
					Listeners: []gatewayv1.Listener{{
						Name:     "http",
						Port:     80,
						Protocol: gatewayv1.HTTPProtocolType,
					}},
				},
			},
			{Namespace: "apps", Name: "app-b"}: {
				ObjectMeta: metav1.ObjectMeta{Name: "app-b", Namespace: "apps"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "example-proxy",
					Listeners: []gatewayv1.Listener{{
						Name:     "https",
						Port:     443,
						Protocol: gatewayv1.HTTPSProtocolType,
						Hostname: ptr.To(gatewayv1.Hostname("b.example.com")),
					}},
				},
			},
		},
		HTTPRoutes: map[types.NamespacedName]gatewayv1.HTTPRoute{
			{Namespace: "apps", Name: "route-a"}: {
				ObjectMeta: metav1.ObjectMeta{Name: "route-a", Namespace: "apps"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{{Name: "app-a"}},
					},
				},
			},
		},
	}

	err := ApplySharedGateway(resources, SharedGatewayOptions{
		GatewayName:      "shared-gateway",
		GatewayNamespace: "infra",
		GatewayClassName: "cilium",
		DefaultTLSSecret: "certs/default-tls",
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if len(resources.Gateways) != 1 {
		t.Fatalf("expected 1 gateway, got %d", len(resources.Gateways))
	}
	gw, ok := resources.Gateways[types.NamespacedName{Namespace: "infra", Name: "shared-gateway"}]
	if !ok {
		t.Fatalf("shared gateway missing: %+v", resources.Gateways)
	}
	if gw.Spec.GatewayClassName != "cilium" {
		t.Errorf("GatewayClassName = %q, want cilium", gw.Spec.GatewayClassName)
	}
	if len(gw.Spec.Listeners) != 2 {
		t.Fatalf("listeners = %d, want 2", len(gw.Spec.Listeners))
	}

	var https *gatewayv1.Listener
	for i := range gw.Spec.Listeners {
		if gw.Spec.Listeners[i].Protocol == gatewayv1.HTTPSProtocolType {
			https = &gw.Spec.Listeners[i]
		}
	}
	if https == nil || https.TLS == nil || len(https.TLS.CertificateRefs) != 1 {
		t.Fatalf("expected default TLS on HTTPS listener, got %+v", https)
	}
	ref := https.TLS.CertificateRefs[0]
	if string(ref.Name) != "default-tls" {
		t.Errorf("secret name = %q", ref.Name)
	}
	if ref.Namespace == nil || string(*ref.Namespace) != "certs" {
		t.Errorf("secret namespace = %v", ref.Namespace)
	}

	route := resources.HTTPRoutes[types.NamespacedName{Namespace: "apps", Name: "route-a"}]
	if len(route.Spec.ParentRefs) != 1 {
		t.Fatalf("parentRefs = %d", len(route.Spec.ParentRefs))
	}
	pr := route.Spec.ParentRefs[0]
	if string(pr.Name) != "shared-gateway" {
		t.Errorf("parent name = %q", pr.Name)
	}
	if pr.Namespace == nil || string(*pr.Namespace) != "infra" {
		t.Errorf("parent namespace = %v", pr.Namespace)
	}

	grantNN := types.NamespacedName{Namespace: "certs", Name: "allow-gateway-tls-infra-default-tls"}
	if _, ok := resources.ReferenceGrants[grantNN]; !ok {
		t.Fatalf("expected ReferenceGrant %v, got %+v", grantNN, resources.ReferenceGrants)
	}
}

func TestApplyNoop(t *testing.T) {
	resources := &GatewayResources{
		Gateways: map[types.NamespacedName]gatewayv1.Gateway{
			{Namespace: "ns", Name: "gw"}: {ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "ns"}},
		},
	}
	before := len(resources.Gateways)
	if err := ApplySharedGateway(resources, SharedGatewayOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(resources.Gateways) != before {
		t.Fatalf("noop mutated gateways")
	}
}

func TestParseNamespacedName(t *testing.T) {
	got, err := parseNamespacedName("ns/name")
	if err != nil {
		t.Fatal(err)
	}
	want := &types.NamespacedName{Namespace: "ns", Name: "name"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
	if _, err := parseNamespacedName("bad"); err == nil {
		t.Fatal("expected error")
	}
}
