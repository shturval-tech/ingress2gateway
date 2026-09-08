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

package fakecluster

import (
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Client wraps controller-runtime fake client helpers for tests.
type Client struct {
	Objects []runtime.Object
	CRDs    map[string]bool
}

// Build returns listers compatible with preflight interfaces.
func (c Client) Build() *Store {
	return NewStore(c.Objects, c.CRDs)
}

// Store implements preflight cluster interfaces.
type Store struct {
	ingresses []networkingv1.Ingress
	gateways  []gatewayv1.Gateway
	byKind    map[string][]unstructured.Unstructured
	crds      map[string]bool
}

// NewStore indexes objects for preflight.
func NewStore(objects []runtime.Object, crds map[string]bool) *Store {
	s := &Store{byKind: map[string][]unstructured.Unstructured{}, crds: crds}
	if s.crds == nil {
		s.crds = map[string]bool{}
	}
	for _, obj := range objects {
		switch v := obj.(type) {
		case *networkingv1.Ingress:
			s.ingresses = append(s.ingresses, *v)
		case *gatewayv1.Gateway:
			s.gateways = append(s.gateways, *v)
		case *unstructured.Unstructured:
			s.byKind[v.GetKind()] = append(s.byKind[v.GetKind()], *v)
		}
	}
	return s
}

func (s *Store) ListIngresses() ([]networkingv1.Ingress, error) {
	return s.ingresses, nil
}

func (s *Store) ListGateways() ([]gatewayv1.Gateway, error) {
	return s.gateways, nil
}

func (s *Store) GetIssuer(name, kind string) (map[string]any, bool) {
	for _, obj := range s.byKind[kind] {
		if obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *Store) GetService(namespace, name string) (map[string]any, bool) {
	for _, obj := range s.byKind["Service"] {
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *Store) GetUnstructured(gvk, namespace, name string) (map[string]any, bool) {
	kind := gvk
	for _, obj := range s.byKind[kind] {
		if obj.GetNamespace() == namespace && obj.GetName() == name {
			return obj.Object, true
		}
	}
	return nil, false
}

func (s *Store) HasCRD(group, version, resource string) bool {
	key := group + "/" + version + "/" + resource
	return s.crds[key]
}

// FakeCRDChecker implements preflight.CRDChecker.
type FakeCRDChecker struct {
	GatewayAPI         bool
	TLSRouteV1         bool
	BackendTLSPolicyV1 bool
	CertManager        bool
	CertManagerIsReady bool
}

func (f FakeCRDChecker) HasGatewayAPI() bool         { return f.GatewayAPI }
func (f FakeCRDChecker) HasTLSRouteV1() bool         { return f.TLSRouteV1 }
func (f FakeCRDChecker) HasBackendTLSPolicyV1() bool { return f.BackendTLSPolicyV1 }
func (f FakeCRDChecker) HasCertManager() bool        { return f.CertManager }
func (f FakeCRDChecker) CertManagerReady() bool      { return f.CertManagerIsReady }

// RuntimeClient builds controller-runtime fake client (unused helper).
func RuntimeClient(objects []runtime.Object) client.Client {
	return fake.NewClientBuilder().WithRuntimeObjects(objects...).Build()
}
