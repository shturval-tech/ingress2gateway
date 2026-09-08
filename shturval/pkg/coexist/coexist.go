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

package coexist

import (
	"fmt"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/classify"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// Apply mutates gateway resources for coexist mode retained hosts.
func Apply(resources *i2gw.GatewayResources, cfg config.Config, hosts []classify.HostRecord, routeNamespace string) error {
	if resources == nil {
		return nil
	}
	if resources.Gateways == nil {
		resources.Gateways = map[types.NamespacedName]gatewayv1.Gateway{}
	}
	if resources.TLSRoutes == nil {
		resources.TLSRoutes = map[types.NamespacedName]gatewayv1.TLSRoute{}
	}
	if resources.HTTPRoutes == nil {
		resources.HTTPRoutes = map[types.NamespacedName]gatewayv1.HTTPRoute{}
	}
	if resources.ReferenceGrants == nil {
		resources.ReferenceGrants = map[types.NamespacedName]gatewayv1beta1.ReferenceGrant{}
	}
	if resources.BackendTLSPolicies == nil {
		resources.BackendTLSPolicies = map[types.NamespacedName]gatewayv1.BackendTLSPolicy{}
	}

	gwKey := types.NamespacedName{Namespace: cfg.GatewayNamespace, Name: cfg.GatewayName}
	gw, ok := resources.Gateways[gwKey]
	if !ok {
		gw = gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: cfg.GatewayName, Namespace: cfg.GatewayNamespace},
			Spec: gatewayv1.GatewaySpec{
				GatewayClassName: gatewayv1.ObjectName(cfg.GatewayClassName),
			},
		}
	}

	needsHTTPCatchAll := false
	for _, h := range hosts {
		if h.Ownership != classify.OwnershipIngressRetained {
			continue
		}
		switch h.IngressKind {
		case classify.IngressKindHTTPPlain, classify.IngressKindHTTPSRedirectOnly:
			needsHTTPCatchAll = true
		case classify.IngressKindHTTPSTerminate, classify.IngressKindHTTPSPassthrough:
			if cfg.CoexistHTTPS == config.CoexistHTTPSReencrypt && h.IngressKind == classify.IngressKindHTTPSTerminate {
				if err := addReencryptPolicy(resources, cfg, h, routeNamespace); err != nil {
					return err
				}
				continue
			}
			gw.Spec.Listeners = appendListenerIfMissing(gw.Spec.Listeners, passthroughListener(h))
			addTLSRoute(resources, cfg, h, routeNamespace)
		}
	}
	if needsHTTPCatchAll {
		gw.Spec.Listeners = appendListenerIfMissing(gw.Spec.Listeners, httpCatchAllListener())
		addHTTPCatchAllRoute(resources, cfg, routeNamespace)
	}
	resources.Gateways[gwKey] = gw
	ensureBackendReferenceGrants(resources, cfg, routeNamespace)
	return nil
}

func passthroughListener(h classify.HostRecord) gatewayv1.Listener {
	host := gatewayv1.Hostname(h.Hostname)
	return gatewayv1.Listener{
		Name:     gatewayv1.SectionName(h.ListenerName),
		Port:     443,
		Protocol: gatewayv1.TLSProtocolType,
		Hostname: &host,
		TLS: &gatewayv1.ListenerTLSConfig{
			Mode: ptr.To(gatewayv1.TLSModePassthrough),
		},
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Kinds: []gatewayv1.RouteGroupKind{{
				Group: ptr.To(gatewayv1.Group(gatewayv1.GroupVersion.Group)),
				Kind:  gatewayv1.Kind("TLSRoute"),
			}},
		},
	}
}

func httpCatchAllListener() gatewayv1.Listener {
	return gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Protocol: gatewayv1.HTTPProtocolType,
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Kinds: []gatewayv1.RouteGroupKind{{
				Group: ptr.To(gatewayv1.Group(gatewayv1.GroupVersion.Group)),
				Kind:  gatewayv1.Kind("HTTPRoute"),
			}},
		},
	}
}

func appendListenerIfMissing(listeners []gatewayv1.Listener, l gatewayv1.Listener) []gatewayv1.Listener {
	for _, existing := range listeners {
		if existing.Name == l.Name {
			return listeners
		}
	}
	return append(listeners, l)
}

func addTLSRoute(resources *i2gw.GatewayResources, cfg config.Config, h classify.HostRecord, routeNamespace string) {
	name := fmt.Sprintf("retained-tls-%s", h.ListenerName)
	nn := types.NamespacedName{Namespace: routeNamespace, Name: name}
	host := gatewayv1.Hostname(h.Hostname)
	gwNS := gatewayv1.Namespace(cfg.GatewayNamespace)
	gwName := gatewayv1.ObjectName(cfg.GatewayName)
	section := gatewayv1.SectionName(h.SectionName)
	resources.TLSRoutes[nn] = gatewayv1.TLSRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: routeNamespace},
		Spec: gatewayv1.TLSRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name:        gwName,
					Namespace:   &gwNS,
					SectionName: &section,
				}},
			},
			Hostnames: []gatewayv1.Hostname{host},
			Rules: []gatewayv1.TLSRouteRule{{
				BackendRefs: []gatewayv1.BackendRef{{
					BackendObjectReference: gatewayv1.BackendObjectReference{
						Name: gatewayv1.ObjectName(cfg.NginxService),
						Port: ptr.To(gatewayv1.PortNumber(cfg.NginxHTTPSPort)),
					},
				}},
			}},
		},
	}
}

func addHTTPCatchAllRoute(resources *i2gw.GatewayResources, cfg config.Config, routeNamespace string) {
	name := "retained-http-catchall"
	nn := types.NamespacedName{Namespace: routeNamespace, Name: name}
	gwNS := gatewayv1.Namespace(cfg.GatewayNamespace)
	gwName := gatewayv1.ObjectName(cfg.GatewayName)
	section := gatewayv1.SectionName("http")
	resources.HTTPRoutes[nn] = gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: routeNamespace},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{
					Name:        gwName,
					Namespace:   &gwNS,
					SectionName: &section,
				}},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name: gatewayv1.ObjectName(cfg.NginxService),
							Port: ptr.To(gatewayv1.PortNumber(cfg.NginxHTTPPort)),
						},
					},
				}},
			}},
		},
	}
}

func addReencryptPolicy(resources *i2gw.GatewayResources, cfg config.Config, h classify.HostRecord, routeNamespace string) error {
	name := fmt.Sprintf("retained-reencrypt-%s", h.ListenerName)
	nn := types.NamespacedName{Namespace: routeNamespace, Name: name}
	target := gatewayv1.LocalObjectReference{Name: gatewayv1.ObjectName(cfg.NginxService)}
	policy := gatewayv1.BackendTLSPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: routeNamespace},
		Spec: gatewayv1.BackendTLSPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: gatewayv1.Group(corev1.GroupName),
					Kind:  "Service",
					Name:  target.Name,
				},
			}},
			Validation: gatewayv1.BackendTLSPolicyValidation{
				Hostname: gatewayv1.PreciseHostname(h.Hostname),
			},
		},
	}
	if cfg.ReencryptSystemCA {
		policy.Spec.Validation.WellKnownCACertificates = ptr.To(gatewayv1.WellKnownCACertificatesSystem)
	}
	resources.BackendTLSPolicies[nn] = policy
	return nil
}

func ensureBackendReferenceGrants(resources *i2gw.GatewayResources, cfg config.Config, routeNamespace string) {
	if routeNamespace == cfg.NginxNamespace {
		return
	}
	name := fmt.Sprintf("allow-retained-routes-%s", routeNamespace)
	nn := types.NamespacedName{Namespace: cfg.NginxNamespace, Name: name}
	if _, exists := resources.ReferenceGrants[nn]; exists {
		return
	}
	resources.ReferenceGrants[nn] = gatewayv1beta1.ReferenceGrant{
		TypeMeta: metav1.TypeMeta{
			APIVersion: gatewayv1beta1.GroupVersion.String(),
			Kind:       "ReferenceGrant",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: cfg.NginxNamespace},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{{
				Group:     gatewayv1.GroupName,
				Kind:      "HTTPRoute",
				Namespace: gatewayv1.Namespace(routeNamespace),
			}, {
				Group:     gatewayv1.GroupName,
				Kind:      "TLSRoute",
				Namespace: gatewayv1.Namespace(routeNamespace),
			}},
			To: []gatewayv1beta1.ReferenceGrantTo{{
				Group: corev1.GroupName,
				Kind:  "Service",
				Name:  ptr.To(gatewayv1.ObjectName(cfg.NginxService)),
			}},
		},
	}
}
