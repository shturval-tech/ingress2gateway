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
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// SharedGatewayPostProcessOptions is an alias used by ApplySharedGateway.
// Prefer SharedGatewayOptions on EmitterConf / public APIs.
type SharedGatewayPostProcessOptions = SharedGatewayOptions

// ApplySharedGateway mutates gatewayResources in place: optionally merge Gateways,
// rewrite parentRefs, emit ReferenceGrants for cross-namespace TLS secrets, and
// apply class / default TLS settings.
func ApplySharedGateway(resources *GatewayResources, opts SharedGatewayOptions) error {
	if resources == nil || !opts.sharedGatewayEnabled() {
		return nil
	}

	defaultSecret, err := parseNamespacedName(opts.DefaultTLSSecret)
	if err != nil {
		return err
	}

	if opts.GatewayName != "" {
		if err := mergeGateways(resources, opts); err != nil {
			return err
		}
		rewriteParentRefs(resources, opts)
	}

	if opts.GatewayClassName != "" {
		for key, gw := range resources.Gateways {
			gw.Spec.GatewayClassName = gatewayv1.ObjectName(opts.GatewayClassName)
			resources.Gateways[key] = gw
		}
	}

	if defaultSecret != nil {
		applyDefaultTLS(resources, *defaultSecret)
	}

	ensureTLSSecretReferenceGrants(resources)
	return nil
}

func parseNamespacedName(value string) (*types.NamespacedName, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("default TLS secret must be namespace/name, got %q", value)
	}
	return &types.NamespacedName{Namespace: parts[0], Name: parts[1]}, nil
}

func (o SharedGatewayOptions) sharedGatewayEnabled() bool {
	return o.GatewayName != "" || o.GatewayClassName != "" || o.DefaultTLSSecret != ""
}

func mergeGateways(resources *GatewayResources, opts SharedGatewayOptions) error {
	if len(resources.Gateways) == 0 {
		return nil
	}

	keys := make([]types.NamespacedName, 0, len(resources.Gateways))
	for key := range resources.Gateways {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})

	ns := opts.GatewayNamespace
	if ns == "" {
		ns = keys[0].Namespace
	}

	src := resources.Gateways[keys[0]]
	merged := src.DeepCopy()
	if merged == nil {
		copied := src
		merged = &copied
	}
	merged.Name = opts.GatewayName
	merged.Namespace = ns
	merged.Spec.Listeners = nil

	seen := map[string]struct{}{}
	for _, key := range keys {
		gw := resources.Gateways[key]
		for _, listener := range gw.Spec.Listeners {
			lk := listenerKey(listener)
			if _, ok := seen[lk]; ok {
				continue
			}
			seen[lk] = struct{}{}
			merged.Spec.Listeners = append(merged.Spec.Listeners, listener)
		}
		if opts.GatewayClassName == "" && merged.Spec.GatewayClassName == "" {
			merged.Spec.GatewayClassName = gw.Spec.GatewayClassName
		}
	}

	sort.SliceStable(merged.Spec.Listeners, func(i, j int) bool {
		return listenerKey(merged.Spec.Listeners[i]) < listenerKey(merged.Spec.Listeners[j])
	})

	resources.Gateways = map[types.NamespacedName]gatewayv1.Gateway{
		{Namespace: ns, Name: opts.GatewayName}: *merged,
	}
	return nil
}

func listenerKey(l gatewayv1.Listener) string {
	host := ""
	if l.Hostname != nil {
		host = string(*l.Hostname)
	}
	return fmt.Sprintf("%s|%d|%s|%s", l.Name, l.Port, l.Protocol, host)
}

func rewriteParentRefs(resources *GatewayResources, opts SharedGatewayOptions) {
	ns := opts.GatewayNamespace
	if ns == "" {
		for key := range resources.Gateways {
			ns = key.Namespace
			break
		}
	}
	targetNS := gatewayv1.Namespace(ns)
	targetName := gatewayv1.ObjectName(opts.GatewayName)

	for key, route := range resources.HTTPRoutes {
		route.Spec.ParentRefs = rewriteRefs(route.Spec.ParentRefs, targetNS, targetName)
		resources.HTTPRoutes[key] = route
	}
	for key, route := range resources.TLSRoutes {
		route.Spec.ParentRefs = rewriteRefs(route.Spec.ParentRefs, targetNS, targetName)
		resources.TLSRoutes[key] = route
	}
	for key, route := range resources.GRPCRoutes {
		route.Spec.ParentRefs = rewriteRefs(route.Spec.ParentRefs, targetNS, targetName)
		resources.GRPCRoutes[key] = route
	}
	for key, route := range resources.TCPRoutes {
		route.Spec.ParentRefs = rewriteAlphaRefs(route.Spec.ParentRefs, targetNS, targetName)
		resources.TCPRoutes[key] = route
	}
	for key, route := range resources.UDPRoutes {
		route.Spec.ParentRefs = rewriteAlphaRefs(route.Spec.ParentRefs, targetNS, targetName)
		resources.UDPRoutes[key] = route
	}
}

func rewriteRefs(refs []gatewayv1.ParentReference, ns gatewayv1.Namespace, name gatewayv1.ObjectName) []gatewayv1.ParentReference {
	if len(refs) == 0 {
		return []gatewayv1.ParentReference{{
			Name:      name,
			Namespace: ptr.To(ns),
		}}
	}
	out := make([]gatewayv1.ParentReference, len(refs))
	for i, ref := range refs {
		ref.Name = name
		ref.Namespace = ptr.To(ns)
		out[i] = ref
	}
	return out
}

func rewriteAlphaRefs(refs []gatewayv1.ParentReference, ns gatewayv1.Namespace, name gatewayv1.ObjectName) []gatewayv1.ParentReference {
	return rewriteRefs(refs, ns, name)
}

func applyDefaultTLS(resources *GatewayResources, secret types.NamespacedName) {
	for key, gw := range resources.Gateways {
		changed := false
		for i := range gw.Spec.Listeners {
			listener := &gw.Spec.Listeners[i]
			if listener.Protocol != gatewayv1.HTTPSProtocolType {
				continue
			}
			if listener.TLS == nil {
				listener.TLS = &gatewayv1.ListenerTLSConfig{}
			}
			if len(listener.TLS.CertificateRefs) > 0 {
				continue
			}
			ref := gatewayv1.SecretObjectReference{
				Name: gatewayv1.ObjectName(secret.Name),
			}
			if secret.Namespace != "" && secret.Namespace != gw.Namespace {
				ref.Namespace = ptr.To(gatewayv1.Namespace(secret.Namespace))
			}
			listener.TLS.CertificateRefs = []gatewayv1.SecretObjectReference{ref}
			changed = true
		}
		if changed {
			resources.Gateways[key] = gw
		}
	}
}

func ensureTLSSecretReferenceGrants(resources *GatewayResources) {
	if resources.ReferenceGrants == nil {
		resources.ReferenceGrants = map[types.NamespacedName]gatewayv1beta1.ReferenceGrant{}
	}

	type grantKey struct {
		fromNS, toNS, secretName string
	}
	needed := map[grantKey]struct{}{}

	for _, gw := range resources.Gateways {
		for _, listener := range gw.Spec.Listeners {
			if listener.TLS == nil {
				continue
			}
			for _, ref := range listener.TLS.CertificateRefs {
				secretNS := gw.Namespace
				if ref.Namespace != nil && string(*ref.Namespace) != "" {
					secretNS = string(*ref.Namespace)
				}
				if secretNS == gw.Namespace {
					continue
				}
				needed[grantKey{
					fromNS:     gw.Namespace,
					toNS:       secretNS,
					secretName: string(ref.Name),
				}] = struct{}{}
			}
		}
	}

	keys := make([]grantKey, 0, len(needed))
	for k := range needed {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.toNS != b.toNS {
			return a.toNS < b.toNS
		}
		if a.fromNS != b.fromNS {
			return a.fromNS < b.fromNS
		}
		return a.secretName < b.secretName
	})

	for _, k := range keys {
		name := fmt.Sprintf("allow-gateway-tls-%s-%s", sanitize(k.fromNS), sanitize(k.secretName))
		nn := types.NamespacedName{Namespace: k.toNS, Name: name}
		if _, exists := resources.ReferenceGrants[nn]; exists {
			continue
		}
		rg := gatewayv1beta1.ReferenceGrant{
			TypeMeta: metav1.TypeMeta{
				APIVersion: gatewayv1beta1.GroupVersion.String(),
				Kind:       "ReferenceGrant",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: k.toNS,
			},
			Spec: gatewayv1beta1.ReferenceGrantSpec{
				From: []gatewayv1beta1.ReferenceGrantFrom{{
					Group:     gatewayv1.GroupName,
					Kind:      "Gateway",
					Namespace: gatewayv1.Namespace(k.fromNS),
				}},
				To: []gatewayv1beta1.ReferenceGrantTo{{
					Group: corev1.GroupName,
					Kind:  "Secret",
					Name:  ptr.To(gatewayv1.ObjectName(k.secretName)),
				}},
			},
		}
		resources.ReferenceGrants[nn] = rg
	}
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return strings.Trim(out, "-")
}
