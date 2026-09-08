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

package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
)

const (
	IngressKindHTTPPlain          = "http-plain"
	IngressKindHTTPSTerminate     = "https-terminate"
	IngressKindHTTPSPassthrough   = "https-passthrough"
	IngressKindHTTPSRedirectOnly  = "https-redirect-only"
	IngressKindMixedMultiHost     = "mixed-multi-host"

	SchemeHTTPOnly = "http-only"
	SchemeHTTPS    = "https"

	TLSTerminateGateway = "gateway"
	TLSTerminateNginx   = "nginx"
	TLSTerminateNone    = "none"

	OwnershipGatewayOwned     = "gateway-owned"
	OwnershipIngressRetained  = "ingress-retained"

	sslPassthroughAnnotation = "nginx.ingress.kubernetes.io/ssl-passthrough"
	sslRedirectAnnotation    = "nginx.ingress.kubernetes.io/ssl-redirect"
	backendProtocolAnnot     = "nginx.ingress.kubernetes.io/backend-protocol"
	issuerAnnotation         = "cert-manager.io/issuer"
	clusterIssuerAnnotation  = "cert-manager.io/cluster-issuer"
)

// HostRecord describes a classified hostname entry.
type HostRecord struct {
	Hostname         string
	IngressKind      string
	Scheme           string
	TLSTerminateAt   string
	BackendProtocol  string
	RelatedHostnames []string
	Ownership        string
	ACME             ACMEInfo
	IngressName      string
	IngressNamespace string
	ListenerName     string
	SectionName      string
}

// ACMEInfo captures cert-manager issuer references for a host.
type ACMEInfo struct {
	IssuerKind string
	IssuerName string
	HasIssuer  bool
}

// Classifier assigns ownership and ingress kinds from ingress objects.
type Classifier struct {
	Mode        string
	OwnHosts    []string
	RetainHosts []string
}

// ClassifyIngresses returns per-host records sorted by hostname.
func (c Classifier) ClassifyIngresses(ingresses []networkingv1.Ingress) ([]HostRecord, error) {
	byHost := map[string]*HostRecord{}

	for _, ing := range ingresses {
		kind := ingressResourceKind(ing)
		hosts := hostsForIngress(ing)
		if len(hosts) == 0 {
			continue
		}
		for _, host := range hosts {
			norm := NormalizeHostname(host)
			rec := classifyHost(ing, norm, kind)
			if existing, ok := byHost[norm]; ok {
				if existing.IngressKind != rec.IngressKind {
					return nil, fmt.Errorf("hostname %q changed ingressKind from %q to %q", norm, existing.IngressKind, rec.IngressKind)
				}
				if existing.Ownership != rec.Ownership {
					return nil, fmt.Errorf("hostname %q has conflicting ownership", norm)
				}
				continue
			}
			rec.Ownership = c.resolveOwnership(norm, rec.IngressKind)
			rec.ListenerName = ListenerName(norm)
			rec.SectionName = rec.ListenerName
			byHost[norm] = &rec
		}
	}

	out := make([]HostRecord, 0, len(byHost))
	for _, rec := range byHost {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	linkRelatedHosts(out)
	return out, nil
}

func (c Classifier) resolveOwnership(host, kind string) string {
	if c.HostInOwn(host) {
		return OwnershipGatewayOwned
	}
	if c.HostInRetain(host) {
		return OwnershipIngressRetained
	}
	if c.Mode == "convert" {
		return OwnershipGatewayOwned
	}
	if kind == IngressKindHTTPPlain || kind == IngressKindHTTPSRedirectOnly || kind == IngressKindHTTPSTerminate || kind == IngressKindHTTPSPassthrough {
		return OwnershipIngressRetained
	}
	return OwnershipIngressRetained
}

func (c Classifier) HostInOwn(host string) bool {
	h := NormalizeHostname(host)
	for _, o := range c.OwnHosts {
		if NormalizeHostname(o) == h {
			return true
		}
	}
	return false
}

func (c Classifier) HostInRetain(host string) bool {
	h := NormalizeHostname(host)
	for _, r := range c.RetainHosts {
		if NormalizeHostname(r) == h {
			return true
		}
	}
	return false
}

func classifyHost(ing networkingv1.Ingress, host, resourceKind string) HostRecord {
	rec := HostRecord{
		Hostname:         host,
		IngressKind:      perHostKind(ing, host, resourceKind),
		BackendProtocol:  strings.ToUpper(strings.TrimSpace(ing.Annotations[backendProtocolAnnot])),
		IngressName:      ing.Name,
		IngressNamespace: ing.Namespace,
	}
	if rec.BackendProtocol == "" {
		rec.BackendProtocol = "HTTP"
	}

	hasTLS := ingressHostHasTLS(ing, host)
	passthrough := annotationTrue(ing.Annotations[sslPassthroughAnnotation])
	redirectExplicit := annotationTrue(ing.Annotations[sslRedirectAnnotation])
	redirectOff := annotationFalse(ing.Annotations[sslRedirectAnnotation])

	switch {
	case passthrough:
		rec.Scheme = SchemeHTTPS
		rec.TLSTerminateAt = TLSTerminateNginx
		rec.IngressKind = IngressKindHTTPSPassthrough
	case hasTLS:
		rec.Scheme = SchemeHTTPS
		rec.TLSTerminateAt = TLSTerminateGateway
		rec.IngressKind = IngressKindHTTPSTerminate
	case redirectExplicit && !redirectOff:
		rec.Scheme = SchemeHTTPS
		rec.TLSTerminateAt = TLSTerminateNone
		rec.IngressKind = IngressKindHTTPSRedirectOnly
	default:
		rec.Scheme = SchemeHTTPOnly
		rec.TLSTerminateAt = TLSTerminateNone
		rec.IngressKind = IngressKindHTTPPlain
	}

	if kind, name, ok := issuerRef(ing); ok {
		rec.ACME = ACMEInfo{HasIssuer: true, IssuerKind: kind, IssuerName: name}
	}
	return rec
}

func perHostKind(ing networkingv1.Ingress, host, resourceKind string) string {
	if resourceKind == IngressKindMixedMultiHost {
		if ingressHostHasTLS(ing, host) || annotationTrue(ing.Annotations[sslPassthroughAnnotation]) {
			if annotationTrue(ing.Annotations[sslPassthroughAnnotation]) {
				return IngressKindHTTPSPassthrough
			}
			return IngressKindHTTPSTerminate
		}
		if !annotationFalse(ing.Annotations[sslRedirectAnnotation]) {
			return IngressKindHTTPSRedirectOnly
		}
		return IngressKindHTTPPlain
	}
	return resourceKind
}

func ingressResourceKind(ing networkingv1.Ingress) string {
	kinds := map[string]struct{}{}
	for _, rule := range ing.Spec.Rules {
		host := ""
		if rule.Host != "" {
			host = NormalizeHostname(rule.Host)
		}
		if host == "" {
			continue
		}
		if annotationTrue(ing.Annotations[sslPassthroughAnnotation]) {
			kinds[IngressKindHTTPSPassthrough] = struct{}{}
			continue
		}
		if ingressHostHasTLS(ing, host) {
			kinds[IngressKindHTTPSTerminate] = struct{}{}
			continue
		}
		if !annotationFalse(ing.Annotations[sslRedirectAnnotation]) {
			kinds[IngressKindHTTPSRedirectOnly] = struct{}{}
			continue
		}
		kinds[IngressKindHTTPPlain] = struct{}{}
	}
	if len(kinds) > 1 {
		return IngressKindMixedMultiHost
	}
	for k := range kinds {
		return k
	}
	return IngressKindHTTPPlain
}

func hostsForIngress(ing networkingv1.Ingress) []string {
	seen := map[string]struct{}{}
	var hosts []string
	for _, rule := range ing.Spec.Rules {
		if rule.Host == "" {
			continue
		}
		h := NormalizeHostname(rule.Host)
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		hosts = append(hosts, h)
	}
	for _, tls := range ing.Spec.TLS {
		for _, h := range tls.Hosts {
			n := NormalizeHostname(h)
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			hosts = append(hosts, n)
		}
	}
	sort.Strings(hosts)
	return hosts
}

func ingressHostHasTLS(ing networkingv1.Ingress, host string) bool {
	for _, tls := range ing.Spec.TLS {
		if len(tls.Hosts) == 0 {
			return true
		}
		for _, h := range tls.Hosts {
			if NormalizeHostname(h) == host || h == "*" {
				return true
			}
		}
	}
	return false
}

func issuerRef(ing networkingv1.Ingress) (kind, name string, ok bool) {
	if v := strings.TrimSpace(ing.Annotations[clusterIssuerAnnotation]); v != "" {
		return "ClusterIssuer", v, true
	}
	if v := strings.TrimSpace(ing.Annotations[issuerAnnotation]); v != "" {
		return "Issuer", v, true
	}
	return "", "", false
}

func annotationTrue(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "true" || v == "1"
}

func annotationFalse(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "false" || v == "0"
}

func linkRelatedHosts(records []HostRecord) {
	byHost := map[string]int{}
	for i := range records {
		byHost[records[i].Hostname] = i
	}
	for i := range records {
		h := records[i].Hostname
		if strings.HasPrefix(h, "www.") {
			apex := strings.TrimPrefix(h, "www.")
			if _, ok := byHost[apex]; ok {
				records[i].RelatedHostnames = appendUnique(records[i].RelatedHostnames, apex)
				records[byHost[apex]].RelatedHostnames = appendUnique(records[byHost[apex]].RelatedHostnames, h)
			}
		}
	}
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// NormalizeHostname lowercases and strips trailing dot.
func NormalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// ListenerName returns a deterministic DNS-safe listener name for hostname.
func ListenerName(hostname string) string {
	norm := NormalizeHostname(hostname)
	base := sanitizeDNSLabel(strings.ReplaceAll(norm, "*", "wildcard"))
	const maxLen = 63
	if len(base) <= maxLen {
		return ensureUnique(base, norm)
	}
	hash := shortHash(norm)
	trim := maxLen - len(hash) - 1
	if trim < 1 {
		trim = 1
	}
	return ensureUnique(base[:trim]+"-"+hash, norm)
}

var usedNames = map[string]string{}

func ensureUnique(name, hostname string) string {
	if prev, ok := usedNames[name]; ok && prev != hostname {
		name = name + "-" + shortHash(hostname)[:6]
	}
	usedNames[name] = hostname
	return name
}

// ResetListenerNameCache clears collision tracking (for tests).
func ResetListenerNameCache() {
	usedNames = map[string]string{}
}

func sanitizeDNSLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-':
			b.WriteByte('-')
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		out = "host"
	}
	return out
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// HostnamesIntersect reports whether two hostnames conflict per Gateway API semantics.
func HostnamesIntersect(a, b string) bool {
	a = NormalizeHostname(a)
	b = NormalizeHostname(b)
	if a == b {
		return true
	}
	if strings.HasPrefix(a, "*.") {
		suffix := strings.TrimPrefix(a, "*")
		return strings.HasSuffix(b, suffix) && b != suffix[1:]
	}
	if strings.HasPrefix(b, "*.") {
		suffix := strings.TrimPrefix(b, "*")
		return strings.HasSuffix(a, suffix) && a != suffix[1:]
	}
	return false
}
