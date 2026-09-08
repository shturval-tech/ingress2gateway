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

package preflight

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/classify"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/config"
	networkingv1 "k8s.io/api/networking/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// Severity constants for report entries.
const (
	SeverityBlocker = "blocker"
	SeverityWarning = "warning"
	SeveritySkipped = "skipped"
)

// Entry is one preflight finding.
type Entry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Host     string `json:"host,omitempty"`
}

// Report aggregates preflight results.
type Report struct {
	Blockers []Entry `json:"blockers"`
	Warnings []Entry `json:"warnings"`
	Skipped  []Entry `json:"skipped"`
	Hosts    []classify.HostRecord `json:"hosts,omitempty"`
}

// HasBlockers returns true when migration must stop.
func (r Report) HasBlockers() bool {
	return len(r.Blockers) > 0
}

// RenderMarkdown formats report for operators.
func (r Report) RenderMarkdown() string {
	var b strings.Builder
	b.WriteString("# Preflight report\n\n")
	writeSection := func(title string, items []Entry) {
		b.WriteString("## ")
		b.WriteString(title)
		b.WriteString("\n\n")
		if len(items) == 0 {
			b.WriteString("_none_\n\n")
			return
		}
		for _, e := range items {
			fmt.Fprintf(&b, "- **%s** [%s]: %s\n", e.ID, e.Severity, e.Message)
		}
		b.WriteString("\n")
	}
	writeSection("Blockers", r.Blockers)
	writeSection("Warnings", r.Warnings)
	writeSection("Skipped", r.Skipped)
	return b.String()
}

// RenderJSON returns machine-readable report.
func (r Report) RenderJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// CRDChecker discovers installed API resources.
type CRDChecker interface {
	HasGatewayAPI() bool
	HasTLSRouteV1() bool
	HasBackendTLSPolicyV1() bool
	HasCertManager() bool
	CertManagerReady() bool
}

// ClusterReader loads cluster objects for preflight.
type ClusterReader interface {
	ListIngresses() ([]networkingv1.Ingress, error)
	ListGateways() ([]gatewayv1.Gateway, error)
	GetIssuer(name, kind string) (map[string]any, bool)
	GetService(namespace, name string) (map[string]any, bool)
	GetUnstructured(gvk, namespace, name string) (map[string]any, bool)
	HasCRD(group, version, resource string) bool
}

// Runner executes preflight checks.
type Runner struct {
	Config   config.Config
	CRDs     CRDChecker
	Cluster  ClusterReader
	Ingresses []networkingv1.Ingress
	Gateways  []gatewayv1.Gateway
}

// Run executes all configured checks.
func (r Runner) Run() (Report, error) {
	report := Report{}
	classifier := classify.Classifier{
		Mode:        r.Config.Mode,
		OwnHosts:    r.Config.OwnHosts,
		RetainHosts: r.Config.RetainHosts,
	}

	ingresses := r.Ingresses
	if len(ingresses) == 0 && r.Cluster != nil {
		var err error
		ingresses, err = r.Cluster.ListIngresses()
		if err != nil {
			return report, err
		}
	}
	if len(ingresses) == 0 {
		report.Warnings = append(report.Warnings, Entry{ID: "I0", Severity: SeverityWarning, Message: "no ingress resources found"})
		return report, nil
	}

	hosts, err := classifier.ClassifyIngresses(ingresses)
	if err != nil {
		report.Blockers = append(report.Blockers, Entry{ID: "I1", Severity: SeverityBlocker, Message: err.Error()})
		return report, nil
	}
	report.Hosts = hosts

	gateways := r.Gateways
	if len(gateways) == 0 && r.Cluster != nil {
		var err error
		gateways, err = r.Cluster.ListGateways()
		if err != nil {
			return report, err
		}
	}

	r.checkGatewayAPI(&report, hosts)
	r.checkProtocolConflict(&report, hosts, gateways)
	r.checkCertManager(&report, ingresses, hosts)
	if r.Config.Mode == config.ModeCoexist {
		r.checkNginxBackend(&report)
	}
	r.checkScale(&report, hosts)
	if r.Config.CheckShturvalCRDs {
		r.checkShturvalCRDs(&report)
	}

	sortEntries(&report)
	return report, nil
}

func (r Runner) checkGatewayAPI(report *Report, hosts []classify.HostRecord) {
	if r.CRDs == nil {
		return
	}
	if !r.CRDs.HasGatewayAPI() {
		report.Blockers = append(report.Blockers, Entry{ID: "G1", Severity: SeverityBlocker, Message: "Gateway API CRDs not installed"})
	}
	needsPassthrough := r.needsPassthrough(hosts)
	if needsPassthrough && !r.CRDs.HasTLSRouteV1() {
		report.Blockers = append(report.Blockers, Entry{ID: "G2", Severity: SeverityBlocker, Message: "TLSRoute CRD v1 required for passthrough coexist"})
	}
	if r.Config.CoexistHTTPS == config.CoexistHTTPSReencrypt && !r.CRDs.HasBackendTLSPolicyV1() {
		report.Blockers = append(report.Blockers, Entry{ID: "G3", Severity: SeverityBlocker, Message: "BackendTLSPolicy CRD v1 required for reencrypt coexist"})
	}
}

func (r Runner) needsPassthrough(hosts []classify.HostRecord) bool {
	for _, h := range hosts {
		if r.Config.Mode == config.ModeCoexist && h.Ownership == classify.OwnershipIngressRetained {
			switch h.IngressKind {
			case classify.IngressKindHTTPSTerminate, classify.IngressKindHTTPSPassthrough:
				return true
			}
		}
	}
	return false
}

func (r Runner) checkProtocolConflict(report *Report, hosts []classify.HostRecord, gateways []gatewayv1.Gateway) {
	existingHTTPS := map[string]struct{}{}
	for _, gw := range gateways {
		for _, l := range gw.Spec.Listeners {
			if l.Protocol != gatewayv1.HTTPSProtocolType || l.Hostname == nil {
				continue
			}
			existingHTTPS[string(*l.Hostname)] = struct{}{}
		}
	}
	for _, h := range hosts {
		if r.Config.Mode != config.ModeCoexist || h.Ownership != classify.OwnershipIngressRetained {
			continue
		}
		if h.IngressKind != classify.IngressKindHTTPSTerminate && h.IngressKind != classify.IngressKindHTTPSPassthrough {
			continue
		}
		for existing := range existingHTTPS {
			if classify.HostnamesIntersect(h.Hostname, existing) {
				report.Blockers = append(report.Blockers, Entry{
					ID:       "X5",
					Severity: SeverityBlocker,
					Host:     h.Hostname,
					Message:  fmt.Sprintf("passthrough hostname %q intersects existing HTTPS Terminate listener %q (ProtocolConflict)", h.Hostname, existing),
				})
			}
		}
	}
}

func (r Runner) checkCertManager(report *Report, ingresses []networkingv1.Ingress, hosts []classify.HostRecord) {
	needsTLS := false
	for _, h := range hosts {
		if h.IngressKind == classify.IngressKindHTTPPlain {
			continue
		}
		if h.Scheme == classify.SchemeHTTPS || h.ACME.HasIssuer {
			needsTLS = true
		}
		if r.Config.EmitCertificates && h.IngressKind != classify.IngressKindHTTPPlain {
			needsTLS = true
		}
	}
	for _, ing := range ingresses {
		if _, _, ok := issuerFromIngress(ing); ok {
			needsTLS = true
		}
	}
	if !needsTLS {
		report.Skipped = append(report.Skipped, Entry{ID: "CM0", Severity: SeveritySkipped, Message: "cert-manager checks skipped (http-plain only)"})
		return
	}
	if r.CRDs == nil || !r.CRDs.HasCertManager() {
		report.Blockers = append(report.Blockers, Entry{ID: "CM1", Severity: SeverityBlocker, Message: "cert-manager CRDs not installed"})
		return
	}
	if !r.CRDs.CertManagerReady() {
		msg := Entry{ID: "CM2", Severity: SeverityWarning, Message: "cert-manager controller not ready"}
		if r.Config.StrictPreflight {
			msg.Severity = SeverityBlocker
		}
		appendFinding(report, msg)
	}

	for _, ing := range ingresses {
		r.checkIngressIssuer(report, ing)
	}
	for _, h := range hosts {
		if h.IngressKind == classify.IngressKindHTTPPlain {
			continue
		}
		if h.ACME.HasIssuer {
			r.checkEffectiveSolver(report, h)
		}
	}
}

func appendFinding(report *Report, e Entry) {
	switch e.Severity {
	case SeverityBlocker:
		report.Blockers = append(report.Blockers, e)
	case SeverityWarning:
		report.Warnings = append(report.Warnings, e)
	default:
		report.Skipped = append(report.Skipped, e)
	}
}

func issuerFromIngress(ing networkingv1.Ingress) (kind, name string, ok bool) {
	if ci := strings.TrimSpace(ing.Annotations["cert-manager.io/cluster-issuer"]); ci != "" {
		return "ClusterIssuer", ci, true
	}
	if is := strings.TrimSpace(ing.Annotations["cert-manager.io/issuer"]); is != "" {
		return "Issuer", is, true
	}
	return "", "", false
}

func (r Runner) checkIngressIssuer(report *Report, ing networkingv1.Ingress) {
	kind, name, ok := issuerFromIngress(ing)
	if !ok {
		return
	}
	if r.Cluster == nil {
		return
	}
	obj, ok := r.Cluster.GetIssuer(name, kind)
	if !ok {
		report.Blockers = append(report.Blockers, Entry{ID: "CM3", Severity: SeverityBlocker, Message: fmt.Sprintf("%s %q not found", kind, name)})
		return
	}
	if !issuerReady(obj) {
		msg := Entry{ID: "CM4", Severity: SeverityWarning, Message: fmt.Sprintf("%s %q not Ready", kind, name)}
		if r.Config.StrictPreflight && hasReadyCondition(obj) {
			msg.Severity = SeverityBlocker
		} else if !hasReadyCondition(obj) {
			// Offline fixtures often omit status; do not block convert.
			msg.Severity = SeverityWarning
			msg.Message = fmt.Sprintf("%s %q has no Ready condition (verify in cluster)", kind, name)
		}
		appendFinding(report, msg)
	}
	r.evaluateACMESolvers(report, obj, ing.Namespace)
}

func (r Runner) checkEffectiveSolver(report *Report, h classify.HostRecord) {
	if r.Cluster == nil {
		return
	}
	obj, ok := r.Cluster.GetIssuer(h.ACME.IssuerName, h.ACME.IssuerKind)
	if !ok {
		return
	}
	r.evaluateACMESolversForHost(report, obj, h.Hostname)
}

func (r Runner) evaluateACMESolvers(report *Report, issuer map[string]any, ingressNS string) {
	acme, _ := issuer["spec"].(map[string]any)
	if acme == nil {
		return
	}
	acmeSpec, _ := acme["acme"].(map[string]any)
	if acmeSpec == nil {
		return
	}
	solvers, _ := acmeSpec["solvers"].([]any)
	for _, s := range solvers {
		solver, _ := s.(map[string]any)
		if solver == nil {
			continue
		}
		if http, ok := solver["http01"].(map[string]any); ok {
			if ing, ok := http["ingress"].(map[string]any); ok {
				r.checkIngressSolver(report, ing, ingressNS)
			}
			if gwr, ok := http["gatewayHTTPRoute"].(map[string]any); ok {
				r.checkGatewayHTTPSolver(report, gwr)
			}
		}
	}
}

func (r Runner) evaluateACMESolversForHost(report *Report, issuer map[string]any, host string) {
	spec, _ := issuer["spec"].(map[string]any)
	if spec == nil {
		return
	}
	acme, _ := spec["acme"].(map[string]any)
	if acme == nil {
		return
	}
	solvers, _ := acme["solvers"].([]any)
	effective := effectiveSolver(solvers, host)
	switch effective {
	case "gatewayHTTPRoute":
		report.Skipped = append(report.Skipped, Entry{ID: "P2", Severity: SeveritySkipped, Host: host, Message: "effective ACME solver is gatewayHTTPRoute"})
	case "ingress-no-path":
		report.Blockers = append(report.Blockers, Entry{ID: "P1", Severity: SeverityBlocker, Host: host, Message: "ACME Ingress solver without path to nginx under Gateway front"})
	case "ingress-with-path":
		report.Warnings = append(report.Warnings, Entry{ID: "P1b", Severity: SeverityWarning, Host: host, Message: "ACME Ingress solver with HTTP route to nginx (verify challenge routing)"})
	case "bad-effective":
		report.Blockers = append(report.Blockers, Entry{ID: "P2b", Severity: SeverityBlocker, Host: host, Message: "effective ACME solver incompatible with hostname selectors"})
	}
}

func effectiveSolver(solvers []any, host string) string {
	if len(solvers) == 0 {
		return "bad-effective"
	}
	for _, s := range solvers {
		solver, _ := s.(map[string]any)
		if solver == nil {
			continue
		}
		if !selectorMatches(solver, host) {
			continue
		}
		if _, ok := solver["http01"].(map[string]any); !ok {
			continue
		}
		http01, _ := solver["http01"].(map[string]any)
		if _, ok := http01["gatewayHTTPRoute"]; ok {
			return "gatewayHTTPRoute"
		}
		if ing, ok := http01["ingress"].(map[string]any); ok {
			if v, _ := ing["ingressClassName"].(string); v == "nginx" || v == "" {
				if rHasNginxRoute(ing) {
					return "ingress-with-path"
				}
				return "ingress-no-path"
			}
		}
		return "bad-effective"
	}
	return "bad-effective"
}

func selectorMatches(solver map[string]any, host string) bool {
	sel, ok := solver["selector"].(map[string]any)
	if !ok {
		return true
	}
	dnsNames, _ := sel["dnsNames"].([]any)
	if len(dnsNames) == 0 {
		return true
	}
	for _, n := range dnsNames {
		name, _ := n.(string)
		if classify.HostnamesIntersect(name, host) || name == host {
			return true
		}
	}
	return false
}

func rHasNginxRoute(ing map[string]any) bool {
	if v, ok := ing["name"].(string); ok && v != "" {
		return true
	}
	if v, ok := ing["serviceType"].(string); ok && strings.EqualFold(v, "ClusterIP") {
		return true
	}
	return false
}

func (r Runner) checkIngressSolver(report *Report, ing map[string]any, _ string) {
	class, _ := ing["ingressClassName"].(string)
	if class != "" && class != "nginx" {
		return
	}
	if !rHasNginxRoute(ing) {
		report.Blockers = append(report.Blockers, Entry{ID: "P1", Severity: SeverityBlocker, Message: "ACME Ingress solver without documented path to nginx"})
	} else {
		report.Warnings = append(report.Warnings, Entry{ID: "P1b", Severity: SeverityWarning, Message: "ACME Ingress solver relies on HTTP path to nginx"})
	}
}

func (r Runner) checkGatewayHTTPSolver(report *Report, gwr map[string]any) {
	parents, _ := gwr["parentRefs"].([]any)
	if len(parents) == 0 {
		report.Blockers = append(report.Blockers, Entry{ID: "P2b", Severity: SeverityBlocker, Message: "gatewayHTTPRoute solver missing parentRefs"})
		return
	}
	report.Skipped = append(report.Skipped, Entry{ID: "P2", Severity: SeveritySkipped, Message: "gatewayHTTPRoute solver configured"})
}

func issuerReady(obj map[string]any) bool {
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		return false
	}
	conds, _ := status["conditions"].([]any)
	for _, c := range conds {
		cond, _ := c.(map[string]any)
		if cond == nil {
			continue
		}
		if cond["type"] == "Ready" && cond["status"] == "True" {
			return true
		}
	}
	return false
}

func hasReadyCondition(obj map[string]any) bool {
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		return false
	}
	conds, _ := status["conditions"].([]any)
	for _, c := range conds {
		cond, _ := c.(map[string]any)
		if cond == nil {
			continue
		}
		if cond["type"] == "Ready" {
			return true
		}
	}
	return false
}

func (r Runner) checkNginxBackend(report *Report) {
	if r.Cluster == nil {
		return
	}
	svc, ok := r.Cluster.GetService(r.Config.NginxNamespace, r.Config.NginxService)
	if !ok {
		report.Blockers = append(report.Blockers, Entry{ID: "N1", Severity: SeverityBlocker, Message: fmt.Sprintf("nginx Service %s/%s not found", r.Config.NginxNamespace, r.Config.NginxService)})
		return
	}
	spec, _ := svc["spec"].(map[string]any)
	ports, _ := spec["ports"].([]any)
	has80, has443 := false, false
	for _, p := range ports {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		switch intFromAny(pm["port"]) {
		case 80:
			has80 = true
		case 443:
			has443 = true
		}
	}
	if !has80 || !has443 {
		report.Blockers = append(report.Blockers, Entry{ID: "N2", Severity: SeverityBlocker, Message: "nginx Service must expose ports 80 and 443"})
	}
	if r.Config.CoexistHTTPS == config.CoexistHTTPSReencrypt && r.Config.NginxDefaultSSLCert == "" {
		report.Blockers = append(report.Blockers, Entry{ID: "N3", Severity: SeverityBlocker, Message: "nginx default SSL certificate required for reencrypt"})
	}
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func (r Runner) checkScale(report *Report, hosts []classify.HostRecord) {
	count := 0
	for _, h := range hosts {
		if r.Config.Mode == config.ModeCoexist && h.Ownership == classify.OwnershipIngressRetained {
			if h.IngressKind == classify.IngressKindHTTPSTerminate || h.IngressKind == classify.IngressKindHTTPSPassthrough {
				count++
			}
		}
	}
	if count > r.Config.MaxPassthroughListeners {
		report.Warnings = append(report.Warnings, Entry{
			ID:       "S1",
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("%d retained https hosts exceed maxPassthroughListeners=%d; consider operator-managed listeners", count, r.Config.MaxPassthroughListeners),
		})
	}
}

func (r Runner) checkShturvalCRDs(report *Report) {
	if r.Cluster == nil {
		return
	}
	gvks := []struct {
		group, version, resource, kind string
	}{
		{"config.shturval.tech", "v1beta1", "clusterconfigs", "ClusterConfig"},
		{"core.shturval.tech", "v1", "shturvalserviceconfigs", "ShturvalServiceConfig"},
	}
	for _, g := range gvks {
		if !r.Cluster.HasCRD(g.group, g.version, g.resource) {
			report.Skipped = append(report.Skipped, Entry{ID: "SC", Severity: SeveritySkipped, Message: fmt.Sprintf("%s CRD not installed (skipped)", g.kind)})
			continue
		}
		report.Warnings = append(report.Warnings, Entry{ID: "SC", Severity: SeverityWarning, Message: fmt.Sprintf("%s present; review legacy ingress cutover annotations manually", g.kind)})
	}
}

func sortEntries(report *Report) {
	sort.Slice(report.Blockers, func(i, j int) bool { return report.Blockers[i].ID < report.Blockers[j].ID })
	sort.Slice(report.Warnings, func(i, j int) bool { return report.Warnings[i].ID < report.Warnings[j].ID })
	sort.Slice(report.Skipped, func(i, j int) bool { return report.Skipped[i].ID < report.Skipped[j].ID })
}
