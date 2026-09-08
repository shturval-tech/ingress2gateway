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

package emitout

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubernetes-sigs/ingress2gateway/pkg/i2gw"
	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/preflight"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const (
	ExitOK         = 0
	ExitInputError = 1
	ExitBlockers   = 2
)

// Bundle is a split emission result.
type Bundle struct {
	Infra []runtime.Object
	App   []runtime.Object
}

// Writer persists manifests and reports.
type Writer struct {
	OutputDir     string
	Force         bool
	SplitInfraApp bool
	Report        preflight.Report
	ReportFormat  string
}

// WriteSplit writes infra/ and app/ directories plus report files.
func (w Writer) WriteSplit(bundle Bundle) error {
	if w.OutputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(w.OutputDir, 0o755); err != nil {
		return err
	}
	if w.SplitInfraApp {
		if err := w.writeObjects(filepath.Join(w.OutputDir, "infra"), bundle.Infra); err != nil {
			return err
		}
		if err := w.writeObjects(filepath.Join(w.OutputDir, "app"), bundle.App); err != nil {
			return err
		}
	} else {
		all := append(append([]runtime.Object{}, bundle.Infra...), bundle.App...)
		if err := w.writeObjects(w.OutputDir, all); err != nil {
			return err
		}
	}
	return w.writeReport()
}

func (w Writer) writeReport() error {
	if w.ReportFormat == "json" {
		data, err := w.Report.RenderJSON()
		if err != nil {
			return err
		}
		return writeFile(filepath.Join(w.OutputDir, "report.json"), data, w.Force)
	}
	return writeFile(filepath.Join(w.OutputDir, "report.md"), []byte(w.Report.RenderMarkdown()), w.Force)
}

func (w Writer) writeObjects(dir string, objects []runtime.Object) error {
	if len(objects) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	grouped := groupObjects(objects)
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, err := encodeMultiYAML(grouped[name])
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(dir, name), data, w.Force); err != nil {
			return err
		}
	}
	return nil
}

func groupObjects(objects []runtime.Object) map[string][]runtime.Object {
	out := map[string][]runtime.Object{}
	for _, obj := range objects {
		kind := kindOf(obj)
		file := fileNameForKind(kind)
		out[file] = append(out[file], obj)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool {
			return objectKey(out[k][i]) < objectKey(out[k][j])
		})
	}
	return out
}

func kindOf(obj runtime.Object) string {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.GetKind()
	}
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind != "" {
		return gvk.Kind
	}
	switch obj.(type) {
	case *gatewayv1.Gateway:
		return "Gateway"
	case *gatewayv1.HTTPRoute:
		return "HTTPRoute"
	case *gatewayv1.TLSRoute:
		return "TLSRoute"
	case *gatewayv1beta1.ReferenceGrant:
		return "ReferenceGrant"
	case *gatewayv1.BackendTLSPolicy:
		return "BackendTLSPolicy"
	default:
		return "Resource"
	}
}

func fileNameForKind(kind string) string {
	switch kind {
	case "Gateway":
		return "gateway.yaml"
	case "HTTPRoute":
		return "httproutes.yaml"
	case "TLSRoute":
		return "tlsroutes.yaml"
	case "ReferenceGrant":
		return "referencegrants.yaml"
	case "BackendTLSPolicy":
		return "backend-tls.yaml"
	case "Certificate":
		return "certificates.yaml"
	default:
		return "resources.yaml"
	}
}

func objectKey(obj runtime.Object) string {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.GetNamespace() + "/" + u.GetName()
	}
	if m, ok := obj.(metav1.Object); ok {
		return m.GetNamespace() + "/" + m.GetName()
	}
	return fmt.Sprintf("%p", obj)
}

func encodeMultiYAML(objects []runtime.Object) ([]byte, error) {
	s := json.NewYAMLSerializer(json.DefaultMetaFactory, nil, nil)
	var buf bytes.Buffer
	for i, obj := range objects {
		if i > 0 {
			buf.WriteString("---\n")
		}
		if err := s.Encode(obj, &buf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func writeFile(path string, data []byte, force bool) error {
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("file %q exists (use --force to overwrite)", path)
	}
	return os.WriteFile(path, data, 0o644)
}

// SplitResources partitions gateway resources into infra and app buckets.
func SplitResources(resources i2gw.GatewayResources, certs []unstructured.Unstructured) Bundle {
	b := Bundle{}
	for _, key := range sortedNNKeys(resources.Gateways) {
		gw := resources.Gateways[key]
		copied := gw.DeepCopy()
		b.Infra = append(b.Infra, copied)
	}
	for _, key := range sortedNNKeys(resources.ReferenceGrants) {
		rg := resources.ReferenceGrants[key]
		b.Infra = append(b.Infra, rg.DeepCopy())
	}
	for _, key := range sortedNNKeys(resources.BackendTLSPolicies) {
		p := resources.BackendTLSPolicies[key]
		b.Infra = append(b.Infra, p.DeepCopy())
	}
	for _, key := range sortedNNKeys(resources.HTTPRoutes) {
		route := resources.HTTPRoutes[key]
		copied := route.DeepCopy()
		if isRetainedName(route.Name) {
			b.Infra = append(b.Infra, copied)
			continue
		}
		b.App = append(b.App, copied)
	}
	for _, key := range sortedNNKeys(resources.TLSRoutes) {
		route := resources.TLSRoutes[key]
		copied := route.DeepCopy()
		if isRetainedName(route.Name) {
			b.Infra = append(b.Infra, copied)
			continue
		}
		b.App = append(b.App, copied)
	}
	for i := range certs {
		c := certs[i]
		b.App = append(b.App, c.DeepCopy())
	}
	return b
}

func isRetainedName(name string) bool {
	return strings.HasPrefix(name, "retained-")
}

func sortedNNKeys[T any](m map[types.NamespacedName]T) []types.NamespacedName {
	keys := make([]types.NamespacedName, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Namespace != keys[j].Namespace {
			return keys[i].Namespace < keys[j].Namespace
		}
		return keys[i].Name < keys[j].Name
	})
	return keys
}

// RenderYAML returns deterministic YAML for objects (tests/golden).
func RenderYAML(objects []runtime.Object) (string, error) {
	data, err := encodeMultiYAML(objects)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
