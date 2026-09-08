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

package manifest

import (
	"bytes"
	"fmt"
	"io"
	"os"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// LoadFromFiles reads multi-doc YAML manifests from paths.
func LoadFromFiles(paths []string) ([]runtime.Object, error) {
	var all []runtime.Object
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		objs, err := ParseDocuments(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, objs...)
	}
	return all, nil
}

// ParseDocuments decodes multi-document YAML/JSON.
func ParseDocuments(r io.Reader) ([]runtime.Object, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(r, 4096)
	var out []runtime.Object
	for {
		raw := runtime.RawExtension{}
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(raw.Raw) == 0 {
			continue
		}
		obj, err := decodeObject(raw.Raw)
		if err != nil {
			return nil, err
		}
		out = append(out, obj)
	}
	return out, nil
}

func decodeObject(raw []byte) (runtime.Object, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	u := unstructured.Unstructured{}
	if err := decoder.Decode(&u); err != nil {
		return nil, err
	}
	switch u.GetKind() {
	case "Ingress":
		ing := networkingv1.Ingress{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &ing); err != nil {
			return nil, err
		}
		return &ing, nil
	case "Gateway":
		gw := gatewayv1.Gateway{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &gw); err != nil {
			return nil, err
		}
		return &gw, nil
	default:
		return &u, nil
	}
}

// Ingresses extracts networking.k8s.io Ingress objects.
func Ingresses(objects []runtime.Object) []networkingv1.Ingress {
	var out []networkingv1.Ingress
	for _, obj := range objects {
		switch v := obj.(type) {
		case *networkingv1.Ingress:
			out = append(out, *v)
		}
	}
	return out
}

// Gateways extracts Gateway API Gateway objects.
func Gateways(objects []runtime.Object) []gatewayv1.Gateway {
	var out []gatewayv1.Gateway
	for _, obj := range objects {
		switch v := obj.(type) {
		case *gatewayv1.Gateway:
			out = append(out, *v)
		}
	}
	return out
}

// UnstructuredByKind returns unstructured objects matching kind.
func UnstructuredByKind(objects []runtime.Object, kind string) []unstructured.Unstructured {
	var out []unstructured.Unstructured
	for _, obj := range objects {
		u, ok := obj.(*unstructured.Unstructured)
		if !ok {
			continue
		}
		if u.GetKind() == kind {
			out = append(out, *u)
		}
	}
	return out
}

// Reader returns a multi-doc reader for i2gw.
func Reader(paths []string) (io.Reader, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("input file required")
	}
	var buf bytes.Buffer
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		buf.Write(data)
		if i < len(paths)-1 {
			buf.WriteString("\n---\n")
		}
	}
	return &buf, nil
}

// ObjectMeta is a helper for tests.
func ObjectMeta(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name}
}
