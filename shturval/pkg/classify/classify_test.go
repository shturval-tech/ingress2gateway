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

package classify_test

import (
	"testing"

	"github.com/kubernetes-sigs/ingress2gateway/shturval/pkg/classify"
)

func TestListenerNameN1(t *testing.T) {
	classify.ResetListenerNameCache()
	cases := []struct {
		host string
	}{
		{host: "App.Example.COM."},
		{host: "*.wildcard.example.com"},
		{host: "this-is-a-very-long-hostname-that-exceeds-sixty-three-characters-for-dns-label.example.com"},
		{host: "collision.example.com"},
		{host: "collision-example-com"},
	}
	names := map[string]string{}
	for _, tc := range cases {
		name := classify.ListenerName(tc.host)
		if name == "" {
			t.Fatalf("empty listener name for %q", tc.host)
		}
		if len(name) > 63 {
			t.Fatalf("listener name too long: %q", name)
		}
		if prev, ok := names[name]; ok && prev != tc.host {
			t.Fatalf("collision without hash: %q used by %q and %q", name, prev, tc.host)
		}
		names[name] = tc.host
		if classify.ListenerName(tc.host) != name {
			t.Fatalf("listener name not deterministic for %q", tc.host)
		}
	}
}

func TestHostnamesIntersect(t *testing.T) {
	if !classify.HostnamesIntersect("*.example.com", "app.example.com") {
		t.Fatal("expected wildcard intersection")
	}
	if classify.HostnamesIntersect("other.com", "app.example.com") {
		t.Fatal("unexpected intersection")
	}
}
