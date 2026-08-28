package useragent

import "testing"

func TestContainsProduct(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, value, product string
		want                 bool
	}{
		{"at start", "Googlebot/2.1", "Googlebot/", true},
		{"compatible product", "Mozilla/5.0 (compatible; Googlebot/2.1)", "Googlebot/", true},
		{"space separated", "Mozilla/5.0 ChatGPT-User/1.0", "ChatGPT-User/", true},
		{"embedded substring", "NotGooglebot/2.1", "Googlebot/", false},
		{"wrong case", "googlebot/2.1", "Googlebot/", false},
		{"absent", "Mozilla/5.0", "Googlebot/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ContainsProduct(tc.value, tc.product); got != tc.want {
				t.Fatalf("ContainsProduct(%q, %q) = %v, want %v", tc.value, tc.product, got, tc.want)
			}
		})
	}
}
