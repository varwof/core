// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package i18n

import (
	"encoding/json"
	"html/template"
	"os"
	"strings"
	"testing"
)

func TestNewBundle(t *testing.T) {
	b := NewBundle()
	if b == nil {
		t.Fatal("NewBundle() returned nil")
	}
	if len(b.data) != 2 {
		t.Fatalf("expected 2 languages, got %d", len(b.data))
	}
}

func TestBundle_KeyConsistency(t *testing.T) {
	enKeys := readKeys("en")
	zhKeys := readKeys("zh")

	missing := make([]string, 0)
	for _, k := range enKeys {
		if !contains(zhKeys, k) {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		t.Errorf("zh.json missing %d keys from en.json:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}

	extra := make([]string, 0)
	for _, k := range zhKeys {
		if !contains(enKeys, k) {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		t.Errorf("zh.json has %d extra keys not in en.json:\n  %s",
			len(extra), strings.Join(extra, "\n  "))
	}
}

func readKeys(lang string) []string {
	raw, err := os.ReadFile("locales/" + lang + ".json")
	if err != nil {
		panic(err)
	}
	var nested map[string]any
	if err := json.Unmarshal(raw, &nested); err != nil {
		panic(err)
	}
	keys := make([]string, 0)
	flattenKeys(nested, "", &keys)
	return keys
}

func flattenKeys(v map[string]any, prefix string, out *[]string) {
	for k, val := range v {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch vv := val.(type) {
		case map[string]any:
			flattenKeys(vv, key, out)
		case string:
			*out = append(*out, key)
		}
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func TestBundle_T(t *testing.T) {
	b := NewBundle()

	t.Run("basic lookup", func(t *testing.T) {
		got := b.T("en", "cli.usage_title")
		if got == "" || got == "cli.usage_title" {
			t.Errorf("unexpected result: %q", got)
		}
	})

	t.Run("chinese lookup", func(t *testing.T) {
		got := b.T("zh", "cli.usage_title")
		if got == "" || got == "cli.usage_title" {
			t.Errorf("unexpected result: %q", got)
		}
	})

	t.Run("formatting with one arg", func(t *testing.T) {
		got := b.T("en", "cli.err_ca_not_found", "test-ca")
		want := "CA \"test-ca\" not found in config"
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("formatting with two args", func(t *testing.T) {
		got := b.T("en", "cli.created_ca", "MyCA", "ABC123", "ecdsa-p256")
		if !strings.Contains(got, "MyCA") || !strings.Contains(got, "ABC123") || !strings.Contains(got, "ecdsa-p256") {
			t.Errorf("all format args should appear in result, got %q", got)
		}
	})

	t.Run("missing key returns key", func(t *testing.T) {
		got := b.T("en", "nonexistent.key")
		if got != "nonexistent.key" {
			t.Errorf("expected key passthrough, got %q", got)
		}
	})

	t.Run("missing lang falls back to en", func(t *testing.T) {
		got := b.T("fr", "cli.usage_title")
		if got == "" || got == "cli.usage_title" {
			t.Errorf("unexpected fallback result: %q", got)
		}
	})

	t.Run("chinese formatting", func(t *testing.T) {
		got := b.T("zh", "cli.created_ca", "MyCA", "ABC123", "ecdsa-p256")
		if got == "" || strings.Contains(got, "cli.") {
			t.Errorf("unexpected result: %q", got)
		}
		if !strings.Contains(got, "MyCA") {
			t.Errorf("expected 'MyCA' in result, got %q", got)
		}
	})
}

func TestBundle_TemplateFuncs(t *testing.T) {
	b := NewBundle()
	funcs := b.TemplateFuncs("en")

	tFn, ok := funcs["t"]
	if !ok {
		t.Fatal("expected 't' function in FuncMap")
	}

	fn, ok := tFn.(func(string, ...any) string)
	if !ok {
		t.Fatal("'t' is not func(string, ...any) string")
	}

	got := fn("cli.usage_title")
	if got == "" || got == "cli.usage_title" {
		t.Errorf("unexpected template func result: %q", got)
	}

	funcsZh := b.TemplateFuncs("zh")
	fnZh := funcsZh["t"].(func(string, ...any) string)
	gotZh := fnZh("cli.usage_title")
	if gotZh == "" || gotZh == "cli.usage_title" {
		t.Errorf("unexpected template func result: %q", gotZh)
	}

	_, tmplErr := template.New("test").Funcs(funcs).Parse("{{t \"cli.usage_title\"}}")
	if tmplErr != nil {
		t.Fatalf("template parse error: %v", tmplErr)
	}
}

func TestDetectLang(t *testing.T) {
	tests := []struct {
		name      string
		cfgLocale string
		accept    string
		want      string
	}{
		{"empty defaults to en", "", "", "en"},
		{"explicit zh", "zh", "", "zh"},
		{"zh-CN normalised", "zh-CN", "", "zh"},
		{"zh_CN normalised", "zh_CN", "", "zh"},
		{"explicit en", "en", "", "en"},
		{"en-US normalised", "en-US", "", "en"},
		{"en_US normalised", "en_US", "", "en"},
		{"accept zh", "", "zh-CN,en;q=0.9", "zh"},
		{"accept en", "", "en-US,en;q=0.9", "en"},
		{"accept zh with quality", "", "zh;q=0.8,en;q=0.9", "zh"},
		{"cfg overrides accept", "zh", "en-US,en;q=0.9", "zh"},
		{"accept lowercase zh", "", "zh,en;q=0.9", "zh"},
		{"accept fr falls back to en", "", "fr-FR,fr;q=0.9", "en"},
		{"config en overrides accept zh", "en", "zh-CN,en;q=0.9", "en"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectLang(tt.cfgLocale, tt.accept)
			if got != tt.want {
				t.Errorf("DetectLang(%q, %q) = %q, want %q",
					tt.cfgLocale, tt.accept, got, tt.want)
			}
		})
	}
}

func BenchmarkBundle_T(b *testing.B) {
	bundle := NewBundle()
	b.ResetTimer()
	for b.Loop() {
		_ = bundle.T("en", "cli.usage_title")
	}
}

func BenchmarkBundle_T_Format(b *testing.B) {
	bundle := NewBundle()
	b.ResetTimer()
	for b.Loop() {
		_ = bundle.T("en", "cli.err_ca_not_found", "test-ca")
	}
}

func TestBundle_Ef(t *testing.T) {
	b := NewBundle()
	err := b.Ef("en", "nonexistent.key")
	if err == nil {
		t.Fatal("Ef should return an error")
	}
	if !strings.Contains(err.Error(), "nonexistent.key") {
		t.Errorf("error should contain key name, got: %v", err)
	}
}

func TestBundle_Locale(t *testing.T) {
	b := NewBundle()

	t.Run("known lang", func(t *testing.T) {
		loc := b.Locale("en")
		if loc == nil {
			t.Fatal("Locale en returned nil")
		}
		if len(loc) == 0 {
			t.Error("Locale en returned empty map")
		}
	})

	t.Run("unknown lang falls back to en", func(t *testing.T) {
		loc := b.Locale("fr")
		if loc == nil {
			t.Fatal("Locale fr returned nil")
		}
		if len(loc) == 0 {
			t.Error("Locale fr returned empty map")
		}
	})

	t.Run("zh locale", func(t *testing.T) {
		loc := b.Locale("zh")
		if loc == nil {
			t.Fatal("Locale zh returned nil")
		}
		if len(loc) == 0 {
			t.Error("Locale zh returned empty map")
		}
	})
}

func TestFlattenJSON_InvalidJSON(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSON([]byte("not json"), "", flat)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestFlattenJSON_UnsupportedType(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSON([]byte(`{"key": 123}`), "", flat)
	if err == nil {
		t.Error("expected error for unsupported type (int)")
	}
}

func TestFlattenJSON_Nested(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSON([]byte(`{"a": {"b": "c"}}`), "", flat)
	if err != nil {
		t.Fatal(err)
	}
	if flat["a.b"] != "c" {
		t.Errorf("expected a.b = c, got %q", flat["a.b"])
	}
}

func TestFlattenJSON_Prefix(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSON([]byte(`{"a": "b"}`), "pre", flat)
	if err != nil {
		t.Fatal(err)
	}
	if flat["pre.a"] != "b" {
		t.Errorf("expected pre.a = b, got %q", flat["pre.a"])
	}
}

func TestFlattenJSONValue_InvalidType(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSONValue(map[string]any{"k": 42}, "pre", flat)
	if err == nil {
		t.Error("expected error for unsupported type in nested")
	}
}

func TestFlattenJSONValue_DeepNested(t *testing.T) {
	flat := make(map[string]string)
	err := flattenJSONValue(map[string]any{
		"l1": map[string]any{"l2": "val"},
	}, "root", flat)
	if err != nil {
		t.Fatal(err)
	}
	if flat["root.l1.l2"] != "val" {
		t.Errorf("expected root.l1.l2 = val, got %q", flat["root.l1.l2"])
	}
}
