// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package i18n

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"strings"
)

//go:embed locales
var localeFS embed.FS

type Bundle struct {
	data map[string]map[string]string // lang -> key -> text
}

func NewBundle() *Bundle {
	b := &Bundle{data: make(map[string]map[string]string)}
	for _, lang := range []string{"en", "zh"} {
		raw, err := localeFS.ReadFile("locales/" + lang + ".json")
		if err != nil {
			panic("i18n: missing locale " + lang + ": " + err.Error())
		}
		flat := make(map[string]string)
		if err := flattenJSON(raw, "", flat); err != nil {
			panic("i18n: parse " + lang + ": " + err.Error())
		}
		b.data[lang] = flat
	}
	return b
}

func flattenJSON(raw []byte, prefix string, out map[string]string) error {
	var nested map[string]any
	if err := json.Unmarshal(raw, &nested); err != nil {
		return err
	}
	for k, v := range nested {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			sub := make(map[string]string)
			if err := flattenJSONValue(val, key, sub); err != nil {
				return err
			}
			for sk, sv := range sub {
				out[sk] = sv
			}
		case string:
			out[key] = val
		default:
			return fmt.Errorf("i18n: unexpected type %T for key %s", v, key)
		}
	}
	return nil
}

func flattenJSONValue(v map[string]any, prefix string, out map[string]string) error {
	for k, val := range v {
		key := prefix + "." + k
		switch vv := val.(type) {
		case map[string]any:
			if err := flattenJSONValue(vv, key, out); err != nil {
				return err
			}
		case string:
			out[key] = vv
		default:
			return fmt.Errorf("i18n: unexpected type %T for key %s", val, key)
		}
	}
	return nil
}

func (b *Bundle) Ef(lang, key string, args ...any) error {
	return errors.New(b.T(lang, key, args...))
}

func (b *Bundle) T(lang, key string, args ...any) string {
	m, ok := b.data[lang]
	if !ok {
		m = b.data["en"]
	}
	text, ok := m[key]
	if !ok {
		text = key
	}
	if len(args) > 0 {
		text = fmt.Sprintf(text, args...)
	}
	return text
}

func (b *Bundle) Locale(lang string) map[string]any {
	if _, ok := b.data[lang]; !ok {
		lang = "en"
	}
	raw, err := localeFS.ReadFile("locales/" + lang + ".json")
	if err != nil {
		raw, _ = localeFS.ReadFile("locales/en.json")
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return map[string]any{}
	}
	return result
}

func (b *Bundle) TemplateFuncs(lang string) template.FuncMap {
	return template.FuncMap{
		"t": func(key string, args ...any) string {
			return b.T(lang, key, args...)
		},
	}
}

func DetectLang(cfgLocale, acceptLang string) string {
	if cfgLocale == "zh" || cfgLocale == "zh-CN" || cfgLocale == "zh_CN" {
		return "zh"
	}
	if cfgLocale == "en" || cfgLocale == "en-US" || cfgLocale == "en_US" {
		return "en"
	}
	if acceptLang != "" {
		raw := strings.Split(acceptLang, ",")[0]
		raw = strings.Split(raw, ";")[0]
		raw = strings.TrimSpace(raw)
		if strings.HasPrefix(raw, "zh") {
			return "zh"
		}
		if strings.HasPrefix(raw, "en") {
			return "en"
		}
	}
	return "en"
}
