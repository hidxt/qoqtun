package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// LoadServer parses a server.toml file in strict mode: any unknown field
// causes an error (fail-closed, per 05-config-schema.md).
func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config %q: %w", path, err)
	}
	var c ServerConfig
	if err := decodeStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parse server config %q: %w", path, err)
	}
	return &c, nil
}

// LoadClient parses a client.toml file in strict mode.
func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config %q: %w", path, err)
	}
	var c ClientConfig
	if err := decodeStrict(data, &c); err != nil {
		return nil, fmt.Errorf("parse client config %q: %w", path, err)
	}
	return &c, nil
}

// LoadServerOverlays parses a server.toml strictly and returns the fields it
// sets as overlays, so partial files merge onto defaults field-by-field and
// explicit zero values (e.g. enroll_addr = "") are preserved.
func LoadServerOverlays(path string) ([]Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read server config %q: %w", path, err)
	}
	var typed ServerConfig
	if err := decodeStrict(data, &typed); err != nil {
		return nil, fmt.Errorf("parse server config %q: %w", path, err)
	}
	return fileOverlays(data)
}

// LoadClientOverlays is the client analogue of LoadServerOverlays.
func LoadClientOverlays(path string) ([]Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config %q: %w", path, err)
	}
	var typed ClientConfig
	if err := decodeStrict(data, &typed); err != nil {
		return nil, fmt.Errorf("parse client config %q: %w", path, err)
	}
	return fileOverlays(data)
}

// decodeStrict decodes TOML rejecting unknown fields (strict mode).
func decodeStrict(data []byte, v any) error {
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// fileOverlays converts raw TOML data into field-path overlays. Values keep
// their parsed types (string/bool/int64/float64/[]string), so explicit zero
// values survive the merge.
func fileOverlays(data []byte) ([]Overlay, error) {
	var m map[string]any
	if err := decodeStrict(data, &m); err != nil {
		return nil, err
	}
	var out []Overlay
	var walk func(prefix string, m map[string]any) error
	walk = func(prefix string, m map[string]any) error {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			switch v := m[k].(type) {
			case map[string]any:
				if err := walk(path, v); err != nil {
					return err
				}
			case []any:
				// arrays of strings become []string; arrays of tables stay
				// as []any (each element a map[string]any) for struct slices.
				allStrings := true
				for _, e := range v {
					if _, ok := e.(string); !ok {
						allStrings = false
						break
					}
				}
				if allStrings {
					ss := make([]string, len(v))
					for i, e := range v {
						ss[i] = e.(string)
					}
					out = append(out, Overlay{Path: path, Value: ss})
				} else {
					out = append(out, Overlay{Path: path, Value: v})
				}
			default:
				out = append(out, Overlay{Path: path, Value: v})
			}
		}
		return nil
	}
	if err := walk("", m); err != nil {
		return nil, err
	}
	return out, nil
}

// Overlay is a single field override: Path is the dot-separated TOML field
// path (e.g. "listen.control_addr"), Value is a string/bool/int/int64/[]string.
type Overlay struct {
	Path  string
	Value any
}

// ResolveServer merges configuration per precedence CLI > ENV > file > default.
//   - defaults: built-in defaults (DefaultServerConfig)
//   - fileOverlays: fields set by a config file (LoadServerOverlays), may be nil
//   - cliOverlays: CLI flag overrides (highest precedence)
//   - env: environment lookup (nil => os.Getenv); only QOQTUN_* keys mapped
//     from config field paths are considered; array fields are NOT supported
//     via env (per 05-config-schema.md §3).
func ResolveServer(defaults *ServerConfig, fileOverlays, cliOverlays []Overlay, env func(string) string) (*ServerConfig, error) {
	out := *defaults // copy
	if env == nil {
		env = os.Getenv
	}
	all := append([]Overlay{}, fileOverlays...)
	all = append(all, envOverlaysFor(&out, "QOQTUN_", env)...)
	all = append(all, cliOverlays...)
	if err := ApplyOverlays(&out, all); err != nil {
		return nil, err
	}
	if err := ValidateServer(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ResolveClient is the client analogue of ResolveServer.
func ResolveClient(defaults *ClientConfig, fileOverlays, cliOverlays []Overlay, env func(string) string) (*ClientConfig, error) {
	out := *defaults
	if env == nil {
		env = os.Getenv
	}
	all := append([]Overlay{}, fileOverlays...)
	all = append(all, envOverlaysFor(&out, "QOQTUN_", env)...)
	all = append(all, cliOverlays...)
	if err := ApplyOverlays(&out, all); err != nil {
		return nil, err
	}
	if err := ValidateClient(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// envOverlaysFor walks the config struct and maps each leaf field path to an
// environment variable named PREFIX + upper(path with '.' -> '_').
// Array fields are skipped (05-config-schema.md §3: arrays are config-only).
func envOverlaysFor(cfg any, prefix string, getenv func(string) string) []Overlay {
	rv := reflect.ValueOf(cfg)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return nil
	}
	var overlays []Overlay
	walkLeaves(rv.Elem(), "", func(path string, _ reflect.Value) {
		envKey := prefix + strings.ToUpper(strings.ReplaceAll(path, ".", "_"))
		if v := getenv(envKey); v != "" {
			overlays = append(overlays, Overlay{Path: path, Value: v})
		}
	})
	return overlays
}

// walkLeaves visits every leaf field path (dot-separated TOML paths).
func walkLeaves(v reflect.Value, prefix string, fn func(path string, fv reflect.Value)) {
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("toml")
		if tag == "" || tag == "-" {
			continue
		}
		path := tag
		if prefix != "" {
			path = prefix + "." + tag
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.Struct:
			walkLeaves(fv, path, fn)
		case reflect.Slice, reflect.Array:
			// arrays are config-only; skip (no ENV mapping)
			continue
		default:
			fn(path, fv)
		}
	}
}

// ApplyOverlays applies field overrides to cfg by path. Values are converted
// to the target field type (string/bool/int/int64/float64/[]string).
func ApplyOverlays(cfg any, overlays []Overlay) error {
	rv := reflect.ValueOf(cfg)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("cfg must be a non-nil pointer")
	}
	elem := rv.Elem()
	for _, ov := range overlays {
		parts := strings.Split(ov.Path, ".")
		if err := applyOne(elem, parts, ov.Path, ov.Value); err != nil {
			return err
		}
	}
	return nil
}

func applyOne(v reflect.Value, parts []string, fullPath string, value any) error {
	// descend
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return fmt.Errorf("overlay path %q: not a struct at %q", fullPath, parts[0])
	}
	t := v.Type()
	var fv reflect.Value
	found := false
	for i := 0; i < t.NumField(); i++ {
		if t.Field(i).Tag.Get("toml") == parts[0] {
			fv = v.Field(i)
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("overlay path %q: unknown field %q", fullPath, parts[0])
	}
	if len(parts) == 1 {
		return setField(fv, fullPath, value)
	}
	return applyOne(fv, parts[1:], fullPath, value)
}

func setField(fv reflect.Value, path string, value any) error {
	if fv.Kind() == reflect.Ptr {
		if fv.IsNil() {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		fv = fv.Elem()
	}
	switch fv.Kind() {
	case reflect.String:
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("overlay %q: expected string, got %T", path, value)
		}
		fv.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(fmt.Sprint(value))
		if err != nil {
			return fmt.Errorf("overlay %q: invalid bool %v", path, value)
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(fmt.Sprint(value), 10, 64)
		if err != nil {
			return fmt.Errorf("overlay %q: invalid int %v", path, value)
		}
		fv.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(fmt.Sprint(value), 64)
		if err != nil {
			return fmt.Errorf("overlay %q: invalid float %v", path, value)
		}
		fv.SetFloat(f)
	case reflect.Slice:
		switch vv := value.(type) {
		case []string:
			if fv.Type().Elem().Kind() != reflect.String {
				return fmt.Errorf("overlay %q: unsupported slice element type", path)
			}
			out := reflect.MakeSlice(fv.Type(), len(vv), len(vv))
			for i, s := range vv {
				out.Index(i).SetString(s)
			}
			fv.Set(out)
		case []any:
			// array of tables: build struct elements from maps
			elemType := fv.Type().Elem()
			if elemType.Kind() != reflect.Struct {
				return fmt.Errorf("overlay %q: unsupported slice element type", path)
			}
			out := reflect.MakeSlice(fv.Type(), len(vv), len(vv))
			for i, e := range vv {
				m, ok := e.(map[string]any)
				if !ok {
					return fmt.Errorf("overlay %q: array element %d is not a table", path, i)
				}
				el := reflect.New(elemType).Elem()
				if err := buildFromMap(el, m); err != nil {
					return fmt.Errorf("overlay %q: element %d: %w", path, i, err)
				}
				out.Index(i).Set(el)
			}
			fv.Set(out)
		default:
			return fmt.Errorf("overlay %q: slice fields accept []string or []table only", path)
		}
	default:
		return fmt.Errorf("overlay %q: unsupported field kind %s", path, fv.Kind())
	}
	return nil
}

// buildFromMap sets struct fields from a decoded TOML table (map[string]any).
func buildFromMap(v reflect.Value, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := m[k]
		if sub, ok := val.(map[string]any); ok {
			// nested table: descend
			found := false
			for i := 0; i < v.Type().NumField(); i++ {
				if v.Type().Field(i).Tag.Get("toml") == k {
					fv := v.Field(i)
					if fv.Kind() == reflect.Ptr {
						if fv.IsNil() {
							fv.Set(reflect.New(fv.Type().Elem()))
						}
						fv = fv.Elem()
					}
					found = true
					if err := buildFromMap(fv, sub); err != nil {
						return fmt.Errorf("%s: %w", k, err)
					}
					break
				}
			}
			if !found {
				return fmt.Errorf("unknown field %q", k)
			}
			continue
		}
		fv := findField(v, k)
		if !fv.IsValid() {
			return fmt.Errorf("unknown field %q", k)
		}
		if err := setField(fv, k, val); err != nil {
			return err
		}
	}
	return nil
}

// findField locates the struct field with the given toml tag. Panics are
// avoided by returning a zero Value; callers validate beforehand via
// schema-typed strict decode.
func findField(v reflect.Value, tag string) reflect.Value {
	for i := 0; i < v.Type().NumField(); i++ {
		if v.Type().Field(i).Tag.Get("toml") == tag {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}
