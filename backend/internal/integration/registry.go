package integration

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Loaded is a manifest plus the bytes it came from, so the store can record a
// hash and detect drift between what is on disk and what was installed.
type Loaded struct {
	Manifest Manifest
	SHA256   []byte
}

// LoadPacks reads every content-packs/<pack>/integration.yaml.
//
// A pack that fails validation is skipped with a loud log and does NOT take
// the others down: one bad pack must not stop a SOC from answering alerts.
func LoadPacks(root fs.FS, log *slog.Logger) ([]Loaded, error) {
	var out []Loaded
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, fmt.Errorf("ler content-packs: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(e.Name(), "integration.yaml")
		raw, err := fs.ReadFile(root, path)
		if err != nil {
			continue // um pack sem integração é legítimo: pode trazer só regras
		}
		var m Manifest
		if err := yaml.Unmarshal(raw, &m); err != nil {
			log.Error("pack inválido, ignorado", "pack", e.Name(), "error", err)
			continue
		}
		if m.PackID == "" {
			m.PackID = e.Name()
		}
		if err := m.Validate(); err != nil {
			log.Error("pack inválido, ignorado", "pack", e.Name(), "error", err)
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, Loaded{Manifest: m, SHA256: sum[:]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out, nil
}

// Registry maps a qualified action name to its manifest and adapter.
type Registry struct {
	manifests map[string]Manifest
	adapters  map[string]Adapter
}

func NewRegistry() *Registry {
	return &Registry{manifests: map[string]Manifest{}, adapters: map[string]Adapter{}}
}

func (r *Registry) Install(m Manifest) { r.manifests[m.ID] = m }

// Bind attaches the compiled adapter. An action declared in a manifest with no
// adapter bound stays visible and answers "not implemented" — which is how
// containment actions exist in the catalogue without existing in this
// deployment (AD-08).
func (r *Registry) Bind(a Adapter) { r.adapters[a.Slug()] = a }

// Lookup parses "integration.action".
func (r *Registry) Lookup(qualified string) (Manifest, Action, Adapter, error) {
	slug, actionID, ok := strings.Cut(qualified, ".")
	if !ok {
		return Manifest{}, Action{}, nil, fmt.Errorf("ação deve ser integração.ação, recebido %q", qualified)
	}
	m, ok := r.manifests[slug]
	if !ok {
		return Manifest{}, Action{}, nil, fmt.Errorf("integração desconhecida: %q", slug)
	}
	a, ok := m.Action(actionID)
	if !ok {
		return Manifest{}, Action{}, nil, fmt.Errorf("%s não oferece a ação %q", slug, actionID)
	}
	return m, a, r.adapters[slug], nil
}

func (r *Registry) Manifests() []Manifest {
	out := make([]Manifest, 0, len(r.manifests))
	for _, m := range r.manifests {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RuleFile is a content pack's rules/*.yaml.
type RuleFile struct {
	Rules []RuleSpec `yaml:"rules"`
}

// RuleSpec is the wire form of a pre-process rule. It stays in this package
// so a pack is parsed in one place, and it carries no behaviour: a pack is
// data, never code (AD-06).
type RuleSpec struct {
	ID         string           `yaml:"id"`
	Name       string           `yaml:"name"`
	Trigger    string           `yaml:"trigger"`
	Order      int              `yaml:"order"`
	ExpiresAt  *time.Time       `yaml:"expires_at"`
	Conditions map[string]any   `yaml:"conditions"`
	Actions    []map[string]any `yaml:"actions"`
}

// LoadRules reads every content-packs/<pack>/rules/*.yaml.
func LoadRules(root fs.FS, log *slog.Logger) (map[string][]RuleSpec, error) {
	out := map[string][]RuleSpec{}
	packs, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, err
	}
	for _, pack := range packs {
		if !pack.IsDir() {
			continue
		}
		dir := filepath.Join(pack.Name(), "rules")
		files, err := fs.ReadDir(root, dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".yaml") {
				continue
			}
			raw, err := fs.ReadFile(root, filepath.Join(dir, f.Name()))
			if err != nil {
				continue
			}
			var parsed RuleFile
			if err := yaml.Unmarshal(raw, &parsed); err != nil {
				// Um arquivo de regras ruim é ignorado com log alto: ele não
				// pode impedir o resto do pack de carregar.
				log.Error("arquivo de regras inválido, ignorado",
					"pack", pack.Name(), "file", f.Name(), "error", err)
				continue
			}
			out[pack.Name()] = append(out[pack.Name()], parsed.Rules...)
		}
	}
	return out, nil
}
