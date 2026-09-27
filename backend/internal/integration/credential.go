package integration

import (
	"fmt"
	"os"
	"strings"
)

// CredentialProvider resolves a pointer into a secret.
//
// The database never stores a credential — only a reference. Three backends
// exist behind one interface so that moving from .env to a Kubernetes Secret
// to Vault is configuration, not a rewrite (docs/soar/03 §9).
type CredentialProvider interface {
	Resolve(ref string) (string, error)
}

// ErrNoCredential separates "this integration needs no key" from "the key is
// missing". A missing API key is a configuration state, not an error — the
// platform must still start, and still say which providers are off.
type ErrNoCredential struct{ Ref string }

func (e ErrNoCredential) Error() string { return "credencial ausente: " + e.Ref }

// ChainProvider dispatches by scheme.
type ChainProvider struct {
	Env func(string) string
	// K8sDir is where projected Secret volumes are mounted, one file per key.
	K8sDir string
}

func NewChainProvider() *ChainProvider {
	return &ChainProvider{Env: os.Getenv, K8sDir: "/run/secrets"}
}

func (p *ChainProvider) Resolve(ref string) (string, error) {
	scheme, rest, ok := strings.Cut(ref, "://")
	if !ok {
		// Nunca tratar o valor como o próprio segredo: isso transformaria uma
		// configuração errada em credencial em texto puro no banco.
		return "", fmt.Errorf("referência de credencial malformada (esperado esquema://): %q", ref)
	}
	switch scheme {
	case "none":
		return "", nil
	case "env":
		v := p.Env(rest)
		if v == "" {
			return "", ErrNoCredential{Ref: ref}
		}
		return v, nil
	case "k8s":
		// k8s://nome-do-secret/chave -> /run/secrets/nome-do-secret/chave
		b, err := os.ReadFile(p.K8sDir + "/" + rest)
		if err != nil {
			return "", ErrNoCredential{Ref: ref}
		}
		return strings.TrimSpace(string(b)), nil
	case "vault":
		return "", fmt.Errorf("provedor vault ainda não implementado: %q", ref)
	default:
		return "", fmt.Errorf("esquema de credencial desconhecido: %q", scheme)
	}
}
