package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Ollama runs the model on the host, outside the cluster.
//
// That placement is deliberate (docs/soar/03, AD-09): there is one GPU and
// one consumer, and passing an AMD card into k3s would need the ROCm device
// plugin for nothing. The platform reaches it by name.
type Ollama struct {
	BaseURL string
	Model   string
	NumCtx  int
	client  *http.Client
}

func NewOllama(baseURL, model string, numCtx int, timeout time.Duration) *Ollama {
	return &Ollama{
		BaseURL: strings.TrimRight(baseURL, "/"), Model: model, NumCtx: numCtx,
		client: &http.Client{Timeout: timeout},
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	// Qwen 3 otherwise spends part of the fixed 8k context on a hidden
	// thinking trace. The measured Python reference explicitly disables it.
	Think bool `json:"think"`
	// Format carries the JSON schema. Constrained decoding is what makes an
	// 8B model usable here at all: left free-form it happily emits prose
	// around the JSON, or invents extra keys, and every one of those is a
	// parse failure in a pipeline that has to run unattended.
	Format  any            `json:"format,omitempty"`
	Options map[string]any `json:"options,omitempty"`
}

type chatResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	PromptEvalCount int  `json:"prompt_eval_count"`
	Done            bool `json:"done"`
}

// Complete asks the model and returns the raw JSON it produced.
func (o *Ollama) Complete(ctx context.Context, system, user string, schema any) (string, int, error) {
	payload, err := json.Marshal(chatRequest{
		Model: o.Model, Stream: false, Think: false, Format: schema,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Options: map[string]any{
			"num_ctx": o.NumCtx,
			// Temperatura baixa: queremos a leitura mais provável da
			// evidência, não variedade. Criatividade aqui é invenção.
			"temperature": 0.2,
			"top_p":       0.9,
		},
	})
	if err != nil {
		return "", 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		o.BaseURL+"/api/chat", bytes.NewReader(payload))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("Ollama inalcançável em %s: %w", o.BaseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode >= 400 {
		return "", 0, fmt.Errorf("Ollama respondeu %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", 0, fmt.Errorf("resposta inesperada do Ollama: %w", err)
	}
	if !parsed.Done || strings.TrimSpace(parsed.Message.Content) == "" {
		return "", parsed.PromptEvalCount, fmt.Errorf("Ollama encerrou sem uma resposta completa")
	}
	return parsed.Message.Content, parsed.PromptEvalCount, nil
}

// Health reports whether the model is loaded and answering.
func (o *Ollama) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.BaseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("Ollama inalcançável: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("Ollama respondeu %d", resp.StatusCode)
	}
	return nil
}
