// Package assessment is the local LLM analyst: the part of this platform that
// none of the five commercial SOARs has.
//
// They all automate ACTIONS. None of them measures whether the ANALYSIS that
// justified the action was right. That is the contribution here, and three
// conventions do the work:
//
// **The Admiralty scale** (NATO STANAG 2511) grades every assessment twice and
// separately: how reliable the SOURCE is (A–F) and how credible this
// particular INFORMATION is (1–6). Telemetry from our own endpoint agent is an
// A source, but a single ambiguous process execution seen once is still
// 4-level information. "A1" and "A4" are very different claims, and collapsing
// them into one "confidence: high" loses exactly the distinction an analyst
// needs.
//
// **The Diamond Model** forces the assessment to say who, with what, from
// where, against whom — and to leave a vertex explicitly unknown rather than
// inventing it. Most alerts here will have an empty adversary vertex, and that
// is a CORRECT assessment, not a failure.
//
// **ATT&CK** anchors the behaviour to a shared catalogue, which is what makes
// the assessment comparable and measurable against a human label.
//
// The hard rule, enforced by RBAC and not by convention: the model never
// writes case state. It produces an immutable artefact. Promoting that
// artefact to a verdict is an act of a human or of an explicit rule, and in
// both cases it becomes a line in the audit trail with the right author.
package assessment

import (
	"bytes"
	"encoding/json"
)

type Verdict string

const (
	TruePositive       Verdict = "true_positive"
	BenignTruePositive Verdict = "benign_true_positive"
	FalsePositive      Verdict = "false_positive"
	Inconclusive       Verdict = "inconclusive"
)

// BenignTruePositive is the category most SOC tooling lacks and most real
// alerts fall into: the detection fired correctly, the described behaviour
// genuinely happened, and it was authorised. Steam launching a process from a
// Steam directory is not a false positive — the rule saw exactly what it
// claimed. Calling it "FP" trains people to distrust the rule; naming it
// properly directs them to an exception instead.
var VerdictLabel = map[Verdict]string{
	TruePositive:       "verdadeiro positivo",
	BenignTruePositive: "verdadeiro positivo benigno",
	FalsePositive:      "falso positivo",
	Inconclusive:       "inconclusivo",
}

type Confidence string

const (
	Low    Confidence = "low"
	Medium Confidence = "medium"
	High   Confidence = "high"
)

// Basis is the evidence policy: every claim says what it rests on.
type Basis string

const (
	Observed Basis = "observed" // sustentado diretamente pela telemetria
	Inferred Basis = "inferred" // leitura razoável do que foi observado
	Unknown  Basis = "unknown"  // necessário, e indisponível
)

// DeriveVerdict is ported exactly, and the reason it exists is a measurement.
//
// Asked "what is the verdict?", the 8B model weighed the hypotheses correctly
// — "the suspicious hypothesis is favoured" — and then answered
// "inconclusive" anyway, seven cases out of seven. Asked instead which
// hypothesis the evidence favours, it answers the question it actually
// reasoned about. The verdict is derived here, in code.
func DeriveVerdict(behaviourOccurred *bool, favoured string) Verdict {
	if behaviourOccurred != nil && !*behaviourOccurred {
		return FalsePositive
	}
	switch favoured {
	case "suspicious":
		return TruePositive
	case "benign":
		return BenignTruePositive
	default:
		return Inconclusive
	}
}

// decisionSchema is the SHORT first pass: commit to a verdict on the alert
// alone. Scored 5/7 against human labels, which is why it survives as the
// decision even though the long pass reasons better.
var decisionSchema = map[string]any{
	"type": "object",
	"properties": ordered(
		prop("verdict", enumOf(string(TruePositive), string(BenignTruePositive),
			string(FalsePositive), string(Inconclusive))),
		prop("source_reliability", enumOf("A", "B", "C", "D", "E", "F")),
		prop("info_credibility", enumOf("1", "2", "3", "4", "5", "6")),
		prop("title", str()),
		prop("summary", str()),
		prop("reasoning", str()),
	),
	"required": []string{"verdict", "source_reliability", "info_credibility",
		"title", "summary", "reasoning"},
}

// caseSchema is the LONG second pass, and **the property order IS the
// reasoning order**.
//
// With constrained decoding the model emits fields in schema order, so
// whatever comes first is decided before anything after it is written. The
// first version put `verdict` first: the model committed to a verdict and then
// justified it. Here the analysis comes first — indicators, hypotheses,
// weighing — and the grades come last, decided on what was just written.
//
// The verdict is not asked for at all. See DeriveVerdict.
var caseSchema = map[string]any{
	"type": "object",
	"properties": ordered(
		prop("title", str()),
		prop("summary", str()),
		prop("why_notable", str()),
		prop("observed", listOf(map[string]any{
			"type": "object",
			"properties": ordered(
				prop("statement", str()),
				prop("basis", enumOf(string(Observed), string(Inferred), string(Unknown))),
			),
			"required": []string{"statement", "basis"},
		}, 5)),
		prop("suspicious_indicators", listOf(str(), 4)),
		prop("benign_indicators", listOf(str(), 4)),
		prop("hypotheses", map[string]any{
			"type": "array", "minItems": 2, "maxItems": 2,
			"items": map[string]any{
				"type": "object",
				"properties": ordered(
					prop("kind", enumOf("benign", "suspicious")),
					prop("statement", str()),
					prop("supporting", listOf(str(), 3)),
					prop("contradicting", listOf(str(), 3)),
				),
				"required": []string{"kind", "statement", "supporting", "contradicting"},
			},
		}),
		prop("attack_context", str()),
		prop("attack_tactics", listOf(str(), 4)),
		prop("attack_techniques", listOf(str(), 4)),
		prop("diamond", map[string]any{
			"type": "object",
			"properties": ordered(
				prop("adversary", nullableStr()),
				prop("capability", nullableStr()),
				prop("infrastructure", nullableStr()),
				prop("victim", nullableStr()),
			),
			"required": []string{"adversary", "capability", "infrastructure", "victim"},
		}),
		prop("likely_benign_if", listOf(str(), 3)),
		prop("more_suspicious_if", listOf(str(), 4)),
		prop("intelligence_gaps", listOf(str(), 5)),
		prop("recommended_actions", listOf(str(), 4)),
		prop("reasoning", str()),
		prop("behaviour_occurred", map[string]any{"type": "boolean"}),
		prop("favoured_hypothesis", enumOf("suspicious", "benign", "balanced")),
		prop("confidence", enumOf(string(Low), string(Medium), string(High))),
		prop("source_reliability", enumOf("A", "B", "C", "D", "E", "F")),
		prop("info_credibility", enumOf("1", "2", "3", "4", "5", "6")),
	),
	"required": []string{
		"title", "summary", "why_notable", "observed", "suspicious_indicators",
		"benign_indicators", "hypotheses", "attack_context", "attack_tactics",
		"attack_techniques", "diamond", "likely_benign_if", "more_suspicious_if",
		"intelligence_gaps", "recommended_actions", "reasoning",
		"behaviour_occurred", "favoured_hypothesis", "confidence",
		"source_reliability", "info_credibility",
	},
}

// --- helpers de schema ------------------------------------------------------
//
// Go maps do not preserve order, and here order is semantics. These build an
// ordered structure that marshals in the declared sequence.

type field struct {
	name string
	spec map[string]any
}

type orderedProps []field

func ordered(fields ...field) orderedProps { return fields }

func prop(name string, spec map[string]any) field { return field{name: name, spec: spec} }

func str() map[string]any         { return map[string]any{"type": "string"} }
func nullableStr() map[string]any { return map[string]any{"type": []string{"string", "null"}} }
func enumOf(v ...string) map[string]any {
	return map[string]any{"type": "string", "enum": v}
}
func listOf(item map[string]any, max int) map[string]any {
	return map[string]any{"type": "array", "items": item, "maxItems": max}
}

// MarshalJSON emits the properties in DECLARED order.
//
// This is not cosmetic. Go marshals maps with sorted keys, which would send
// the schema alphabetically — `attack_context` first, `why_notable` near the
// end — and llama.cpp builds its decoding grammar in the order the properties
// arrive. The model would then be forced to emit its conclusion before its
// analysis, which is the exact failure the ordering was chosen to avoid.
func (o orderedProps) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := json.Marshal(f.name)
		if err != nil {
			return nil, err
		}
		buf.Write(name)
		buf.WriteByte(':')
		spec, err := json.Marshal(f.spec)
		if err != nil {
			return nil, err
		}
		buf.Write(spec)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
