import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { AssessmentService, type Assessment } from '../../../core/api/assessment.service';
import { AuthService } from '../../../core/auth/auth.service';
import { AssessmentPanel } from './assessment-panel';

const assessment: Assessment = {
  id: '00000000-0000-7000-8000-000000000030',
  incident_id: '00000000-0000-7000-8000-000000000010', supersedes: null,
  author_kind: 'model', model: 'qwen3:8b', schema_version: 2,
  verdict: 'true_positive', confidence: 'medium', source_reliability: 'A',
  info_credibility: '2', admiralty: 'A2', title: 'Execução suspeita confirmada',
  summary: 'A telemetria favorece atividade não autorizada.', disagreed: false,
  body: {
    why_notable: 'Processo raro no host.',
    observed: [{ statement: 'bash executou a partir de /tmp', basis: 'observed' }],
    suspicious_indicators: ['origem temporária'], benign_indicators: ['usuário administrativo'],
    hypotheses: [
      { kind: 'suspicious', statement: 'execução hostil', supporting: ['processo raro'], contradicting: ['sem persistência'] },
      { kind: 'benign', statement: 'manutenção autorizada', supporting: ['usuário administrativo'], contradicting: ['sem mudança registrada'] },
    ],
    attack_context: 'Possível execução de comandos.',
    diamond: { adversary: '', capability: 'shell', infrastructure: 'srv-01', victim: 'srv-01' },
    likely_benign_if: ['houver mudança aprovada'], more_suspicious_if: ['pai for processo web'],
    intelligence_gaps: ['processo pai'], recommended_actions: ['verificar árvore de processos'],
    reasoning: 'A hipótese suspeita explica mais evidências.', decision_reasoning: 'Comportamento incomum.',
    investigation_verdict: 'true_positive', favoured_hypothesis: 'suspicious', behaviour_occurred: true,
  },
  case_context: {}, attack_tactics: ['Execution'], attack_techniques: ['T1059'],
  promoted_at: null, promoted_by: null, generated_at: '2026-09-21T03:00:00Z',
  latency_ms: 12000, prompt_tokens: 1400,
};

class StubAssessment {
  promoted = false;
  list() { return of([assessment]); }
  promote(_incident: string, _id: string, _note: string) {
    this.promoted = true;
    return of({ ...assessment, promoted_at: '2026-09-21T04:00:00Z', promoted_by: 'user-1' });
  }
}

describe('AssessmentPanel', () => {
  let fixture: ComponentFixture<AssessmentPanel>;
  let api: StubAssessment;

  beforeEach(async () => {
    api = new StubAssessment();
    await TestBed.configureTestingModule({
      imports: [AssessmentPanel],
      providers: [
        { provide: AssessmentService, useValue: api },
        { provide: AuthService, useValue: { can: (permission: string) => permission === 'assessment.promote' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(AssessmentPanel);
    fixture.componentRef.setInput('incidentId', assessment.incident_id);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('mostra as duas hipóteses, a base e as lacunas', () => {
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('Hipótese benigna');
    expect(text).toContain('Hipótese suspeita');
    expect(text).toContain('observado');
    expect(text).toContain('processo pai');
    expect(text).toContain('Admiralty A2');
  });

  it('promove sem fechar o incidente e exibe a confirmação do backend', () => {
    const root = fixture.nativeElement as HTMLElement;
    const note = root.querySelector('textarea') as HTMLTextAreaElement;
    note.value = 'Concordo após revisar a árvore de processos.';
    (root.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
    fixture.detectChanges();

    expect(api.promoted).toBe(true);
    expect(root.textContent).toContain('Veredito promovido por um analista');
    expect(root.textContent).not.toContain('Promover a veredito');
  });
});
