import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { forkJoin } from 'rxjs';
import { IncidentsService } from '../../core/api/incidents.service';
import { RESOLUTION_LABEL, STATUS_LABEL, type Incident, type Resolution, type TimelineEntry } from '../../core/api/types';
import { AuthService } from '../../core/auth/auth.service';
import { ApiError } from '../../core/errors/api-error';
import { ActionPanel } from './components/action-panel';
import { AssessmentPanel } from './components/assessment-panel';
import { EvidencePanel } from './components/evidence-panel';
import { SeverityChip } from '../queue/components/severity-chip';
import { TaskPanel } from './components/task-panel';

@Component({
  selector: 'soar-incident-page',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ActionPanel, AssessmentPanel, EvidencePanel, RouterLink, SeverityChip, TaskPanel],
  template: `
    <div class="page">
      <a class="back" routerLink="/queue">← Incidentes</a>
      @if (loading()) { <p class="muted" role="status">Carregando incidente…</p> }
      @if (error()) {
        <div class="error" role="alert"><strong>{{ error() }}</strong><button (click)="load()">Tentar de novo</button></div>
      }
      @if (incident(); as item) {
        <header class="case-head">
          <div>
            <p class="key">{{ item.key }} / {{ item.type_slug }}</p>
            <h1>{{ item.title }}</h1>
            <p class="muted">{{ item.description || item.source_rule || 'Incidente em análise' }}</p>
          </div>
          <div class="head-meta"><soar-severity-chip [severity]="item.severity" /><span class="status-badge">{{ statusLabel(item.status) }}</span></div>
        </header>
        <div class="case-grid">
          <div class="case-main">
            <nav class="tabs" aria-label="Áreas do incidente">
              <button type="button" [class.active]="tab() === 'tasks'" [attr.aria-current]="tab() === 'tasks' ? 'page' : null" (click)="tab.set('tasks')">Tasks</button>
              <button type="button" [class.active]="tab() === 'warroom'" [attr.aria-current]="tab() === 'warroom' ? 'page' : null" (click)="tab.set('warroom')">War Room</button>
            </nav>
            @if (tab() === 'tasks') {
              <soar-task-panel [incidentId]="id()" (changed)="refreshTimeline()" />
            } @else {
              <div class="war-stack">
                <soar-evidence-panel [incidentId]="id()" />
                <soar-assessment-panel [incidentId]="id()" (promoted)="load()" />
                <soar-action-panel [incidentId]="id()" (executed)="load()" />
                <section class="panel war-room" aria-labelledby="timeline-title">
                  <div class="section-head"><div><p class="eyebrow">War Room</p><h2 id="timeline-title">Linha do tempo</h2></div><span>{{ timeline().length }} evento(s)</span></div>
                  @if (timeline().length === 0) { <p class="muted">Nenhum evento registrado ainda.</p> }
                  <ol>
                    @for (entry of timeline(); track entry.id) {
                      <li><time [attr.datetime]="entry.occurred_at">{{ date(entry.occurred_at) }}</time><div><strong>{{ entry.title }}</strong><p>{{ entry.detail }}</p><small>{{ entry.actor_label || entry.actor_kind }}</small></div></li>
                    }
                  </ol>
                </section>
              </div>
            }
          </div>
          <aside class="side">
            <section class="panel" aria-labelledby="summary-title">
              <h2 id="summary-title">Summary</h2>
              <dl>
                <div><dt>Regra</dt><dd>{{ item.source_rule || 'Não informada' }}</dd></div>
                <div><dt>Estado</dt><dd>{{ statusLabel(item.status) }}</dd></div>
                <div><dt>Severidade</dt><dd>{{ item.severity }}</dd></div>
                <div><dt>Alertas</dt><dd>{{ item.alert_count }}</dd></div>
                <div><dt>Prioridade</dt><dd>P{{ item.priority }}</dd></div>
                <div><dt>Primeiro evento</dt><dd>{{ date(item.first_seen) }}</dd></div>
                <div><dt>Último evento</dt><dd>{{ date(item.last_seen) }}</dd></div>
                <div><dt>Responsável</dt><dd>{{ item.owner_name || 'Não atribuído' }}</dd></div>
                @if (item.resolution) { <div><dt>Resolução</dt><dd>{{ resolutionLabel(item.resolution) }}</dd></div> }
              </dl>
            </section>
          @if (item.status !== 'closed' && canClose()) {
            <section class="panel action" aria-labelledby="close-title">
              <h2 id="close-title">Fechar incidente</h2>
              <p class="muted">A mudança só aparece depois da confirmação do backend.</p>
              <form (submit)="close($event, resolution.value, reason.value)">
                <label>Resolução
                  <select #resolution required>
                    <option value="true_positive">Verdadeiro positivo</option>
                    <option value="benign_true_positive">VP benigno</option>
                    <option value="false_positive">Falso positivo</option>
                    <option value="inconclusive">Inconclusivo</option>
                  </select>
                </label>
                <label>Motivo<textarea #reason required minlength="3" maxlength="4000"></textarea></label>
                @if (mutationError()) { <p class="error-text" role="alert">{{ mutationError() }}</p> }
                <button type="submit" [disabled]="saving()">{{ saving() ? 'Fechando…' : 'Fechar incidente' }}</button>
              </form>
            </section>
          }
          </aside>
        </div>
      }
    </div>
  `,
  styles: `
    :host{display:block}.page{max-width:86rem;margin:0 auto;padding:1.25rem 1rem 4rem}.back{color:var(--fg-muted);font-size:.8125rem;text-decoration:none}.back:hover{color:var(--fg)}
    .case-head{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;margin:1rem 0 1.4rem}.key,.eyebrow{font-size:.75rem;letter-spacing:.05em;text-transform:uppercase;color:var(--fg-muted);margin:0}.head-meta{display:flex;align-items:center;gap:.7rem}.status-badge{border:1px solid var(--border);padding:.25rem .55rem;border-radius:1rem;color:var(--fg-muted);font-size:.75rem}
    h1{font-size:1.5rem;margin:.25rem 0}h2{font-size:1rem;margin:0 0 .75rem}.muted{color:var(--fg-muted);font-size:.8125rem}.case-grid{display:grid;grid-template-columns:minmax(0,3fr) minmax(17rem,1fr);gap:1.2rem}.case-main{min-width:0}.side{display:flex;flex-direction:column;gap:1rem}.tabs{display:flex;gap:1.5rem;border-bottom:1px solid var(--border);margin-bottom:1rem}.tabs button{font:inherit;font-size:.9rem;color:var(--fg-muted);background:none;border:0;border-bottom:2px solid transparent;padding:.65rem .3rem;cursor:pointer}.tabs button.active{color:var(--fg);border-color:var(--focus);font-weight:600}.war-stack{display:flex;flex-direction:column;gap:1rem}
    .panel{background:var(--bg-raised);border:1px solid var(--border);border-radius:.5rem;padding:1rem}dl{display:flex;flex-direction:column;gap:0;margin:0}dl div{display:grid;grid-template-columns:6rem minmax(0,1fr);gap:.7rem;border-bottom:1px solid var(--border-subtle);padding:.55rem 0}dt{color:var(--fg-muted);font-size:.72rem}dd{margin:0;font-size:.82rem;overflow-wrap:anywhere}
    form,label{display:flex;flex-direction:column}form{gap:.75rem}label{gap:.3rem;color:var(--fg-muted);font-size:.75rem}select,textarea,button{font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:.375rem;padding:.5rem}textarea{min-height:5rem;resize:vertical}button{cursor:pointer;background:var(--focus);color:white;border-color:var(--focus);font-weight:600}.war-room{margin-top:1rem}.section-head{display:flex;justify-content:space-between;align-items:start}.section-head span{color:var(--fg-muted);font-size:.75rem}
    ol{list-style:none;padding:0;margin:0}li{display:grid;grid-template-columns:11rem 1fr;gap:1rem;padding:.75rem 0;border-top:1px solid var(--border-subtle)}time,small{color:var(--fg-muted);font-size:.75rem}li p{margin:.25rem 0;font-size:.875rem}.error{border:1px solid var(--sev-critical-fg);padding:1rem;border-radius:.5rem}.error-text{color:var(--sev-critical-fg);font-size:.8125rem}.error button{margin-left:1rem}
    :is(a,button,select,textarea):focus-visible{outline:2px solid var(--focus);outline-offset:2px}@media(max-width:62rem){.case-grid{grid-template-columns:1fr}.side{order:-1}.case-head{flex-direction:column}li{grid-template-columns:1fr;gap:.25rem}}
  `,
})
export class IncidentPage implements OnInit {
  readonly id = input.required<string>();
  private readonly api = inject(IncidentsService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly incident = signal<Incident | null>(null);
  protected readonly timeline = signal<TimelineEntry[]>([]);
  protected readonly loading = signal(true);
  protected readonly saving = signal(false);
  protected readonly error = signal('');
  protected readonly mutationError = signal('');
  protected readonly tab = signal<'tasks' | 'warroom'>('tasks');
  protected readonly canClose = computed(() => this.auth.can('incident.close'));
  protected readonly statusLabel = (value: Incident['status']): string => STATUS_LABEL[value];
  protected readonly resolutionLabel = (value: Resolution): string => RESOLUTION_LABEL[value];

  ngOnInit(): void { this.load(); }

  protected load(): void {
    this.loading.set(true); this.error.set('');
    forkJoin({ incident: this.api.get(this.id()), timeline: this.api.timeline(this.id()) })
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: ({ incident, timeline }) => { this.incident.set(incident); this.timeline.set(timeline); this.loading.set(false); },
        error: (err: ApiError) => { this.error.set(err.userMessage); this.loading.set(false); },
      });
  }

  protected refreshTimeline(): void {
    this.api.timeline(this.id()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({ next: (timeline) => this.timeline.set(timeline) });
  }

  protected close(event: Event, rawResolution: string, reason: string): void {
    event.preventDefault(); const item = this.incident(); if (!item) return;
    this.saving.set(true); this.mutationError.set('');
    this.api.close(item.id, item.version, rawResolution as Resolution, reason.trim())
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: () => { this.saving.set(false); this.load(); },
        error: (err: ApiError) => { this.saving.set(false); this.mutationError.set(err.userMessage); },
      });
  }

  protected date(value: string): string { return new Intl.DateTimeFormat('pt-BR', { dateStyle:'short', timeStyle:'medium' }).format(new Date(value)); }
}
