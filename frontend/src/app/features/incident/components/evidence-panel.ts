import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { AssessmentService, type CaseEvidence } from '../../../core/api/assessment.service';
import { ApiError } from '../../../core/errors/api-error';

interface ObservableGroup {
  field: string;
  label: string;
  values: string[];
}

const OBSERVABLE_LABEL: Record<string, string> = {
  'source.ip': 'IP de origem',
  'destination.ip': 'IP de destino',
  'destination.domain': 'Domínio de destino',
  'dns.question.name': 'Consulta DNS',
  'url.original': 'URL',
  'url.path': 'Caminho HTTP',
  'http.request.method': 'Método HTTP',
  'http.response.status_code': 'Status HTTP',
  'process.executable': 'Executável',
  'process.command_line': 'Linha de comando',
  'process.parent.executable': 'Processo pai',
  'user.name': 'Usuário',
  'file.path': 'Arquivo',
};

const LEVEL_LABEL: Record<string, string> = {
  grandparent: 'Avô', parent: 'Pai', process: 'Processo',
};

@Component({
  selector: 'soar-evidence-panel',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="panel" aria-labelledby="evidence-title">
      <div class="head">
        <div>
          <p class="eyebrow">Telemetria · extração determinística</p>
          <h2 id="evidence-title">Evidências e IOCs</h2>
        </div>
        <span class="without-ai">sem IA</span>
      </div>

      @if (loading()) { <p class="muted" role="status">Coletando evidências do caso…</p> }
      @if (failure()) {
        <p class="error" role="alert">{{ failure() }}</p>
        <button type="button" class="ghost" (click)="load()">Tentar novamente</button>
      }

      @if (evidence(); as item) {
        <dl class="identity">
          <div><dt>Regra</dt><dd>{{ item.cluster.rule_name }}</dd></div>
          <div><dt>Host</dt><dd>{{ item.cluster.host || 'não informado' }}</dd></div>
          <div><dt>Entidade principal</dt><dd class="technical">{{ item.cluster.entity || 'não identificada' }}</dd></div>
          <div><dt>Janela</dt><dd>{{ item.cluster.count }} alerta(s), {{ date(item.cluster.first_seen) }} – {{ date(item.cluster.last_seen) }}</dd></div>
        </dl>

        <div class="stats" aria-label="Entidades extraídas">
          <span>{{ item.case_context.entities.processes }} processo(s)</span>
          <span>{{ item.case_context.entities.files }} arquivo(s)</span>
          <span>{{ item.case_context.entities.hashes }} hash(es)</span>
          <span>{{ item.case_context.entities.ips }} IP(s)</span>
          <span>{{ item.case_context.entities.domains }} domínio(s)</span>
          <span>{{ item.case_context.entities.urls }} URL(s)</span>
        </div>

        <div class="grid">
          <section aria-labelledby="observables-title">
            <h3 id="observables-title">Observáveis extraídos</h3>
            @for (group of observableGroups(); track group.field) {
              <div class="observable-group">
                <h4>{{ group.label }}</h4>
                <ul class="values">
                  @for (value of group.values; track value) { <li class="technical">{{ value }}</li> }
                </ul>
              </div>
            } @empty {
              <p class="muted">Nenhum observável foi normalizado para este alerta.</p>
            }
          </section>

          <section aria-labelledby="ioc-title">
            <h3 id="ioc-title">Correspondências em inteligência</h3>
            @if (item.case_context.ioc_hits.length) {
              <ul class="ioc-list">
                @for (hit of item.case_context.ioc_hits; track stringify(hit.indicator) + stringify(hit.feed)) {
                  <li>
                    <strong class="technical">{{ stringify(hit.indicator) }}</strong>
                    <span>{{ stringify(hit.type) }} · {{ stringify(hit.feed) }}</span>
                  </li>
                }
              </ul>
            } @else {
              <p class="empty">Nenhuma correspondência encontrada nos feeds ingeridos.</p>
              <p class="muted">Isso não classifica o caso como benigno; apenas registra o resultado da consulta.</p>
            }

            @if (item.case_context.process_chain?.length) {
              <h3>Cadeia de processos</h3>
              <ol class="process-chain">
                @for (process of item.case_context.process_chain; track process.level) {
                  <li>
                    <span>{{ level(process.level) }}</span>
                    <strong class="technical">{{ process.executable || 'não encontrado' }}</strong>
                    @if (process.command_line) { <small class="technical">{{ process.command_line }}</small> }
                    @if (process.user) { <small>usuário {{ process.user }}</small> }
                  </li>
                }
              </ol>
            }
          </section>
        </div>

        @if (item.case_context.files || item.case_context.network || item.case_context.web || item.case_context.related_alerts.length) {
          <details>
            <summary>Atividade correlacionada</summary>
            <div class="grid correlated">
              @if (item.case_context.files; as files) {
                <section><h3>Arquivos</h3>
                  <p>{{ files.events ?? 0 }} evento(s), {{ files.count }} caminho(s) distinto(s)</p>
                  <ul class="values">
                    @for (path of files.paths; track path) { <li class="technical">{{ path }}</li> }
                    @for (hash of files.hashes; track hash) { <li class="technical">SHA-256 {{ hash }}</li> }
                  </ul>
                </section>
              }
              @if (item.case_context.network; as network) {
                <section><h3>Rede</h3><p>{{ network.events }} evento(s)</p>
                  <ul class="values">
                    @for (destination of network.destinations; track destination.ip) { <li class="technical">{{ destination.ip }}{{ port(destination.port) }} · {{ destination.n }}×</li> }
                    @for (domain of network.domains; track domain) { <li class="technical">{{ domain }}</li> }
                  </ul>
                </section>
              }
              @if (item.case_context.web; as web) {
                <section><h3>Web</h3><ul class="values">
                  @for (url of web.urls; track url) { <li class="technical">{{ url }}</li> }
                </ul></section>
              }
              @if (item.case_context.related_alerts.length) {
                <section><h3>Alertas relacionados</h3><ul>
                  @for (related of item.case_context.related_alerts; track related.rule) { <li>{{ related.rule }} · {{ related.n }}×</li> }
                </ul></section>
              }
            </div>
          </details>
        }

        @if (item.case_context.missing.length) {
          <details class="missing"><summary>Limitações da coleta ({{ item.case_context.missing.length }})</summary>
            <ul>@for (gap of item.case_context.missing; track gap) { <li>{{ gap }}</li> }</ul>
          </details>
        }
      }
    </section>
  `,
  styles: `
    :host{display:block;grid-column:1/-1}.panel{background:var(--bg-raised);border:1px solid var(--border);border-radius:.625rem;padding:1rem}.head{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start}.eyebrow{margin:0;color:var(--fg-muted);font-size:.6875rem;font-weight:600;letter-spacing:.06em;text-transform:uppercase}h2{font-size:1rem;margin:.125rem 0 0}h3{font-size:.875rem;margin:0 0 .65rem}h4{color:var(--fg-muted);font-size:.7rem;letter-spacing:.04em;margin:.75rem 0 .25rem;text-transform:uppercase}.without-ai{border:1px solid var(--border);border-radius:999px;color:var(--fg-muted);font-size:.7rem;font-weight:700;padding:.25rem .55rem}.identity{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.65rem;margin:1rem 0}.identity div{border-bottom:1px solid var(--border-subtle);padding-bottom:.5rem}dt{color:var(--fg-muted);font-size:.7rem;text-transform:uppercase}dd{font-size:.8125rem;margin:.2rem 0 0}.technical{overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.stats{display:flex;flex-wrap:wrap;gap:.35rem;margin-bottom:1rem}.stats span{background:var(--bg);border:1px solid var(--border-subtle);border-radius:.3rem;color:var(--fg-muted);font-size:.72rem;padding:.25rem .45rem}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem}.grid>section{border:1px solid var(--border-subtle);border-radius:.5rem;padding:.75rem}.values,.ioc-list,.process-chain{list-style:none;margin:.25rem 0;padding:0}.values li{border-top:1px solid var(--border-subtle);font-size:.75rem;padding:.35rem 0}.ioc-list li,.process-chain li{display:flex;flex-direction:column;gap:.15rem;border-top:1px solid var(--border-subtle);font-size:.75rem;padding:.5rem 0}.ioc-list span,.process-chain span,.process-chain small,.muted{color:var(--fg-muted);font-size:.75rem}.empty,.error{border-radius:.375rem;font-size:.8rem;padding:.6rem}.empty{background:var(--sev-low-bg);color:var(--sev-low-fg)}.error{background:var(--sev-critical-bg);color:var(--sev-critical-fg)}button{font:inherit;border:1px solid var(--border);border-radius:.375rem;padding:.45rem .6rem;cursor:pointer}.ghost{background:transparent;color:var(--fg-muted)}details{border-top:1px solid var(--border-subtle);font-size:.8rem;margin-top:1rem;padding-top:.75rem}summary{cursor:pointer;font-weight:600}.correlated{margin-top:.75rem}.correlated p,.correlated li,.missing li{font-size:.75rem}:is(button,summary):focus-visible{outline:2px solid var(--focus);outline-offset:2px}@media(max-width:48rem){.identity,.grid{grid-template-columns:1fr}}
  `,
})
export class EvidencePanel implements OnInit {
  readonly incidentId = input.required<string>();
  private readonly api = inject(AssessmentService);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly evidence = signal<CaseEvidence | null>(null);
  protected readonly loading = signal(true);
  protected readonly failure = signal('');
  protected readonly observableGroups = computed<ObservableGroup[]>(() =>
    Object.entries(this.evidence()?.cluster.observables ?? {}).map(([field, values]) => ({
      field, values, label: OBSERVABLE_LABEL[field] ?? field,
    })),
  );

  ngOnInit(): void { this.load(); }

  protected load(): void {
    this.loading.set(true); this.failure.set('');
    this.api.evidence(this.incidentId()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: (evidence) => { this.evidence.set(evidence); this.loading.set(false); },
      error: (error: ApiError) => { this.failure.set(error.userMessage); this.loading.set(false); },
    });
  }

  protected date(value: string): string {
    return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
  }
  protected stringify(value: unknown): string {
    if (value === null || value === undefined || value === '') return 'não informado';
    return typeof value === 'string' ? value : JSON.stringify(value);
  }
  protected level(value: string): string { return LEVEL_LABEL[value] ?? value; }
  protected port(value: unknown): string {
    return value === null || value === undefined || value === '' ? '' : `:${this.stringify(value)}`;
  }
}
