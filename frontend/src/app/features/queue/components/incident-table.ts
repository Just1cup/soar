import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';
import { STATUS_LABEL, type IncidentSummary } from '../../../core/api/types';
import { SeverityChip } from './severity-chip';

/**
 * A fila. Apresentação pura: recebe as linhas, emite a seleção.
 *
 * `track` por id é obrigatório aqui — sem ele o Angular recria a lista inteira
 * a cada atualização, e esta lista atualiza sozinha.
 */
@Component({
  selector: 'soar-incident-table',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SeverityChip],
  template: `
    <div class="table-scroll"><table class="queue">
      <caption class="sr-only">Incidentes aguardando tratamento</caption>
      <thead>
        <tr>
          <th scope="col">Severidade</th>
          <th scope="col">ID</th>
          <th scope="col">Nome</th>
          <th scope="col">Descoberto</th>
          <th scope="col">Responsável</th>
          <th scope="col" class="num">Alertas</th>
          <th scope="col">Estado</th>
        </tr>
      </thead>
      <tbody>
        @for (incident of incidents(); track incident.id) {
          <tr tabindex="0" (click)="select.emit(incident)"
              (keydown.enter)="select.emit(incident)">
            <td><soar-severity-chip [severity]="incident.severity" /></td>
            <td class="key">{{ incident.key }}</td>
            <td><div class="title">{{ incident.title }}</div>@if (incident.source_rule) { <div class="rule">{{ incident.source_rule }}</div> }</td>
            <td class="date">{{ date(incident.first_seen) }}</td>
            <td class="owner">{{ incident.owner_name || 'Não atribuído' }}</td>
            <td class="num">{{ incident.alert_count }}</td>
            <td><span class="status">{{ statusLabel(incident.status) }}</span></td>
          </tr>
        }
      </tbody>
    </table></div>
  `,
  styles: `
    .table-scroll{overflow-x:auto}.queue { width: 100%; min-width:55rem; border-collapse: collapse; font-size: .875rem; background:var(--bg-raised); border:1px solid var(--border); }
    th {
      text-align: left; font-size: .75rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: .04em; color: var(--fg-muted); padding: .8rem .75rem; background:var(--bg-hover);
      border-bottom: 1px solid var(--border);
    }
    td { padding: .9rem .75rem; border-bottom: 1px solid var(--border-subtle); vertical-align: top; }
    tbody tr { cursor: pointer; }
    tbody tr:hover, tbody tr:focus-visible { background: var(--bg-hover); }
    tbody tr:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
    .title { color: var(--fg); font-weight: 500; line-height: 1.35; }
    .key { color:var(--focus);font-size:.8rem;white-space:nowrap;font-variant-numeric:tabular-nums; }
    .rule { color:var(--fg-muted);font-size:.72rem;margin-top:.3rem; }
    .date,.owner { color:var(--fg-muted);font-size:.78rem;white-space:nowrap; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .status { color: var(--fg-muted); font-size: .8125rem; }
    .sr-only {
      position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px;
      overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
    }
  `,
})
export class IncidentTable {
  readonly incidents = input.required<readonly IncidentSummary[]>();
  readonly select = output<IncidentSummary>();
  protected date(value: string): string {
    return new Intl.DateTimeFormat('pt-BR', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
  }
  protected statusLabel(status: IncidentSummary['status']): string {
    return STATUS_LABEL[status];
  }
}
