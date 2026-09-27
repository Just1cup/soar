import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { SEVERITY_LABEL, type Severity } from '../../../core/api/types';

/**
 * Componente de apresentação: recebe input, não busca dado, não tem estado.
 * A cor nunca é a única portadora de significado — o rótulo textual vai junto,
 * porque cerca de 8% dos analistas homens têm deficiência de visão de cores.
 */
@Component({
  selector: 'soar-severity-chip',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="chip" [attr.data-severity]="severity()">{{ label() }}</span>`,
  styles: `
    .chip {
      display: inline-block; padding: .125rem .5rem; border-radius: 999px;
      font-size: .75rem; font-weight: 600; letter-spacing: .01em;
      border: 1px solid transparent; white-space: nowrap;
    }
    .chip[data-severity='critical'] { background: var(--sev-critical-bg); color: var(--sev-critical-fg); border-color: var(--sev-critical-fg); }
    .chip[data-severity='high']     { background: var(--sev-high-bg);     color: var(--sev-high-fg); }
    .chip[data-severity='medium']   { background: var(--sev-medium-bg);   color: var(--sev-medium-fg); }
    .chip[data-severity='low']      { background: var(--sev-low-bg);      color: var(--sev-low-fg); }
    .chip[data-severity='info']     { background: var(--sev-info-bg);     color: var(--sev-info-fg); }
  `,
})
export class SeverityChip {
  readonly severity = input.required<Severity>();
  protected readonly label = computed(() => SEVERITY_LABEL[this.severity()]);
}
