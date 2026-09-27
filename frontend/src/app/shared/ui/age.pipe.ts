import { Pipe, PipeTransform } from '@angular/core';

/**
 * Há quanto tempo, em português curto.
 *
 * A fila do SOC é ordenada por severidade, mas lida por tempo de espera: o
 * número que o analista procura é "há quanto tempo isto está aqui sem
 * tratamento".
 */
@Pipe({ name: 'age' })
export class AgePipe implements PipeTransform {
  transform(value: string | Date | null | undefined, now: Date = new Date()): string {
    if (!value) return '—';
    const then = value instanceof Date ? value : new Date(value);
    const minutes = Math.floor((now.getTime() - then.getTime()) / 60_000);
    if (!Number.isFinite(minutes) || minutes < 0) return '—';
    if (minutes < 1) return 'agora';
    if (minutes < 60) return `${minutes} min`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} h`;
    const days = Math.floor(hours / 24);
    if (days < 30) return `${days} d`;
    return `${Math.floor(days / 30)} mes${Math.floor(days / 30) > 1 ? 'es' : ''}`;
  }
}
