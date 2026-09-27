/**
 * Estado explícito de toda operação assíncrona (docs/soar/06, §96 do briefing).
 *
 * Existe porque "sem dados na tela" é ambíguo: pode ser carregando, pode ser
 * vazio de verdade, pode ser erro. Para quem está de plantão às três da manhã,
 * essa diferença importa.
 */
import { ApiError } from '../../core/errors/api-error';

export type AsyncState<T> =
  | { readonly status: 'idle' }
  | { readonly status: 'loading' }
  | { readonly status: 'success'; readonly value: T }
  | { readonly status: 'error'; readonly error: ApiError };

export const idle = (): AsyncState<never> => ({ status: 'idle' });
export const loading = (): AsyncState<never> => ({ status: 'loading' });
export const success = <T>(value: T): AsyncState<T> => ({ status: 'success', value });
export const failure = (error: ApiError): AsyncState<never> => ({ status: 'error', error });
