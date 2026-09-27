import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { catchError, throwError, timeout } from 'rxjs';
import { ApiError, ApiErrorKind } from '../errors/api-error';

function cookie(name: string): string | null {
  const prefix = `${encodeURIComponent(name)}=`;
  const item = document.cookie.split('; ').find((part) => part.startsWith(prefix));
  return item ? decodeURIComponent(item.slice(prefix.length)) : null;
}

/** Toda requisição sai com um id, e ele volta no log do servidor. */
export const requestIdInterceptor: HttpInterceptorFn = (req, next) =>
  next(req.clone({ setHeaders: { 'X-Request-Id': crypto.randomUUID() } }));

/** Mutação por cookie só sai acompanhada do token vinculado à sessão. */
export const csrfInterceptor: HttpInterceptorFn = (req, next) => {
  const safe = req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS';
  const token = safe ? null : cookie('soar_csrf');
  return next(token ? req.clone({ setHeaders: { 'X-CSRF-Token': token } }) : req);
};

/**
 * Nenhuma requisição fica pendurada para sempre. Uma tela travada é
 * indistinguível de uma tela quebrada para quem está de plantão.
 */
export const timeoutInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(timeout({ each: 30_000 }));

function kindFor(status: number): ApiErrorKind {
  if (status === 0) return 'network';
  if (status === 401) return 'authentication';
  if (status === 403) return 'authorization';
  if (status === 404) return 'not_found';
  if (status === 409 || status === 412 || status === 428) return 'conflict';
  if (status === 422 || status === 400) return 'validation';
  if (status === 429) return 'rate_limited';
  return 'server';
}

/** Traduz o envelope de erro do backend para ApiError, uma vez só. */
export const errorInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(
    catchError((err: unknown) => {
      if (err instanceof ApiError) return throwError(() => err);

      if (err instanceof HttpErrorResponse) {
        const body: unknown = err.error;
        let code = 'UNKNOWN';
        let message = err.message;
        let requestId: string | null = err.headers.get('X-Request-Id');

        if (body && typeof body === 'object' && 'error' in body) {
          const envelope = body as { error?: { code?: string; message?: string }; request_id?: string };
          code = envelope.error?.code ?? code;
          message = envelope.error?.message ?? message;
          requestId = envelope.request_id ?? requestId;
        }
        return throwError(() => new ApiError(kindFor(err.status), code, message, err.status, requestId));
      }

      const isTimeout = err instanceof Error && err.name === 'TimeoutError';
      return throwError(
        () => new ApiError(isTimeout ? 'timeout' : 'network', 'TRANSPORT', 'Falha de transporte', 0, null),
      );
    }),
  );
