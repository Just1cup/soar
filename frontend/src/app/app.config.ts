import { ApplicationConfig, provideBrowserGlobalErrorListeners } from '@angular/core';
import { provideHttpClient, withInterceptors, withFetch } from '@angular/common/http';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { routes } from './app.routes';
import {
  csrfInterceptor, errorInterceptor, requestIdInterceptor, timeoutInterceptor,
} from './core/http/api.interceptors';

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideRouter(routes, withComponentInputBinding()),
    provideHttpClient(
      withFetch(),
      // A ordem importa: o id é anexado antes de sair, o timeout envolve a
      // chamada, e a tradução de erro é a mais externa para capturar as duas.
      withInterceptors([requestIdInterceptor, csrfInterceptor, timeoutInterceptor, errorInterceptor]),
    ),
  ],
};
