import { Routes } from '@angular/router';
import { authGuard } from './core/auth/auth.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'queue' },
  {
    path: 'login', title: 'Entrar · SOAR',
    loadComponent: () => import('./features/auth/login-page').then((m) => m.LoginPage),
  },
  {
    path: 'queue',
    title: 'Fila · SOAR',
    // Lazy por rota desde o começo: adicionar a página de caso, playbooks e
    // auditoria depois não pode engordar o bundle inicial da fila.
    loadComponent: () => import('./features/queue/queue-page').then((m) => m.QueuePage),
    canActivate: [authGuard],
  },
  {
    path: 'incidents/:id', title: 'Incidente · SOAR', canActivate: [authGuard],
    loadComponent: () => import('./features/incident/incident-page').then((m) => m.IncidentPage),
  },
  {
    path: 'approvals',
    title: 'Aprovações · SOAR',
    canActivate: [authGuard],
    loadComponent: () => import('./features/approvals/approvals-page').then((m) => m.ApprovalsPage),
  },
  { path: '**', redirectTo: 'queue' },
];
