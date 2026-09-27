import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, map, switchMap, tap } from 'rxjs';
import type { CurrentActor, Envelope } from '../api/types';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  readonly actor = signal<CurrentActor | null>(null);

  load(): Observable<CurrentActor> {
    return this.http.get<Envelope<CurrentActor>>('/api/v1/auth/me').pipe(
      map((res) => res.data),
      tap((actor) => this.actor.set(actor)),
    );
  }

  login(email: string, password: string): Observable<CurrentActor> {
    return this.http.post('/api/v1/auth/login', { email, password }).pipe(
      switchMap(() => this.load()),
    );
  }

  logout(): Observable<void> {
    return this.http.post('/api/v1/auth/logout', {}).pipe(
      tap(() => this.actor.set(null)),
      map(() => undefined),
    );
  }

  can(permission: string): boolean {
    return this.actor()?.permissions.includes(permission) ?? false;
  }
}
