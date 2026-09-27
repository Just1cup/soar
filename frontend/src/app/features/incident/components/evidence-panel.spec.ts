import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { AssessmentService, type CaseEvidence } from '../../../core/api/assessment.service';
import { EvidencePanel } from './evidence-panel';

const evidence: CaseEvidence = {
  cluster: {
    cluster_id: 'cluster-1', rule_name: 'Unusual File Creation by Web Server', host: 'web-01',
    entity_kind: 'process.executable', entity: '/usr/bin/caddy', count: 30,
    first_seen: '2026-09-20T20:22:38Z', last_seen: '2026-09-21T12:22:58Z',
    severity: 'medium', risk_score: 47, rule_tactics: [], rule_techniques: [],
    observables: {
      'process.executable': ['/usr/bin/caddy'],
      'file.path': ['/srv/www/upload.php'],
      'destination.ip': ['203.0.113.20'],
    },
  },
  case_context: {
    window: { first: '2026-09-20T20:22:38Z', last: '2026-09-21T12:22:58Z', alerts: 30 },
    collected: ['file activity'], missing: ['network activity unavailable'], timeline: [],
    process_chain: [
      { level: 'parent', executable: '/usr/bin/systemd', source: 'endpoint' },
      { level: 'process', executable: '/usr/bin/caddy', command_line: 'caddy run', user: 'caddy', source: 'alert' },
    ],
    files: { events: 30, actions: { creation: 30 }, paths: ['/srv/www/upload.php'], count: 1, directories: ['/srv/www'], extensions: { '.php': 1 }, hashes: ['abc123'] },
    network: { events: 1, destinations: [{ ip: '203.0.113.20', port: 443, n: 1 }], domains: ['example.test'] },
    related_alerts: [], prevalence: {},
    ioc_hits: [{ indicator: '203.0.113.20', feed: 'lab-feed', type: 'ipv4-addr' }],
    entities: { hosts: 1, users: 1, processes: 2, files: 1, hashes: 1, ips: 1, domains: 1, urls: 0, ioc_hits: 1 },
  },
};

describe('EvidencePanel', () => {
  let fixture: ComponentFixture<EvidencePanel>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [EvidencePanel],
      providers: [{ provide: AssessmentService, useValue: { evidence: () => of(evidence) } }],
    }).compileComponents();
    fixture = TestBed.createComponent(EvidencePanel);
    fixture.componentRef.setInput('incidentId', 'incident-1');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  });

  it('mostra observáveis e matches de IOC sem depender de assessment', () => {
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('Evidências e IOCs');
    expect(text).toContain('sem IA');
    expect(text).toContain('/usr/bin/caddy');
    expect(text).toContain('/srv/www/upload.php');
    expect(text).toContain('203.0.113.20');
    expect(text).toContain('lab-feed');
    expect(text).toContain('network activity unavailable');
  });
});
