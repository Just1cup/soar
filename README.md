# SOAR

Plataforma de *Security Orchestration, Automation and Response* para triagem de
alertas, gestão de incidentes, evidências, tarefas e respostas aprovadas por um
analista. O frontend é Angular 22, a API é Go 1.27 e o estado é persistido em
PostgreSQL 18. Este README descreve **o que esta versão executa**, não todas
as capacidades planejadas para um SOAR futuro.

> Uso restrito a ambientes autorizados. Fechar alertas e criar exceções modifica
> a detecção no SIEM. Revise o escopo exibido no plano antes de aprovar.

## Sumário

- [Escopo e arquitetura](#escopo-e-arquitetura)
- [Protocolos e fluxo dos dados](#protocolos-e-fluxo-dos-dados)
- [Instalação com Docker Compose](#instalação-com-docker-compose)
- [Criar usuários e permissões](#criar-usuários-e-permissões)
- [Conectar fontes de alertas e o SIEM](#conectar-fontes-de-alertas-e-o-siem)
- [Usar a interface](#usar-a-interface)
- [Tarefas por regra](#tarefas-por-regra)
- [Avaliação local com Ollama](#avaliação-local-com-ollama)
- [API, segurança e operação](#api-segurança-e-operação)
- [Desenvolvimento e testes](#desenvolvimento-e-testes)
- [Importar casos de um console legado](#importar-casos-de-um-console-legado)
- [Limitações atuais](#limitações-atuais)

## Escopo e arquitetura

| Camada | Responsabilidade |
|---|---|
| `frontend/` | Login, fila, incidente com abas Tasks e War Room, aprovações |
| `backend/cmd/api` | API HTTP, ingestão periódica no perfil `edge`, migrações e comandos de operação |
| `backend/internal/ingestion` | Coleta, cursor durável, mapeamento, deduplicação, supressão e criação de incidentes |
| `backend/internal/casework` | Tarefas obrigatórias, conclusão e notas |
| `backend/internal/assessment` | Extração determinística de evidências e avaliação opcional por LLM local |
| `backend/internal/response` | Catálogo, planejamento, aprovação, execução e auditoria de ações |
| PostgreSQL | Incidentes, alertas, fontes, sessões, avaliações, tarefas, aprovações, auditoria e outbox |
| `content-packs/elastic-siem` | Manifesto e adapter da integração Elastic Security; regras de pré-processamento |

Nesta versão, o conector **implementado** é `elastic-siem` em modo *pull*. O
projeto **não recebe logs brutos diretamente**: agentes/coletores enviam logs ao
SIEM, as regras de detecção do Elastic produzem alertas, e o SOAR consulta esses
alertas. A interface das capturas do QRadar serve de inspiração visual; **não há
conector QRadar compilado**. Não suponha suporte a outras fontes apenas porque
o esquema de banco admite outros tipos de conector.

## Protocolos e fluxo dos dados

```text
Agente/Beat/Elastic Agent → Elasticsearch → regra de detecção → índice de alertas
                                                               ↓ HTTPS/REST, pull
                                                       SOAR (Go) → PostgreSQL
                                                          ↓          ↓
                                                  Angular/HTTP   auditoria/outbox
                                                          ↓
                                               plano → aprovação → Kibana/Elastic
```

1. O conector faz `POST /<índice>/_search` no Elasticsearch, por padrão em
   `.alerts-security.alerts-*`. O primeiro ciclo lê uma janela limitada
   (`first_fetch`, padrão `24h`); depois usa cursor por timestamp e IDs vistos.
2. O lote é aceito de modo durável **antes** de avançar o cursor. Repetições
   podem ocorrer após falhas, mas a chave externa única deduplica os alertas.
   Alertas que não podem ser mapeados são colocados em quarentena.
3. A regra de detecção, o host e a entidade formam o fingerprint do incidente.
   Novos alertas do mesmo grupo incrementam o contador, em vez de criarem um
   incidente por evento. Regras de pré-processamento podem etiquetar ou
   suprimir; `drop` conserva o alerta e registra a razão.
4. A UI usa HTTP/JSON em `/api/v1`. Respostas vêm em
   `{ "data": ..., "meta": ..., "request_id": ... }`. O contrato está em
   [api/openapi.yaml](api/openapi.yaml). Login cria cookie de sessão HttpOnly;
   mutações exigem também o token CSRF. Mudanças versionadas usam `If-Match` ou
   `expected_version`; execução externa exige `Idempotency-Key`.
5. A extração de evidências e IOCs em `GET /incidents/{id}/evidence` independe
   do Ollama. Quando habilitada, a avaliação por IA consome `incident.created`
   da outbox, faz dois passes e grava um artefato imutável. O modelo não fecha
   casos nem executa ações.
6. Uma ação externa segue **planejar → revisar impacto → aprovar/recusar →
   revalidar o plano → executar → auditar**. O plano possui fingerprint e prazo;
   se o escopo mudar, a execução é recusada. Fechar o incidente **no SOAR** e
   fechar alertas **no SIEM** são operações distintas.

O War Room é a projeção cronológica dos fatos registrados. A trilha de
auditoria e a timeline são append-only e gravadas pelo mesmo escritor.

## Instalação com Docker Compose

### Pré-requisitos

- Docker Engine com Compose v2; acesso às imagens `postgres:18-alpine`, Go,
  Node e Nginx usadas nos Dockerfiles.
- Pelo menos uma rede Docker externa para o serviço `api`. Se o SIEM estiver
  em Docker, use a rede em que Elasticsearch e Kibana estão conectados.
- Para desenvolvimento sem SIEM, crie uma rede vazia; a UI sobe, mas não haverá
  ingestão nem ações reais. O SOAR não cria um Elasticsearch automaticamente.
- Uma porta local livre para a UI (`8088` por padrão) e para o banco (`5433`).

```bash
# Na raiz do repositório
cp .env.example .env
docker network create soar-siem-local
```

Edite o `.env` e defina, no mínimo, uma senha forte em `POSTGRES_PASSWORD`,
um valor aleatório em `SOAR_CURSOR_SECRET` e
`SOAR_SIEM_NETWORK=soar-siem-local`. Para gerar o segredo do cursor, use
`openssl rand -base64 48`. O `.env` é ignorado pelo Git; **não o publique**.
Se o Elastic já usa uma rede externa, use o nome dela e não crie a rede vazia.

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8088/healthz
```

Abra `http://localhost:8088`. A API aplica as migrações ao iniciar; PostgreSQL
usa um volume no diretório indicado por `SOAR_PGDATA` (padrão:
`~/.local/share/soar/pg`). O Compose publica UI e banco **somente no loopback**.
O arquivo de exemplo usa `SOAR_ENV=development` para HTTP local. Em um serviço
remoto, use HTTPS na borda, `SOAR_ENV=production` e controles de acesso à rede;
não exponha a porta 8088 diretamente à Internet.

```bash
docker compose logs --tail=100 api       # erros de startup, migration e ingestão
docker compose up -d --build api frontend # atualizar somente a aplicação
docker compose stop                       # parar sem apagar dados
```

Não use `docker compose down -v` para uma atualização: isso removeria volumes.
Se a UI continuar antiga após um rebuild, faça atualização forçada no navegador
(`Ctrl+Shift+R`) e confira `docker compose ps`.

### Desenvolvimento sem a stack completa

`make db-up` inicia um PostgreSQL local com credencial **apenas de
desenvolvimento**. Com Go 1.27 e Node 24 instalados:

```bash
make db-up
make api    # API em 127.0.0.1:8081
make web    # Angular em http://localhost:4300, com proxy para a API
```

O servidor Angular pode escutar em IPv6 (`[::1]`): prefira `localhost:4300` a
`127.0.0.1:4300`. O `Makefile` não substitui a configuração de produção.

## Criar usuários e permissões

Não existe usuário com senha fixa no repositório. Depois de subir o banco,
provisione o primeiro administrador pela CLI. A senha não vai no argumento do
processo nem no histórico do shell:

```bash
read -rsp 'Senha (mínimo 12 caracteres): ' SOAR_NEW_PASSWORD; echo
export SOAR_BOOTSTRAP_PASSWORD="$SOAR_NEW_PASSWORD"
docker compose run --rm --no-deps -e SOAR_BOOTSTRAP_PASSWORD api \
  -create-user 'admin@example.test:admin'
unset SOAR_BOOTSTRAP_PASSWORD SOAR_NEW_PASSWORD
```

Troque o e-mail de exemplo. Repita com outro `email:papel` para criar contas;
repetir com o mesmo e-mail **redefine a senha e substitui o papel anterior**.
Não há tela de administração de usuários nesta versão. Para desenvolvimento
nativo, execute `go run ./cmd/api -create-user 'email:papel'` dentro de
`backend/`, com `SOAR_DATABASE_URL` e `SOAR_BOOTSTRAP_PASSWORD` definidos.

| Papel | Uso principal |
|---|---|
| `analyst_l1` | Ler/atribuir incidentes, concluir tarefas e escrever notas; não fecha casos |
| `analyst_l2` | Investigação, fechamento, avaliação, aprovação e ações Elastic |
| `manager` | Gestão e auditoria; possui permissões de caso, mas não execução de resposta Elastic por padrão |
| `auditor` | Leitura, sem mutações |
| `admin` | Todas as permissões cadastradas, inclusive integração e resposta |

Os papéis exatos e as permissões estão em
[0004_reference_iam.up.sql](backend/migrations/0004_reference_iam.up.sql).
Permissão modelada não significa recurso implementado: por exemplo, ainda não
há endpoint para pular tarefa obrigatória. Faça login pela UI; a sessão usa
cookies, expira e pode ser encerrada com logout.

## Conectar fontes de alertas e o SIEM

Há **duas configurações independentes**: uma *fonte* de leitura no
Elasticsearch (ingestão) e um *asset* de resposta no Kibana (planejamento e
execução). Uma pode funcionar sem a outra. Configuração de fonte/asset vive no
banco, não no Compose; reiniciar a API não a apaga.

### 1. Logs e detecções no Elastic

Configure os agentes e coletores de logs **no próprio Elastic**, com campos
ECS e regras de detecção ativas. O SOAR precisa ler os documentos de alerta
com, no mínimo, identificador estável, `@timestamp` e
`kibana.alert.rule.name`; os campos `host.name`, `source.ip`,
`process.executable`, `user.name` e `kibana.alert.severity` melhoram o
agrupamento. O conector não instala Elastic Agent, não recebe syslog e não
cria regras de detecção no SIEM.

As permissões da conta Elastic devem permitir leitura e busca no índice de
alertas. Coloque a credencial em `ELASTIC_AUTH` no `.env`, no formato
`usuario:senha`, `ApiKey <valor>` ou `Bearer <valor>`; reinicie a API para que
a variável entre no contêiner. **Não** inclua senha em `config.elastic_url`.

```bash
# Depois de editar .env e conectar o Elastic à rede SOAR_SIEM_NETWORK:
docker compose up -d --no-deps --force-recreate api
docker compose exec api /api -configure-source \
  'slug=elastic-security,kind=elastic-siem,mode=pull,enabled=true,incident_type=generic,config.elastic_url=http://elasticsearch:9200,config.auth_ref=env://ELASTIC_AUTH,config.index=.alerts-security.alerts-*,config.first_fetch=24h'
```

Substitua o hostname e o índice pelo ambiente real. `first_fetch` aceita
duração Go (`30m`, `24h`, `168h`) e limita a primeira coleta. A ingestão roda
no startup e depois a cada `SOAR_INGEST_INTERVAL_SECONDS` (padrão: 60). Um
batch busca no máximo 200 alertas; o cursor persiste no PostgreSQL.
`SOAR_INGEST_ENABLED=false` desliga o laço sem desligar a API. Para testar a
conectividade do mesmo ponto de rede da API, use os logs do conector ou um
contêiner diagnóstico temporário na mesma rede; `127.0.0.1` do host não é
`127.0.0.1` do contêiner.

O protocolo desta fonte é HTTP(S) da API Elasticsearch. Se o Elastic só escuta
no loopback do host, `host.docker.internal` sozinho não resolve o acesso:
conecte os contêineres à mesma rede ou configure uma ponte restrita. Em redes
fora do host, exija TLS e valide a cadeia de certificados.

### 2. Ações de resposta no Kibana

Para planejar e aplicar ações, configure `KIBANA_AUTH` como `usuario:senha` no
`.env`. A conta precisa acessar as APIs de regras/exceções do Kibana e contar
alertas no Elasticsearch. Nesta versão, **o mesmo Basic Auth** é usado nos
dois endpoints do asset; não configure contas com permissões de escrita além
do necessário. Reinicie a API após mudar a variável:

```bash
docker compose up -d --no-deps --force-recreate api
docker compose exec api /api -configure-asset \
  'integration=elastic-siem,endpoint=http://kibana:5601,cred=env://KIBANA_AUTH,config.elastic_url=http://elasticsearch:9200'
```

O banco armazena a referência `env://KIBANA_AUTH`, não a senha. O catálogo do
pack está em [integration.yaml](content-packs/elastic-siem/integration.yaml).
As ações implementadas são `close_alerts`, `create_exception` e a leitura
`find_rule`. `isolate_host` aparece indisponível de propósito: não há adapter
de contenção neste deploy.

### 3. Supressão e regras de pré-processamento

Os arquivos em `content-packs/*/rules/*.yaml` são instalados **desligados**.
Antes de ativar uma regra, faça dry-run contra uma amostra dos alertas já
ingeridos, revise os casamentos e a validade `expires_at`:

```bash
docker compose exec api /api -dry-run-rule example-noop
docker compose exec api /api -dry-run-rule example-noop -enable
```

O primeiro comando apenas mede; o segundo mede novamente e habilita. A regra
`example-noop` é um modelo inofensivo: ajuste os campos ao seu ambiente antes
de usá-la. Não habilite uma regra de supressão sem conferir os alertas que
seriam afetados. `drop` não elimina o registro bruto: a supressão permanece
rastreável.

## Usar a interface

1. Em **Fila**, escolha “Todos os incidentes abertos”, um estado específico ou
   “Todos os incidentes”. A lista é paginada; “Carregar mais” busca a próxima
   página. Abrir uma linha leva ao incidente.
2. A aba **Tasks** mostra fases e progresso. Abra uma tarefa para ler a
   instrução, enviar notas em **Notes** e marcá-la concluída. Tarefas
   obrigatórias pendentes bloqueiam o fechamento do incidente no SOAR.
3. A aba **War Room** reúne evidências/IOCs extraídos sem IA, avaliações locais
   quando existirem, ações guiadas e timeline auditável. Ausência de hit em
   feed não é prova de benignidade.
4. Em **Ações**, escolha uma ação. Regra, host, entidade e observáveis são
   sugeridos pelo caso quando disponíveis, mas são **proposta editável**, não
   decisão automática. Confira o número de alertas e o filtro no plano. A
   aprovação inline permite responder sim/não; a fila **Aprovações** permite
   revisar pedidos pendentes separadamente.
5. Fechar o **incidente SOAR** exige resolução e motivo. Isso não equivale a
   fechar os alertas correspondentes no Elastic; use a ação própria do SIEM
   quando necessário. A avaliação da IA também não fecha o caso sozinha.

**Atenção ao escopo:** se host e entidade não estiverem presentes, o plano de
`close_alerts` pode usar somente o nome da regra e alcançar alertas de outros
hosts. Reveja a contagem e não aprove um plano amplo inesperado. A exceção
Elastic atual aceita **um único par campo/valor** por plano; ela vale para a
regra escolhida e não fecha alertas antigos.

## Tarefas por regra

A migration `0015_case_tasks` materializa três tarefas obrigatórias por
incidente aberto, selecionando um roteiro para disponibilidade, autenticação,
malware/processo, rede/DNS, web ou geral. Incidentes já fechados não são
reabertos. Notas de tarefa são append-only e também entram na timeline. O
roteiro é escolhido na criação do incidente; alterar regras depois **não
reescreve tarefas em andamento**.

O mapeamento configurável está em `incident.task_rules` (regex sobre
`source_rule` ou título; menor `priority` vence) e os passos em
`incident.task_templates`. Para uma regra específica, use uma categoria
exclusiva e um padrão ancorado, executando SQL com uma conta administrativa:

```sql
INSERT INTO incident.task_templates
  (category, phase, title, instruction, position, mandatory)
VALUES
  ('minha-regra', 'Apropriação', 'Validar escopo', 'Confirme ativo e janela.', 10, true),
  ('minha-regra', 'Análise', 'Confirmar impacto', 'Registre evidências nas notas.', 20, true);

INSERT INTO incident.task_rules (pattern, category, priority)
VALUES ('^Minha Regra Exata$', 'minha-regra', 1);
```

Revise conflitos com padrões existentes antes de alterar produção. Não há
editor visual de roteiros nem motor de playbooks nesta versão.

## Avaliação local com Ollama

O recurso é **opcional e desligado por padrão** (`SOAR_ASSESSMENT_ENABLED=false`).
Configure um servidor Ollama acessível **pela API**, o nome de um modelo
disponível no servidor e `SOAR_OLLAMA_NUM_CTX` de pelo menos 4096. No Compose,
`127.0.0.1` aponta para o contêiner, não para o host. Use uma ponte/rede
restrita, sem abrir o modelo à Internet. Exemplo de variáveis no `.env`:

```dotenv
SOAR_ASSESSMENT_ENABLED=true
SOAR_OLLAMA_URL=http://host.docker.internal:11434
SOAR_OLLAMA_MODEL=qwen3:8b
SOAR_OLLAMA_NUM_CTX=8192
SOAR_OLLAMA_TIMEOUT_SECONDS=240
```

Após editar, recrie a API com `docker compose up -d --no-deps --force-recreate
api`. `SOAR_ASSESSMENT_ELASTIC_URL` é opcional para correlação adicional; sem
ela, o artefato registra a lacuna. A avaliação faz dois passes e pode levar
minutos. Não é necessário esperar para usar tarefas, evidências, IOCs ou ações.
Para acompanhar pelo próprio terminal, sem manter o cliente deste assistente
esperando, use `docker compose logs -f --tail=100 api`.

O portão de qualidade do modelo Go contra o baseline Python ainda está em
validação; portanto a saída do modelo deve ser revisada por um humano antes
de qualquer promoção. O corpus e o harness são material de avaliação, não
autorização para executar respostas automaticamente.

O corpus de avaliação com telemetria de laboratório é **privado e não faz
parte da distribuição pública**. Os testes Golden que dependem dele são
ignorados quando ele não está presente; os demais testes continuam ativos.

## API, segurança e operação

- Contrato HTTP: [api/openapi.yaml](api/openapi.yaml). Rotas principais:
  `/api/v1/auth/*`, `/api/v1/incidents`, `/api/v1/incidents/{id}`,
  `/tasks`, `/evidence`, `/assessments`, `/timeline`, `/actions` e
  `/api/v1/approvals`.
- Autenticação local: senha com Argon2id; cookie HttpOnly e token CSRF
  vinculado à sessão. RBAC é verificado no backend, não só pelo botão da UI.
- Auditoria e timeline são append-only. Aprovações têm expiração; ação externa
  usa plano revalidado, chave de idempotência e registro de resultado.
- `GET /health/live` verifica processo; `GET /health/ready` verifica banco.
  No Compose, Nginx publica `/healthz` no frontend. Consulte
  `docker compose ps` e `docker compose logs --tail=100 api` para diagnóstico.
- O banco é persistente. Faça backup regular fora do repositório, teste a
  restauração e aplique migrações antes de servir uma nova versão. Não copie
  dumps, `.env`, credenciais nem telemetria real para um repositório público.
- `SOAR_LOG_LEVEL`, `SOAR_DB_MAX_CONNS`, `SOAR_INGEST_INTERVAL_SECONDS`,
  `SOAR_DEDUPE_WINDOW_HOURS` e `SOAR_APPROVAL_TTL_MINUTES` ajustam operação;
  os padrões estão em [config.go](backend/internal/platform/config/config.go).
- A implementação de `standard`/`scale`, conectores push/agente, gestão
  multi-tenant e contenção automática **não está pronta**; o perfil operacional
  implementado é `edge`.

### Problemas comuns

| Sintoma | Verificação |
|---|---|
| `docker compose up` falha pela rede | Crie a rede externa ou ajuste `SOAR_SIEM_NETWORK`; não exponha o SIEM para resolver isso. |
| Fonte não cria incidentes | Confira `enabled=true`, índice, credencial, regra de detecção, janela `first_fetch` e logs da API. |
| `401` / login falha | Provisione usuário, confira senha e ambiente HTTP local versus HTTPS de produção. |
| `403` ao mutar | Verifique papel/permissão e token CSRF; não desative o controle para contornar erro. |
| Ações não aparecem ou plano falha | Confira content pack, asset, `KIBANA_AUTH`, DNS e permissões das APIs Elastic/Kibana. |
| UI antiga depois de alterar código | Reconstrua API/frontend e atualize o navegador sem cache. |
| Incidente não fecha | Abra Tasks: todas as tarefas obrigatórias precisam estar concluídas. |
| Avaliação não aparece | Confira `SOAR_ASSESSMENT_ENABLED`, rota para o Ollama e logs; IOCs não dependem dela. |

## Desenvolvimento e testes

```bash
make test       # Go com -race + testes Angular
make lint       # go vet + typecheck
make types      # regenera frontend/src/app/core/api/schema.d.ts
docker compose config --quiet
```

O CI valida testes com PostgreSQL 18, contrato OpenAPI, formato/lint, imagens,
segurança e manifests Kubernetes. O teste de integração Go contra banco real
requer `SOAR_INTEGRATION_TEST=1` e um banco **descartável**. Não aponte testes
destrutivos para o banco de produção. Manifests para k3s estão em `deploy/k8s/`;
o Compose é a forma suportada aqui para o perfil `edge`.

## Importar casos de um console legado

Se houver os três arquivos JSON do console Python anterior, o importador em
`backend/cmd/import-legacy` cria incidentes, avaliações e eventos de auditoria
sem duplicar casos já importados. Não armazene esses arquivos no repositório
público; são dados operacionais. Faça backup do banco e rode a importação em
janela controlada:

```bash
cd backend
go run ./cmd/import-legacy \
  --assessments /caminho/privado/assessments.json \
  --cases /caminho/privado/cases.json \
  --labels /caminho/privado/labels.json
```

O comando presume `SOAR_DATABASE_URL` já definido; não use uma URL com senha
literal no histórico do shell. Carregue a variável de ambiente de um
gerenciador de segredos. O importador não instala nem executa o console antigo.

## Limitações atuais

- Apenas alertas de detecção Elastic Security são coletados. QRadar, syslog,
  webhook, agentes e coletores de log não possuem conector funcional aqui.
- O fluxo de exceção permite um par ECS campo/valor por item; combinações de
  vários artefatos ainda não são editadas como uma única exceção.
- A seleção de alvo/escopo é uma proposta; exige julgamento humano. Não há
  bloqueio automático para plano amplo baseado só em nome de regra.
- Roteiros são configuráveis por SQL, não por UI. Pular tarefa obrigatória,
  SLA, automações genéricas e playbooks ainda não estão implementados.
- A avaliação local por IA é experimental e não substitui verificação de
  evidências, autorização ou aprovação de ações.
