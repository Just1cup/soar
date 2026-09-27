SHELL := /bin/bash
export PATH := $(HOME)/.local/bin:$(PATH)
DB_URL ?= postgres://soar:soar_dev_only@127.0.0.1:5433/soar?sslmode=disable

.PHONY: help db-up db-down api web test test-go test-web lint fmt vet tidy types clean

help:
	@grep -E '^[a-z-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-12s %s\n", $$1, $$2}'

db-up: ## Sobe o PostgreSQL 18 com os dados no NVMe
	@mkdir -p $(HOME)/.local/share/soar/pg
	@docker start soar-postgres 2>/dev/null || docker run -d --name soar-postgres \
	  -p 127.0.0.1:5433:5432 \
	  -e POSTGRES_PASSWORD=soar_dev_only -e POSTGRES_USER=soar -e POSTGRES_DB=soar \
	  -v $(HOME)/.local/share/soar/pg:/var/lib/postgresql \
	  --shm-size=256m postgres:18-alpine -c shared_preload_libraries=pg_stat_statements
	@until docker exec soar-postgres pg_isready -U soar -d soar >/dev/null 2>&1; do sleep 1; done
	@echo "postgres pronto em 127.0.0.1:5433"

db-down: ## Para o banco (os dados ficam)
	@docker stop soar-postgres

api: ## Sobe a API (aplica migrations na partida)
	cd backend && SOAR_DATABASE_URL="$(DB_URL)" SOAR_HTTP_ADDR=127.0.0.1:8081 \
	  SOAR_ENV=development go run ./cmd/api

web: ## Sobe o frontend (proxy para a API em 8081). Escuta em [::1], use localhost.
	cd frontend && npx ng serve --port 4300

types: ## Regenera os tipos TypeScript a partir do contrato OpenAPI
	cd frontend && npm run api:types

test: test-go test-web ## Todos os testes

test-go: ## Go, com detector de corrida
	cd backend && go test ./... -race -count=1

test-web: ## Angular: unitários e de componente
	cd frontend && npx ng test --watch=false

lint: vet ## Verificações estáticas (Go + TypeScript + contrato)
	cd frontend && npm run typecheck
fmt: ; cd backend && gofmt -w .
vet: ; cd backend && go vet ./...
tidy: ; cd backend && go mod tidy

clean:
	rm -f backend/bin/* /tmp/soar-api
