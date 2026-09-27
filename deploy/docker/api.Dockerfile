# syntax=docker/dockerfile:1.7
# Orçamento: <= 25 MB (docs/soar/03 §14.1).

FROM golang:1.27-alpine AS build
WORKDIR /src
# Dependências primeiro: mudar código não invalida o download.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/api ./cmd/api

# distroless static: sem shell, sem gerenciador de pacotes, sem busybox.
# Um atacante que consiga executar comando aqui não tem com o que executá-lo.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/api"]
