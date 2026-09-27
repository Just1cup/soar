package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/platform/config"
	"github.com/titas/soar/backend/internal/platform/postgres"
)

// This test is the Phase 1 exit criterion, against a real PostgreSQL:
// HTTP + auth + RBAC + row lock + state + audit + timeline + outbox.
func TestConcurrentCloseIsAtomic(t *testing.T) {
	if os.Getenv("SOAR_INTEGRATION_TEST") != "1" {
		t.Skip("set SOAR_INTEGRATION_TEST=1 against a disposable PostgreSQL")
	}
	databaseURL := os.Getenv("SOAR_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("SOAR_DATABASE_URL ausente")
	}
	if _, err := postgres.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, databaseURL, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	suffix := uuid.NewString()
	email := "phase1-" + suffix + "@test.invalid"
	password := "integration-password-2026"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO iam.users(id,tenant_id,email,display_name,password_hash)
		VALUES($1,$2,$3,'Analista de integração',$4)`, userID, defaultTenant.UUID, email, hash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO iam.user_roles(user_id,role_id)
		SELECT $1,id FROM iam.roles WHERE tenant_id=$2 AND name='admin'`, userID, defaultTenant.UUID)
	if err != nil {
		t.Fatal(err)
	}

	incidentID := uuid.New()
	_, err = pool.Exec(ctx, `
		INSERT INTO incident.incidents
		 (id,tenant_id,key,type_id,title,status,severity,priority,fingerprint,
		  alert_count,first_seen,last_seen)
		SELECT $1,$2,$3,t.id,'Critério da Fase 1','investigating','high',2,$4,1,now(),now()
		  FROM incident.incident_types t WHERE t.tenant_id=$2 AND t.slug='generic'`,
		incidentID, defaultTenant.UUID, "TEST-"+suffix, []byte(suffix))
	if err != nil {
		t.Fatal(err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.Config{Env: "development", Profile: "edge", CursorSecret: "integration-secret"}
	handler, _, _, err := router(ctx, cfg, pool, log)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}

	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": password})
	resp, err := client.Post(server.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login HTTP %d", resp.StatusCode)
	}
	csrf := ""
	for _, cookie := range jar.Cookies(resp.Request.URL) {
		if cookie.Name == auth.CSRFCookie {
			csrf = cookie.Value
		}
	}
	if csrf == "" {
		t.Fatal("login não entregou cookie CSRF")
	}

	closeBody, _ := json.Marshal(map[string]any{
		"resolution": "true_positive", "reason": "confirmado no teste de integração", "expected_version": 1,
	})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodPost,
				fmt.Sprintf("%s/api/v1/incidents/%s/close", server.URL, incidentID), bytes.NewReader(closeBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("If-Match", `"1"`)
			req.Header.Set("X-CSRF-Token", csrf)
			res, callErr := client.Do(req)
			if callErr != nil {
				statuses <- 0
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			statuses <- res.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	got := make([]int, 0, 2)
	for status := range statuses {
		got = append(got, status)
	}
	sort.Ints(got)
	if fmt.Sprint(got) != fmt.Sprint([]int{http.StatusOK, http.StatusConflict}) {
		t.Fatalf("fechamentos concorrentes = %v, want [200 409]", got)
	}

	var status string
	var version, auditCount, timelineCount, outboxCount int
	if err := pool.QueryRow(ctx, `SELECT status,version FROM incident.incidents WHERE id=$1`, incidentID).Scan(&status, &version); err != nil {
		t.Fatal(err)
	}
	if status != "closed" || version != 2 {
		t.Fatalf("estado=%s versão=%d", status, version)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit.audit_events WHERE incident_id=$1`, incidentID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit.timeline_events WHERE incident_id=$1`, incidentID).Scan(&timelineCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM platform.outbox_events WHERE aggregate_id=$1`, incidentID).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || timelineCount != 1 || outboxCount != 2 {
		t.Fatalf("audit=%d timeline=%d outbox=%d; want 1/1/2", auditCount, timelineCount, outboxCount)
	}

	if _, err := pool.Exec(ctx, `UPDATE audit.audit_events SET reason='adulterado' WHERE incident_id=$1`, incidentID); err == nil {
		t.Fatal("UPDATE da auditoria deveria ser recusado")
	}
	partition := "audit.audit_events_" + time.Now().UTC().Format("2006_01")
	if _, err := pool.Exec(ctx, "TRUNCATE "+partition); err == nil {
		t.Fatal("TRUNCATE da partição de auditoria deveria ser recusado")
	}
}
