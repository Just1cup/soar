package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC)

func TestLimiterBucketsAreIndependent(t *testing.T) {
	// Um balde combinado "IP|conta" deixaria um IP espalhar uma senha por
	// contas ilimitadas; um balde só por IP deixaria um usuário travar todo
	// mundo atrás de um proxy corporativo. Por isso são dois.
	l := NewLoginLimiter(3, 100, time.Minute)

	for i := range 3 {
		if !l.Allow("10.0.0.1", "alvo@soar.local", t0) {
			t.Fatalf("tentativa %d deveria passar", i)
		}
	}
	if l.Allow("10.0.0.2", "alvo@soar.local", t0) {
		t.Fatal("a conta estourou o limite; trocar de IP não deveria ajudar")
	}
	if !l.Allow("10.0.0.2", "outra@soar.local", t0) {
		t.Fatal("outra conta no mesmo IP não deveria estar bloqueada")
	}
}

func TestLimiterSourceBucketCapsSpray(t *testing.T) {
	l := NewLoginLimiter(100, 3, time.Minute)
	for i := range 3 {
		if !l.Allow("203.0.113.9", fmtAccount(i), t0) {
			t.Fatalf("tentativa %d deveria passar", i)
		}
	}
	if l.Allow("203.0.113.9", "quarta@soar.local", t0) {
		t.Fatal("o IP estourou o limite; trocar de conta não deveria ajudar")
	}
}

func TestLimiterWindowRolls(t *testing.T) {
	l := NewLoginLimiter(2, 100, time.Minute)
	l.Allow("10.0.0.1", "a@b.c", t0)
	l.Allow("10.0.0.1", "a@b.c", t0)
	if l.Allow("10.0.0.1", "a@b.c", t0.Add(59*time.Second)) {
		t.Fatal("ainda dentro da janela")
	}
	if !l.Allow("10.0.0.1", "a@b.c", t0.Add(time.Minute)) {
		t.Fatal("a janela deveria ter virado")
	}
}

func TestResetForgivesAccountButNotSource(t *testing.T) {
	l := NewLoginLimiter(2, 3, time.Minute)
	l.Allow("10.0.0.1", "a@b.c", t0)
	l.Allow("10.0.0.1", "a@b.c", t0)
	l.ResetAccount("A@B.C") // e-mail é case-insensitive
	if !l.Allow("10.0.0.1", "a@b.c", t0) {
		t.Fatal("login válido deveria perdoar o balde da conta")
	}
	// O balde do IP continua contando: ciclar por uma conta boa não pode
	// apagar a evidência de uma rajada de credential stuffing.
	if l.Allow("10.0.0.1", "outra@b.c", t0) {
		t.Fatal("o balde do IP deveria ter sido preservado")
	}
}

// O mapa cresce com chaves distintas. Sem poda, o próprio limitador vira o
// vetor de exaustão de memória que ele existe para conter.
func TestLimiterMemoryIsBounded(t *testing.T) {
	l := NewLoginLimiter(5, 1_000_000, time.Minute)
	for i := range 200_000 {
		l.Allow("10.0.0.1", fmtAccount(i), t0)
	}
	if n := l.account.size(); n > hardCap {
		t.Fatalf("mapa de contas cresceu sem limite: %d entradas", n)
	}

	// E entradas vencidas somem na primeira chamada depois da janela, mesmo
	// sem pressão de tamanho: um sistema que ficou ocioso depois de uma
	// rajada não deve segurar o mapa inteiro.
	l2 := NewLoginLimiter(5, 1_000_000, time.Minute)
	for i := range 500 {
		l2.Allow("10.0.0.1", fmtAccount(i), t0)
	}
	l2.Allow("10.0.0.1", "gatilho@soar.local", t0.Add(2*time.Minute))
	if n := l2.account.size(); n != 1 {
		t.Fatalf("entradas vencidas não foram podadas: %d restaram", n)
	}
}

func TestClientIPTrustsProxyOnlyFromPrivatePeer(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		realIP     string
		want       string
	}{
		{"sem header", "192.0.2.10:5555", "", "192.0.2.10"},
		{"peer loopback confia no proxy", "127.0.0.1:5555", "198.51.100.7", "198.51.100.7"},
		{"peer privado confia no proxy", "10.1.2.3:5555", "198.51.100.7", "198.51.100.7"},
		// O caso que importa: um cliente público falando direto com a API não
		// pode escolher a chave do próprio rate limit.
		{"peer publico ignora o header", "203.0.113.5:5555", "127.0.0.1", "203.0.113.5"},
		{"header lixo cai no peer", "127.0.0.1:5555", "nao-e-ip", "127.0.0.1"},
		{"header vazio cai no peer", "127.0.0.1:5555", "   ", "127.0.0.1"},
		{"remoteaddr sem porta", "sem-porta", "198.51.100.7", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
			r.RemoteAddr = c.remoteAddr
			if c.realIP != "" {
				r.Header.Set("X-Real-IP", c.realIP)
			}
			if got := clientIP(r); got != c.want {
				t.Fatalf("clientIP = %q, want %q", got, c.want)
			}
		})
	}
}

func fmtAccount(i int) string {
	return "conta" + itoa(i) + "@soar.local"
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
