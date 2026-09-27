package auth

import "testing"

func TestPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("uma senha longa e unica")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyPassword("uma senha longa e unica", hash)
	if err != nil || !ok {
		t.Fatalf("senha correta recusada: ok=%v err=%v", ok, err)
	}
	ok, err = VerifyPassword("senha errada", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("senha errada aceita")
	}
}

func TestCSRFIsBoundToSession(t *testing.T) {
	token := "token-csrf-da-sessao"
	session := &Session{CSRFHash: HashToken(token)}
	if !ValidCSRF(session, token, token) {
		t.Fatal("token correto foi recusado")
	}
	for _, tc := range []struct{ cookie, header string }{
		{"outro", token}, {token, "outro"}, {"", token}, {token, ""},
	} {
		if ValidCSRF(session, tc.cookie, tc.header) {
			t.Fatalf("par inválido aceito: cookie=%q header=%q", tc.cookie, tc.header)
		}
	}
}
