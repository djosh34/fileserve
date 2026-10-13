package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	for _, value := range []string{"", " ", "alice,", ",alice", "alice,,bob"} {
		if _, err := parseAllow(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	allowed, err := parseAllow(" alice , Bob ")
	if err != nil || !allowed["alice"] || !allowed["Bob"] || allowed["bob"] {
		t.Fatalf("allowlist: %v, %v", allowed, err)
	}
}

func TestCLIAndSetup(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"--help"}, &output); err != nil || !strings.Contains(output.String(), ":8443") {
		t.Fatalf("help: %v, %s", err, &output)
	}
	for _, args := range [][]string{nil, {"--unknown"}, {"extra"}, {"--allow", "alice"}} {
		if err := run(args, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	pki := makePKI(t)
	cert, key := pki.issue(t, "server", "localhost", x509.ExtKeyUsageServerAuth)
	data := filepath.Join(t.TempDir(), "data")
	mustWrite(t, data, []byte("hello"))
	args := []string{"--allow", "alice", "--file", data, "--cacert", pki.caPath, "--cert", cert, "--key", key, "--listen", "bad address"}
	for _, test := range []struct {
		index       int
		value, want string
	}{
		{1, "alice,", "--allow"}, {3, filepath.Dir(data), "regular file"},
		{3, data + "missing", "open file"}, {5, data, "no certificates"},
		{5, data + "missing", "read client CA"}, {7, data, "load server"},
		{9, data, "load server"}, {11, "bad address", "address"},
	} {
		copyArgs := append([]string(nil), args...)
		copyArgs[test.index] = test.value
		if err := run(copyArgs, io.Discard); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%v: %v (want %s)", copyArgs, err, test.want)
		}
	}
}

func TestHandler(t *testing.T) {
	data := bytes.Repeat([]byte("file\x00bytes\n"), 10000)
	path := filepath.Join(t.TempDir(), "data")
	mustWrite(t, path, data)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	handler := fileHandler(file, log.New(io.Discard, "", 0))
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/", 200}, {"GET", "/?query=yes", 200}, {"GET", "/other", 404},
		{"GET", "//", 404}, {"HEAD", "/", 404}, {"POST", "/", 404},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.status {
			t.Errorf("%v: %d", test, w.Code)
		}
		if test.status == 200 && !bytes.Equal(w.Body.Bytes(), data) {
			t.Errorf("%v: wrong bytes", test)
		}
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			for range 3 {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
				if !bytes.Equal(w.Body.Bytes(), data) {
					t.Error("incomplete concurrent transfer")
				}
			}
		})
	}
	wg.Wait()
	// Replacing the pathname must not change the already-open file.
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, path, []byte("replacement"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !bytes.Equal(w.Body.Bytes(), data) {
		t.Fatal("reopened the file")
	}
}

type brokenFile struct {
	seekError bool
	sent      bool
	fail      bool
}

func (f *brokenFile) Seek(int64, int) (int64, error) {
	f.sent = false
	if f.seekError {
		return 0, errors.New("seek failed")
	}
	return 0, nil
}
func (f *brokenFile) Read(p []byte) (int, error) {
	if f.sent {
		if f.fail {
			return 0, errors.New("read failed")
		}
		return 0, io.EOF
	}
	f.sent = true
	return copy(p, bytes.Repeat([]byte("x"), 8192)), nil
}

func TestTransferErrors(t *testing.T) {
	var logs bytes.Buffer
	file := &brokenFile{seekError: true}
	handler := fileHandler(file, log.New(&logs, "", 0))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 || !strings.Contains(logs.String(), "seek failed") {
		t.Fatal("seek failure not reported")
	}
	file.seekError = false
	file.fail = true
	server := httptest.NewServer(handler)
	defer server.Close()
	response, err := server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(response.Body)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if readErr == nil {
		t.Fatal("partial stream reported as complete")
	}
	// Wait until the failed handler has released the mutex before changing the fake.
	// The next request exercises that same mutex and must finish.
	response, err = server.Client().Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.ReadAll(response.Body)
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if readErr == nil {
		t.Fatal("second partial stream reported as complete")
	}
}

type testPKI struct {
	ca     *x509.Certificate
	key    *ecdsa.PrivateKey
	caPath string
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func makePKI(t *testing.T) testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	mustWrite(t, path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return testPKI{ca, key, path}
}
func (p testPKI) issue(t *testing.T, cn, san string, usage x509.ExtKeyUsage) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, DNSNames: []string{san}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, cert, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	mustWrite(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	mustWrite(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func TestTLSCommonName(t *testing.T) {
	pki := makePKI(t)
	cert, key := pki.issue(t, "server", "localhost", x509.ExtKeyUsageServerAuth)
	config, err := clientTLS(pki.caPath, cert, key, map[string]bool{"alice": true})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	server.TLS = config
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(pki.ca)
	other := makePKI(t)
	for _, test := range []struct {
		name, cn, san string
		issuer        testPKI
		usage         x509.ExtKeyUsage
		allowed       bool
	}{
		{"allowed unrelated SAN", "alice", "unrelated", pki, x509.ExtKeyUsageClientAuth, true},
		{"SAN is not CN", "bob", "alice", pki, x509.ExtKeyUsageClientAuth, false},
		{"case sensitive", "Alice", "alice", pki, x509.ExtKeyUsageClientAuth, false},
		{"untrusted", "alice", "alice", other, x509.ExtKeyUsageClientAuth, false},
		{"wrong usage", "alice", "alice", pki, x509.ExtKeyUsageServerAuth, false},
		{"missing", "", "", pki, x509.ExtKeyUsageClientAuth, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: roots, ServerName: "localhost"}
			if test.cn != "" {
				certPath, keyPath := test.issuer.issue(t, test.cn, test.san, test.usage)
				pair, err := tls.LoadX509KeyPair(certPath, keyPath)
				if err != nil {
					t.Fatal(err)
				}
				cfg.Certificates = []tls.Certificate{pair}
			}
			transport := &http.Transport{TLSClientConfig: cfg}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			response, err := client.Get(server.URL)
			if response != nil {
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if (err == nil) != test.allowed {
				t.Fatalf("allowed=%v, err=%v", test.allowed, err)
			}
		})
	}
}
