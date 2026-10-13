package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		log.Fatal(err)
	}
}

func run(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("fileserve", flag.ContinueOnError)
	flags.SetOutput(stderr)
	allow := flags.String("allow", "", "comma-separated allowed client certificate Common Names")
	path := flags.String("file", "", "regular file to serve")
	ca := flags.String("cacert", "", "trusted client CA PEM file")
	cert := flags.String("cert", "", "server certificate PEM file")
	key := flags.String("key", "", "server private key PEM file")
	listen := flags.String("listen", ":8443", "HTTPS listening address")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *allow == "" || *path == "" || *ca == "" || *cert == "" || *key == "" {
		return errors.New("--allow, --file, --cacert, --cert and --key are required")
	}
	allowed, err := parseAllow(*allow)
	if err != nil {
		return err
	}
	config, err := clientTLS(*ca, *cert, *key, allowed)
	if err != nil {
		return err
	}
	file, err := os.Open(*path)
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	logger := log.New(stderr, "fileserve: ", log.LstdFlags)
	defer func() {
		if err := file.Close(); err != nil {
			logger.Printf("close file: %v", err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("--file must be a regular file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek file: %w", err)
	}
	server := &http.Server{
		Addr: *listen, TLSConfig: config,
		Handler: fileHandler(file, logger),
	}
	return server.ListenAndServeTLS("", "")
}

func parseAllow(value string) (map[string]bool, error) {
	allowed := make(map[string]bool)
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, errors.New("--allow must contain nonempty comma-separated Common Names")
		}
		allowed[entry] = true
	}
	return allowed, nil
}

func clientTLS(caPath, certPath, keyPath string, allowed map[string]bool) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("client CA file contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server certificate/key: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 || !allowed[state.VerifiedChains[0][0].Subject.CommonName] {
				return errors.New("client certificate Common Name is not allowed")
			}
			return nil
		},
	}, nil
}

func fileHandler(file io.ReadSeeker, logger *log.Logger) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			logger.Printf("seek file: %v", err)
			http.Error(w, "cannot read file", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if _, err := io.Copy(w, file); err != nil {
			logger.Printf("stream file: %v", err)
			panic(http.ErrAbortHandler)
		}
	})
}
