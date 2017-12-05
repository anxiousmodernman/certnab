package certnab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ericchiang/letsencrypt"
)

var supportedChallenges = []string{
	letsencrypt.ChallengeHTTP,
}

var (
	leEnv = flag.String("le-env", "stage", "Let's Encrypt server; one of: stage, prod")
)

func GetCerts() {
	flag.Parse()

	var acmeServer string

	switch *leEnv {
	case "prod":
		acmeServer = "https://acme-v01.api.letsencrypt.org/directory"
	case "stage":
		acmeServer = "https://acme-staging.api.letsencrypt.org/directory"
	default:
		acmeServer = "https://acme-staging.api.letsencrypt.org/directory"
	}
	cli, err := letsencrypt.NewClient("https://acme-staging.api.letsencrypt.org/directory")
	if err != nil {
		log.Fatal("failed to create client:", err)
	}

	_ = acmeServer

	// Create a private key for your account and register
	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := cli.NewRegistration(accountKey); err != nil {
		log.Fatal("new registration failed:", err)
	}

	// ask for a set of challenges for a given domain
	auth, _, err := cli.NewAuthorization(accountKey, "dns", "dev.coleman.codes")
	if err != nil {
		log.Fatal(err)
	}
	chals := auth.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		log.Fatal("no supported challenge combinations")
	}
	chal := chals[0][0]

	path, resource, err := chal.HTTP(accountKey)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		// Listen on HTTP for a request at the given path.
		hf := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, resource)
		}
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(hf)))
	}()

	// Tell the server the challenge is ready and poll the server for updates.
	if err := cli.ChallengeReady(accountKey, chal); err != nil {
		// oh no, you failed the challenge
		log.Fatal(err)
	}
	csr, certKey, err := newCSR()
	if err != nil {
		log.Fatal(err)
	}

	// Request a certificate for your domain
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = cert, certKey

	// Bundle is a convenience method to get the []byte we write to disk
	pemCert, err := cli.Bundle(cert)
	if err != nil {
		log.Fatal(err)
	}

	err = ioutil.WriteFile("cert.pem", pemCert, 0755)
	if err != nil {
		log.Fatal(err)
	}

	pemKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certKey),
		},
	)

	err = ioutil.WriteFile("key.pem", pemKey, 0755)
	if err != nil {
		log.Fatal(err)
	}
}

func newCSR() (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: "dev.coleman.codes"},
		DNSNames:           []string{"dev.coleman.codes"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}
