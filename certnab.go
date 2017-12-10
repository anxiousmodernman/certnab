package certnab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/ericchiang/letsencrypt"
)

var supportedChallenges = []string{
	letsencrypt.ChallengeHTTP,
}

// NewClient constructs our Certnab client.
func NewClient(acmeURL, dest, domain string) (*Client, error) {
	var c Client
	srv := fmt.Sprintf("https://%s/directory", acmeURL)
	cli, err := letsencrypt.NewClient(srv)
	if err != nil {
		return nil, err
	}
	c.LEClient = cli
	c.dest = dest
	c.ourDomain = domain
	return &c, nil
}

// Client wraps information we need to talk to an ACME server
// and
type Client struct {
	LEClient  *letsencrypt.Client
	dest      string
	ourDomain string
}

// HTTPChallenge binds to port 80 and serves content. This proves control over
// the server.
func (c *Client) HTTPChallenge() error {

	accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	if _, err := c.LEClient.NewRegistration(accountKey); err != nil {
		return fmt.Errorf("new registration failed: %v", err)
	}

	auth, _, err := c.LEClient.NewAuthorization(accountKey, "dns", c.ourDomain)
	if err != nil {
		return err
	}
	chals := auth.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		return errors.New("no supported challenge combinations")
	}
	if len(chals[0]) == 0 {
		return errors.New("no supported challenge combinations")
	}

	chal := chals[0][0]

	path, resource, err := chal.HTTP(accountKey)
	if err != nil {
		return err
	}

	go func() {
		// Serve the requested resource
		f := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, resource)
		}
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(f)))
	}()

	if err := c.LEClient.ChallengeReady(accountKey, chal); err != nil {
		return fmt.Errorf("challenge failed: %v", err)
	}
	csr, certKey, err := c.newCSR()
	if err != nil {
		return err
	}

	cert, err := c.LEClient.NewCertificate(accountKey, csr)
	if err != nil {
		return err
	}

	pemCert, err := c.LEClient.Bundle(cert)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("cert.pem", pemCert, 0755)
	if err != nil {
		return err
	}

	pemKey := pemEncodePrivateKey(certKey)

	err = ioutil.WriteFile("key.pem", pemKey, 0755)
	if err != nil {
		return err
	}
	return nil
}

func pemEncodePrivateKey(priv *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
}

func (c *Client) newCSR() (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: c.ourDomain},
		DNSNames:           []string{c.ourDomain},
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
