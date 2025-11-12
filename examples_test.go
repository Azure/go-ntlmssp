// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp_test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"

	"github.com/Azure/go-ntlmssp"
)

// Example demonstrates basic HTTPS authentication using NTLM.
// The library works the same way with HTTP - just use http:// URLs instead.
func Example() {
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set basic auth credentials - these will be automatically converted to NTLM
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
}

// Example_customTLS demonstrates HTTPS authentication with custom TLS configuration.
// Useful for self-signed certificates or custom CA certificates.
func Example_customTLS() {
	url := "https://ntlm-protected-server.example.com/resource"
	username := "DOMAIN\\username" // or "username@domain.com" for UPN format
	password := "your-password"
	caCertFile := "/path/to/ca-cert.pem" // Optional: path to CA certificate

	// Create TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Option 1: Load custom CA certificate (for self-signed certs)
	if caCertFile != "" {
		caCert, err := os.ReadFile(caCertFile)
		if err != nil {
			log.Printf("Warning: Failed to read CA certificate: %v", err)
		} else {
			caCertPool := x509.NewCertPool()
			if caCertPool.AppendCertsFromPEM(caCert) {
				tlsConfig.RootCAs = caCertPool
			}
		}
	}

	// Option 2: Skip certificate verification (NOT recommended for production!)
	// Uncomment the following line only for testing with self-signed certificates
	// tlsConfig.InsecureSkipVerify = true

	client := &http.Client{
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set basic auth credentials - these will be automatically converted to NTLM
	req.SetBasicAuth(username, password)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
}

// ntlmAuth implements smtp.Auth for NTLM authentication.
type ntlmAuth struct {
	username string
	password string
	host     string
	state    int
}

func (a *ntlmAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	a.state = 1
	_, domain, _ := ntlmssp.GetDomain(a.username)
	// Create the negotiate message
	negotiateMsg, err := ntlmssp.NewNegotiateMessage(domain, "")
	if err != nil {
		return "", nil, err
	}
	return "NTLM", negotiateMsg, nil
}

func (a *ntlmAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if a.state == 1 {
		a.state = 2
		// Process the challenge message from the server
		user, _, domainNeeded := ntlmssp.GetDomain(a.username)
		authenticateMsg, err := ntlmssp.ProcessChallenge(fromServer, user, a.password, domainNeeded)
		if err != nil {
			return nil, err
		}
		return authenticateMsg, nil
	}
	return nil, nil
}

// Example_smtp demonstrates using NTLM authentication with net/smtp.
func Example_smtp() {
	smtpServer := "mail.example.com:587"
	from := "sender@example.com"
	to := []string{"recipient@example.com"}
	username := "DOMAIN\\username"
	password := "your-password"

	// Create NTLM auth
	auth := &ntlmAuth{
		username: username,
		password: password,
		host:     smtpServer,
	}

	// Compose message
	msg := []byte("To: recipient@example.com\r\n" +
		"Subject: Test Email\r\n" +
		"\r\n" +
		"This is a test email using NTLM authentication.\r\n")

	// Send email
	err := smtp.SendMail(smtpServer, auth, from, to, msg)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Email sent successfully")
}

// Example_smtpWithTLS demonstrates using NTLM authentication with net/smtp over TLS.
func Example_smtpWithTLS() {
	smtpHost := "mail.example.com"
	smtpPort := "587"
	from := "sender@example.com"
	to := []string{"recipient@example.com"}
	username := "DOMAIN\\username"
	password := "your-password"

	// Compose message
	msg := []byte("To: recipient@example.com\r\n" +
		"Subject: Test Email\r\n" +
		"\r\n" +
		"This is a test email using NTLM authentication over TLS.\r\n")

	// Connect to the SMTP server
	client, err := smtp.Dial(smtpHost + ":" + smtpPort)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// Start TLS
	if err = client.StartTLS(&tls.Config{ServerName: smtpHost}); err != nil {
		log.Fatal(err)
	}

	// Create NTLM auth
	auth := &ntlmAuth{
		username: username,
		password: password,
		host:     smtpHost,
	}

	// Authenticate
	if err = client.Auth(auth); err != nil {
		log.Fatal(err)
	}

	// Send the email
	if err = client.Mail(from); err != nil {
		log.Fatal(err)
	}
	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			log.Fatal(err)
		}
	}

	w, err := client.Data()
	if err != nil {
		log.Fatal(err)
	}
	_, err = w.Write(msg)
	if err != nil {
		log.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		log.Fatal(err)
	}

	if err = client.Quit(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Email sent successfully")
}
