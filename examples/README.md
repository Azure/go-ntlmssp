# go-ntlmssp Examples

This directory contains practical examples demonstrating how to use the go-ntlmssp library for NTLM authentication over both HTTP and HTTPS.

## Overview

The go-ntlmssp library provides NTLM/Negotiate authentication for HTTP clients. It works seamlessly with both HTTP and HTTPS by wrapping the standard `http.RoundTripper` interface.

## Examples

### 1. Basic HTTP Authentication (`basic_http/`)

Demonstrates the simplest use case: NTLM authentication over plain HTTP.

```go
client := &http.Client{
    Transport: ntlmssp.Negotiator{
        RoundTripper: &http.Transport{},
    },
}
req.SetBasicAuth(username, password)
```

**Run:**
```bash
cd basic_http
go run main.go
```

### 2. Basic HTTPS Authentication (`basic_https/`)

Shows how to use NTLM authentication over HTTPS with default TLS configuration.

**Key Points:**
- Simply use `https://` URLs instead of `http://`
- The library automatically handles the TLS connection
- Uses system's default certificate pool

```go
client := &http.Client{
    Transport: ntlmssp.Negotiator{
        RoundTripper: &http.Transport{
            TLSClientConfig: &tls.Config{
                MinVersion: tls.VersionTLS12,
            },
        },
    },
}
```

**Run:**
```bash
cd basic_https
go run main.go
```

### 3. HTTPS with Custom TLS Configuration (`https_custom_tls/`)

Demonstrates advanced TLS configuration for scenarios like:
- Self-signed certificates
- Custom CA certificates
- Corporate proxy environments

**Features:**
- Load custom CA certificates
- Configure TLS versions
- Option to skip verification (testing only)

```go
tlsConfig := &tls.Config{
    MinVersion: tls.VersionTLS12,
    RootCAs:    caCertPool, // Custom CA
}

client := &http.Client{
    Transport: ntlmssp.Negotiator{
        RoundTripper: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    },
}
```

**Run:**
```bash
cd https_custom_tls
go run main.go
```

### 4. POST Request with NTLM (`post_request/`)

Shows how to send POST requests with a request body using NTLM authentication over HTTPS.

**Features:**
- JSON payload
- Content-Type headers
- Request body handling during NTLM handshake

```go
jsonData, _ := json.Marshal(data)
req, _ := http.NewRequest("POST", url, bytes.NewReader(jsonData))
req.Header.Set("Content-Type", "application/json")
req.SetBasicAuth(username, password)
```

**Run:**
```bash
cd post_request
go run main.go
```

## Username Formats

The library supports multiple username formats:

### SAM Format (Domain\Username)
```go
username := "DOMAIN\\username"
```

### UPN Format (username@domain.com)
```go
username := "username@domain.com"
```

### Simple Username
```go
username := "username"  // Domain will be negotiated
```

## Common Use Cases

### Corporate Network Access
```go
// Access SharePoint, Exchange, or other Windows-integrated services
url := "https://sharepoint.company.com/api/data"
username := "CORPORATE\\john.doe"
```

### Azure Resources with NTLM
```go
// Some Azure resources support NTLM authentication
url := "https://resource.azure.com/api/endpoint"
username := "user@tenant.onmicrosoft.com"
```

### Development with Self-Signed Certificates
```go
// For testing environments
tlsConfig := &tls.Config{
    InsecureSkipVerify: true, // ⚠️ Never use in production!
}
```

## Important Notes

### HTTPS vs HTTP
- **HTTPS is strongly recommended** for production use to protect credentials
- HTTP should only be used in controlled, trusted networks
- NTLM over HTTPS provides the same authentication while encrypting all traffic

### Request Body Handling
- The library automatically buffers request bodies to support the NTLM handshake
- For seekable bodies (like `*os.File`), no buffering is needed
- Large request bodies are handled efficiently

### Error Handling
Always check for errors during:
- Request creation
- Client execution
- Response reading

```go
resp, err := client.Do(req)
if err != nil {
    log.Fatalf("Request failed: %v", err)
}
defer resp.Body.Close()

if resp.StatusCode != http.StatusOK {
    log.Printf("Unexpected status: %s", resp.Status)
}
```

## Troubleshooting

### Certificate Verification Failed
If you encounter TLS certificate errors:
1. Ensure the server's certificate is valid and trusted
2. For self-signed certs, add the CA to your trust store or use `RootCAs`
3. Check system time - certificate validity depends on correct time

### Authentication Failed (401)
Common causes:
1. Incorrect username or password
2. Account locked or disabled
3. Wrong domain or username format
4. Server not configured for NTLM authentication

### Connection Timeout
- Check network connectivity
- Verify firewall rules allow HTTPS (port 443)
- Ensure proxy settings if behind a corporate proxy

## Security Best Practices

1. **Always use HTTPS** in production to encrypt credentials
2. **Never hardcode credentials** - use environment variables or secure vaults
3. **Validate TLS certificates** - avoid `InsecureSkipVerify` in production
4. **Use minimum TLS 1.2** - disable older, insecure versions
5. **Rotate credentials regularly** - follow your organization's password policy

## Additional Resources

- [Main README](../README.md) - Library overview and installation
- [E2E Tests](../E2E_README.md) - End-to-end testing guide
- [NTLM Protocol Specification](https://msdn.microsoft.com/en-us/library/cc236621.aspx)
- [HTTP Authentication RFC](https://datatracker.ietf.org/doc/html/rfc4559)

## Contributing

Found an issue or have a suggestion for a new example? Please open an issue or submit a pull request on [GitHub](https://github.com/Azure/go-ntlmssp).

## License

Copyright (c) Microsoft Corporation. Licensed under the MIT License.
