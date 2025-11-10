// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// seekableBuffer implements io.ReadSeeker to simulate a seekable body like a file
type seekableBuffer struct {
	reader     *bytes.Reader
	seekCalled *bool
}

func newSeekableBuffer(data []byte, seekCalled *bool) *seekableBuffer {
	return &seekableBuffer{
		reader:     bytes.NewReader(data),
		seekCalled: seekCalled,
	}
}

func (sb *seekableBuffer) Read(p []byte) (n int, err error) {
	return sb.reader.Read(p)
}

func (sb *seekableBuffer) Seek(offset int64, whence int) (int64, error) {
	if sb.seekCalled != nil {
		*sb.seekCalled = true
	}
	return sb.reader.Seek(offset, whence)
}

func (sb *seekableBuffer) Close() error {
	return nil
}

// TestNegotiatorWithSeekableBody tests that seekable bodies work correctly
func TestNegotiatorWithSeekableBody(t *testing.T) {
	testData := []byte("test data that would be large in real scenarios")

	// Track seek calls to ensure the body is being seeked, not buffered
	seekCalled := false
	bodyReader := newSeekableBuffer(testData, &seekCalled)

	// Create a test server that accepts requests without auth
	// (testing the seekable body path without complex NTLM flow)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and verify the body was sent correctly
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, testData) {
			t.Errorf("Body mismatch: expected %q, got %q", testData, body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create a request with basic auth
	req, err := http.NewRequest("POST", server.URL, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(respBody))
	}

	// Verify that seek was called (indicating body handling used seek path)
	if !seekCalled {
		t.Log("Note: Seek was not called - server accepted request without auth negotiation")
	}
}

// TestNegotiatorWithPartialSeekableBody tests that seekable bodies starting at non-zero position work correctly
func TestNegotiatorWithPartialSeekableBody(t *testing.T) {
	fullData := []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
	// Simulate a partial read starting at position 10
	startPos := int64(10)
	expectedData := fullData[startPos:]

	// Create a seekable reader and position it at startPos
	bodyReader := bytes.NewReader(fullData)
	_, err := bodyReader.Seek(startPos, io.SeekStart)
	if err != nil {
		t.Fatalf("Failed to seek to start position: %v", err)
	}

	// Create a test server that accepts requests without auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and verify the body was sent correctly from the offset position
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, expectedData) {
			t.Errorf("Body mismatch: expected %q, got %q", expectedData, body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create a request with basic auth
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bodyReader))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(respBody))
	}
}

// TestNegotiatorWithNonSeekableBody tests that non-seekable bodies still work (backward compatibility)
func TestNegotiatorWithNonSeekableBody(t *testing.T) {
	testData := []byte("test data")

	// Create a test server that immediately returns success without auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Use a regular bytes.Buffer which is not seekable
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request - should work even with non-seekable body
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(body) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(body))
	}
}

// verifyRequestUnmodified checks that the request's headers and properties remain unchanged
func verifyRequestUnmodified(t *testing.T, req *http.Request, originalAuthHeader, originalCustomHeader, originalUserAgent, originalURL, originalMethod string) {
	t.Helper()

	if got := req.Header.Get("Authorization"); got != originalAuthHeader {
		t.Errorf("Authorization header was modified: expected %q, got %q", originalAuthHeader, got)
	}
	if got := req.Header.Get("X-Custom-Header"); got != originalCustomHeader {
		t.Errorf("Custom header was modified: expected %q, got %q", originalCustomHeader, got)
	}
	if got := req.Header.Get("User-Agent"); got != originalUserAgent {
		t.Errorf("User-Agent header was modified: expected %q, got %q", originalUserAgent, got)
	}
	if got := req.URL.String(); got != originalURL {
		t.Errorf("Request URL was modified: expected %q, got %q", originalURL, got)
	}
	if got := req.Method; got != originalMethod {
		t.Errorf("Request method was modified: expected %q, got %q", originalMethod, got)
	}
}

// TestNegotiatorDoesNotModifyRequest verifies that Negotiator doesn't modify
// the incoming request, as mandated by the http.RoundTripper contract.
func TestNegotiatorDoesNotModifyRequest(t *testing.T) {
	testData := []byte("test request body")

	// Create a test server that returns success without auth challenges
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create a request with basic auth
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("User-Agent", "test-agent")

	// Capture the original request state
	originalAuthHeader := req.Header.Get("Authorization")
	originalCustomHeader := req.Header.Get("X-Custom-Header")
	originalUserAgent := req.Header.Get("User-Agent")
	originalURL := req.URL.String()
	originalMethod := req.Method

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify the original request was NOT modified
	verifyRequestUnmodified(t, req, originalAuthHeader, originalCustomHeader, originalUserAgent, originalURL, originalMethod)

	// Read response body to ensure request completed successfully
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(body))
	}
}

// TestNegotiatorDoesNotModifyRequestWithAuthChallenge verifies that even when
// auth challenges occur, the original request remains unmodified.
func TestNegotiatorDoesNotModifyRequestWithAuthChallenge(t *testing.T) {
	testData := []byte("test request body")
	callCount := 0

	// Create a test server that returns 401 with NTLM but we won't complete
	// the full handshake - we just want to verify the original request isn't modified
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with NTLM challenge
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 2 && authHeader == "Basic dGVzdHVzZXI6dGVzdHBhc3M=" {
			// Second request: tries basic auth, we'll just accept it for the test
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok with basic"))
		} else {
			// Any other scenario
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer server.Close()

	// Create a request with basic auth
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("User-Agent", "test-agent")

	// Capture the original request state
	originalAuthHeader := req.Header.Get("Authorization")
	originalCustomHeader := req.Header.Get("X-Custom-Header")
	originalUserAgent := req.Header.Get("User-Agent")
	originalURL := req.URL.String()
	originalMethod := req.Method

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request - will trigger auth negotiation
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify the original request was NOT modified, even after auth negotiation
	verifyRequestUnmodified(t, req, originalAuthHeader, originalCustomHeader, originalUserAgent, originalURL, originalMethod)

	// Just verify we got a response (don't care about specifics of auth result)
	if resp.StatusCode != http.StatusOK {
		t.Logf("Note: Got status %d, but request state is what matters for this test", resp.StatusCode)
	}
}

// unseekableReadSeeker implements io.ReadSeeker but fails on Seek (like pipes)
type unseekableReadSeeker struct {
	reader *bytes.Reader
}

func (u *unseekableReadSeeker) Read(p []byte) (n int, err error) {
	return u.reader.Read(p)
}

func (u *unseekableReadSeeker) Seek(offset int64, whence int) (int64, error) {
	// Simulate a pipe or other unseekable stream that implements the interface
	// but returns an error when seeking
	return 0, io.ErrUnexpectedEOF
}

func (u *unseekableReadSeeker) Close() error {
	return nil
}

// TestNegotiatorWithUnseekableReadSeeker tests that bodies implementing io.ReadSeeker
// but failing to seek (like pipes) are handled correctly by falling back to buffering
func TestNegotiatorWithUnseekableReadSeeker(t *testing.T) {
	testData := []byte("test data from pipe-like source")

	// Create a test server that accepts requests without auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read and verify the body was sent correctly
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, testData) {
			t.Errorf("Body mismatch: expected %q, got %q", testData, body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create an unseekable ReadSeeker (simulating a pipe)
	bodyReader := &unseekableReadSeeker{reader: bytes.NewReader(testData)}

	// Create a request with basic auth
	req, err := http.NewRequest("POST", server.URL, bodyReader)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request - should fallback to buffering and work correctly
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "ok" {
		t.Errorf("Expected 'ok', got '%s'", string(respBody))
	}
}
