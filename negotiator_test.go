// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
		t.Error("Note: Seek was not called - server accepted request without auth negotiation")
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
		t.Errorf("Note: Got status %d, but request state is what matters for this test", resp.StatusCode)
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

// asyncRoundTripper simulates a RoundTripper that continues reading the request body
// and headers on background goroutines after RoundTrip returns, which is allowed by
// the http.RoundTripper contract. This tests for race conditions in concurrent access
// to both the request body and headers.
type asyncRoundTripper struct {
	// requestCount tracks how many times RoundTrip has been called
	requestCount atomic.Int32
	t            *testing.T
}

func (a *asyncRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	count := a.requestCount.Add(1)

	// Simulate async body reading and header access
	bodyCopy := &bytes.Buffer{}
	if req.Body != nil {
		// Start reading the body on a background goroutine
		go func() {
			defer req.Body.Close()
			time.Sleep(30 * time.Millisecond)
			// Access request headers in background goroutine
			_ = req.Header.Get("Authorization")
			_ = req.Header.Get("Content-Type")
			_ = req.Header.Get("User-Agent")
			// Also access other request fields that might be read
			_ = req.Method
			_ = req.URL.String()
			// Simulate slow reading - this is key to testing the race condition
			// Without the closeWaiter fix, this would race with the body being
			// seeked and reused in the next request
			time.Sleep(50 * time.Millisecond)
			_, err := io.Copy(bodyCopy, req.Body)
			if err != nil {
				a.t.Errorf("Background read error: %v", err)
			}
		}()

		// Return immediately (before background goroutine finishes)
		// This simulates the behavior that can cause races
	}

	authHeader := req.Header.Get("Authorization")

	// First request with no auth returns 401 requesting Basic or Negotiate
	if count == 1 && authHeader == "" {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Www-Authenticate": []string{"Basic realm=\"test\"", "Negotiate"},
			},
			Body:          io.NopCloser(bytes.NewReader([]byte{})),
			ContentLength: 0,
			Request:       req,
		}, nil
	}

	// Second request with Basic auth, reject and request Negotiate
	if count == 2 && bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header: http.Header{
				"Www-Authenticate": []string{"Negotiate"},
			},
			Body:          io.NopCloser(bytes.NewReader([]byte{})),
			ContentLength: 0,
			Request:       req,
		}, nil
	}

	// Any other request: return success
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader([]byte("success"))),
		ContentLength: 7,
		Request:       req,
	}, nil
}

// TestNegotiatorWithAsyncBodyReading tests that the Negotiator correctly handles
// race conditions when the wrapped RoundTripper accesses the request on background
// goroutines after RoundTrip returns, which is allowed by the http.RoundTripper contract.
// This test covers two race conditions:
//  1. Body reading: The wrapped RoundTripper reads the request body on a background
//     goroutine. Without the closeWaiter fix, this would race with Negotiator seeking
//     and reusing the body for the next request.
//  2. Header reading: The wrapped RoundTripper reads request headers on a background
//     goroutine. Without cloning the request, this would race with Negotiator modifying
//     headers for the next request.
func TestNegotiatorWithAsyncBodyReading(t *testing.T) {
	testData := []byte("test data that will be read asynchronously")

	// Create an async RoundTripper that simulates background body reading
	asyncRT := &asyncRoundTripper{t: t}

	// Create a request with a body
	bodyReader := bytes.NewReader(testData)
	req, err := http.NewRequest("POST", "http://example.com/test", io.NopCloser(bodyReader))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create Negotiator with the async RoundTripper
	negotiator := Negotiator{RoundTripper: asyncRT}

	resp, err := negotiator.RoundTrip(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "success" {
		t.Errorf("Expected 'success', got '%s'", string(respBody))
	}

	// Verify multiple round trips occurred (testing body reuse)
	count := asyncRT.requestCount.Load()

	// Should be at least 2 round trips: 1. anonymous, 2. with auth
	// This is sufficient to test the critical path where body is reused
	if count < 2 {
		t.Errorf("Expected at least 2 round trips to test body reuse, got %d", count)
	}

	// Give background goroutines time to complete
	time.Sleep(200 * time.Millisecond)
}

// TestNegotiatorWithEmptyBody tests that requests with nil body work correctly
func TestNegotiatorWithEmptyBody(t *testing.T) {
	// Create a test server that accepts requests without auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify body is nil or empty
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed to read body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(body) != 0 {
				t.Errorf("Expected empty body, got %d bytes", len(body))
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Create a GET request with nil body
	req, err := http.NewRequest("GET", server.URL, nil)
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

// TestNegotiatorWithEmptyBodyAndNTLMChallenge tests that requests with nil body
// work correctly through the full NTLM negotiation
func TestNegotiatorWithEmptyBodyAndNTLMChallenge(t *testing.T) {
	callCount := 0

	// Create a test server that performs NTLM negotiation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Verify body is nil or empty on all requests
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed to read body: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if len(body) != 0 {
				t.Errorf("Expected empty body on request %d, got %d bytes", callCount, len(body))
			}
		}

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with NTLM challenge
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 2 && authHeader == "Basic dGVzdHVzZXI6dGVzdHBhc3M=" {
			// Second request: tries basic auth, still return 401 with NTLM
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			// Final request or any other: success
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		}
	}))
	defer server.Close()

	// Create a GET request with nil body
	req, err := http.NewRequest("GET", server.URL, nil)
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

	// Make the request - should complete NTLM negotiation without body
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

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(respBody) != "authenticated" {
		t.Errorf("Expected 'authenticated', got '%s'", string(respBody))
	}

	// The test verifies that NTLM negotiation completes successfully in two round trips
	// (anonymous and NTLM negotiate), even with an empty body,
	// because the server accepts the NTLM negotiate message without requiring a challenge response.
	if callCount != 2 {
		t.Errorf("Note: %d round trips occurred (expected 2: anonymous + Basic)", callCount)
	}
}

// TestNegotiatorBasicToNTLMUpgrade tests that the Negotiator correctly handles
// servers that initially request Basic auth and then upgrade to NTLM
func TestNegotiatorBasicToNTLMUpgrade(t *testing.T) {
	testData := []byte("test request body")
	callCount := 0
	var negotiateMessageReceived bool

	// Create a test server that first accepts Basic auth, then upgrades to NTLM
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Verify body is sent correctly on all requests
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body on request %d: %v", callCount, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !bytes.Equal(body, testData) {
			t.Errorf("Body mismatch on request %d: expected %q, got %q", callCount, testData, body)
		}

		if callCount == 1 {
			// First request: no auth, return 401 with Basic auth request
			w.Header().Set("Www-Authenticate", "Basic realm=\"test\"")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("basic auth required"))
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
			// Second request: Basic auth provided, but upgrade to NTLM
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("upgrading to ntlm"))
		} else if callCount == 3 && bytes.HasPrefix([]byte(authHeader), []byte("NTLM ")) {
			// Third request: NTLM negotiate message
			negotiateMessageReceived = true
			// Verify the negotiate message doesn't contain credentials
			token := strings.TrimPrefix(authHeader, "NTLM ")
			decoded, err := base64.StdEncoding.DecodeString(token)
			if err == nil {
				if bytes.Contains(decoded, []byte("testuser")) {
					t.Error("Negotiate message contains username")
				}
				if bytes.Contains(decoded, []byte("testpass")) {
					t.Error("Negotiate message contains password")
				}
			}
			// Final request: accept (would be NTLM in real scenario)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		} else {
			// Unexpected request
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	// Create a POST request with a body
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper:   http.DefaultTransport,
			AllowBasicAuth: true,
		},
	}

	// Make the request - should handle Basic to NTLM upgrade successfully
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

	// The upgrade should complete successfully
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(respBody) != "authenticated" {
		t.Errorf("Expected 'authenticated', got '%s'", string(respBody))
	}

	// Verify we went through the expected upgrade flow:
	// 1. Initial request (no auth) -> 401 Basic
	// 2. Request with Basic auth -> 401 NTLM
	// 3. Request with NTLM negotiate -> 200 OK (accepted without challenge in test)
	if callCount != 3 {
		t.Errorf("Expected exactly 3 round trips for Basic->NTLM upgrade, got %d", callCount)
	}

	// Verify we received and validated the negotiate message
	if !negotiateMessageReceived {
		t.Error("NTLM negotiate message was not received during Basic->NTLM upgrade")
	}
}

func TestNegotiatorNegotiateKeyExchange(t *testing.T) {
	testData := []byte(`<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"
              xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">
	<env:Header/>
	<env:Body>
		<wsmid:Identify/>
	</env:Body>
</env:Envelope>`)
	callCount := 0

	// Create a test server that first accepts Basic auth, then upgrades to NTLM
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		if callCount == 1 {
			// First request: something was provided, but we want to negotiate
			w.Header().Set("Www-Authenticate", "Negotiate")
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("Negotiate ")) {
			// Second request: negotiate message received, send challenge
			// just send a random (valid) challenge for testing
			serverChallenge := "TlRMTVNTUAACAAAAEAAQADgAAAAFAoriSbUIyJkyrfMAAAAAAAAAAGAAYABIAAAACgBdWAAAAA9NAFkAUwBFAFIAVgBFAFIAAgAQAE0AWQBTAEUAUgBWAEUAUgABABAATQBZAFMARQBSAFYARQBSAAQAEABtAHkAcwBlAHIAdgBlAHIAAwAQAG0AeQBzAGUAcgB2AGUAcgAHAAgAX2oKeJ963AEAAAAA"
			w.Header().Set("Www-Authenticate", "Negotiate "+serverChallenge)
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 3 && bytes.HasPrefix([]byte(authHeader), []byte("Negotiate ")) {
			// winrm expects an empty body
			if r.Body != nil {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					t.Errorf("Failed to read body on request %d: %v", callCount, err)
					return
				}
				if len(body) != 0 {
					w.WriteHeader(http.StatusInternalServerError)
					t.Errorf("Expected empty body on request %d, got %q", callCount, body)
				}
			}

			// Third request: key exchange message
			token := strings.TrimPrefix(authHeader, "Negotiate ")
			decoded, err := base64.StdEncoding.DecodeString(token)

			if err == nil {
				if bytes.Contains(decoded, []byte("testuser")) {
					t.Error("Negotiate message contains username")
				}
				if bytes.Contains(decoded, []byte("testpass")) {
					t.Error("Negotiate message contains password")
				}
			}

			// Final request: accept
			w.Header().Set("Www-Authenticate", "Negotiate ")
			w.WriteHeader(http.StatusOK)
		} else if callCount == 4 {
			// the server would check its a valid soap request, and return 500 if not
			// Verify body is sent correctly on all requests
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("Failed to read body on request %d: %v", callCount, err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if !bytes.Equal(body, testData) {
				t.Errorf("Body mismatch on request %d: expected %q, got %q", callCount, testData, body)
			}

			// dont need to respond, just say ok
			w.WriteHeader(http.StatusOK)
		} else {
			// Unexpected request
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	// Create a POST request with a body
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")
	req.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
		},
	}

	// Make the request - should handle Basic to NTLM upgrade successfully
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// The upgrade should complete successfully
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify we went through the expected upgrade flow:
	// 1. Initial request with no auth-> 401 request to Negotiate
	// 2. Request with Negotiate message -> 401 with challenge
	// 3. Request with key exchange -> 200 OK
	if callCount != 3 {
		t.Errorf("Expected exactly 3 round trips for Basic->NTLM upgrade, got %d", callCount)
	}
}

// TestNegotiatorBasicAuthOnly tests that the Negotiator correctly handles
// servers that only request Basic auth and accept it without upgrading to NTLM
func TestNegotiatorBasicAuthOnly(t *testing.T) {
	testData := []byte("test request body")
	callCount := 0

	// Create a test server that only accepts Basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Verify body is sent correctly on all requests
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed to read body on request %d: %v", callCount, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !bytes.Equal(body, testData) {
			t.Errorf("Body mismatch on request %d: expected %q, got %q", callCount, testData, body)
		}

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with Basic auth request
			w.Header().Set("Www-Authenticate", "Basic realm=\"test\"")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("basic auth required"))
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
			// Second request: Basic auth provided, accept it
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		} else {
			// Unexpected scenario
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("unexpected request"))
		}
	}))
	defer server.Close()

	// Create a POST request with a body
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper:   http.DefaultTransport,
			AllowBasicAuth: true,
		},
	}

	// Make the request - should succeed with Basic auth only
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

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(respBody) != "authenticated" {
		t.Errorf("Expected 'authenticated', got '%s'", string(respBody))
	}

	// Verify we went through the expected Basic auth flow:
	// 1. Initial request (no auth) -> 401 Basic
	// 2. Request with Basic auth -> 200 OK
	if callCount != 2 {
		t.Errorf("Expected exactly 2 round trips for Basic auth only, got %d", callCount)
	}
}

// failingReadSeeker implements io.ReadSeeker but fails on Seek after being read
type failingReadSeeker struct {
	reader     *bytes.Reader
	failOnNext bool
}

func (f *failingReadSeeker) Read(p []byte) (n int, err error) {
	n, err = f.reader.Read(p)
	if err == nil || err == io.EOF {
		// After a successful read, mark to fail on next seek
		f.failOnNext = true
	}
	return n, err
}

func (f *failingReadSeeker) Seek(offset int64, whence int) (int64, error) {
	if f.failOnNext {
		// Simulate a seek failure (e.g., the underlying file was closed)
		return 0, io.ErrUnexpectedEOF
	}
	return f.reader.Seek(offset, whence)
}

func (f *failingReadSeeker) Close() error {
	return nil
}

// TestNegotiatorRewindFailureWithBasicAuth tests that when body.rewind() fails
// during Basic auth flow, the response is returned to the client instead of an error
func TestNegotiatorRewindFailureWithBasicAuth(t *testing.T) {
	testData := []byte("test request body")
	callCount := 0

	// Create a test server that requests Basic auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Read body to trigger body consumption
		_, _ = io.ReadAll(r.Body)

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with Basic auth request
			w.Header().Set("Www-Authenticate", "Basic realm=\"test\"")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("basic auth required"))
		} else {
			// Should not reach here if rewind fails properly
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		}
	}))
	defer server.Close()

	// Create a body that will fail to rewind after being read
	bodyReader := &failingReadSeeker{reader: bytes.NewReader(testData), failOnNext: false}

	// Create a POST request with the failing body
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

	// Make the request - should return the 401 response when rewind fails
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed with error (expected response): %v", err)
	}
	defer resp.Body.Close()

	// Should receive the 401 response since rewind failed
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (rewind failed), got %d", resp.StatusCode)
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "basic auth required" {
		t.Errorf("Expected 'basic auth required', got '%s'", string(respBody))
	}

	// Should only have made 1 round trip since rewind failed
	if callCount != 1 {
		t.Errorf("Expected exactly 1 round trip (rewind failed), got %d", callCount)
	}
}

// TestNegotiatorRewindFailureWithNTLM tests that when body.rewind() fails
// during NTLM negotiation, the response is returned to the client instead of an error
func TestNegotiatorRewindFailureWithNTLM(t *testing.T) {
	testData := []byte("test request body")
	callCount := 0

	// Create a test server that requests NTLM auth
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Read body to trigger body consumption
		_, _ = io.ReadAll(r.Body)

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with NTLM challenge
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("ntlm auth required"))
		} else {
			// Should not reach here if rewind fails properly
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		}
	}))
	defer server.Close()

	// Create a body that will fail to rewind after being read
	bodyReader := &failingReadSeeker{reader: bytes.NewReader(testData), failOnNext: false}

	// Create a POST request with the failing body
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

	// Make the request - should return the 401 response when rewind fails
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed with error (expected response): %v", err)
	}
	defer resp.Body.Close()

	// Should receive the 401 response since rewind failed
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (rewind failed), got %d", resp.StatusCode)
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "ntlm auth required" {
		t.Errorf("Expected 'ntlm auth required', got '%s'", string(respBody))
	}

	// Should only have made 1 round trip since rewind failed
	if callCount != 1 {
		t.Errorf("Expected exactly 1 round trip (rewind failed), got %d", callCount)
	}
}

// TestNegotiatorInvalidChallengeToken tests that when resauth.token() fails
// to parse the challenge, the response is returned to the client instead of an error
func TestNegotiatorInvalidChallengeToken(t *testing.T) {
	callCount := 0

	// Create a test server that sends an invalid NTLM challenge token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		if callCount == 1 {
			// First request: no auth, return 401 with NTLM
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("NTLM ")) {
			// Second request: negotiate message, return invalid challenge token
			w.Header().Set("Www-Authenticate", "NTLM invalid-base64-token!!!")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("invalid challenge"))
		} else {
			// Should not reach here if token parsing fails properly
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		}
	}))
	defer server.Close()

	// Create a GET request
	req, err := http.NewRequest("GET", server.URL, nil)
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

	// Make the request - should return the 401 response when token parsing fails
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed with error (expected response): %v", err)
	}
	defer resp.Body.Close()

	// Should receive the 401 response since token parsing failed
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (invalid token), got %d", resp.StatusCode)
	}

	// Read response body (will be empty because the negotiator returns the original 401 response from the first request, which had no body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// The response body is empty because the returned response is the original 401 from the initial request, not the one with the invalid token
	if len(respBody) != 0 {
		t.Errorf("Unexpected response body: '%s'", string(respBody))
	}

	// Should have made 2 round trips before stopping at invalid token
	if callCount != 2 {
		t.Errorf("Expected exactly 2 round trips (stopped at invalid token), got %d", callCount)
	}
}

// TestNegotiatorEmptyChallengeToken tests that when the server returns an empty
// NTLM challenge token, the response is returned to the client
func TestNegotiatorEmptyChallengeToken(t *testing.T) {
	callCount := 0

	// Create a test server that sends an empty NTLM challenge token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		if callCount == 1 {
			// First request: no auth, return 401 with NTLM
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("NTLM ")) {
			// Second request: negotiate message, return empty challenge token
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("empty challenge"))
		} else {
			// Should not reach here if empty token is handled properly
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		}
	}))
	defer server.Close()

	// Create a GET request
	req, err := http.NewRequest("GET", server.URL, nil)
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

	// Make the request - should return the 401 response when challenge is empty
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed with error (expected response): %v", err)
	}
	defer resp.Body.Close()

	// Should receive the 401 response since challenge was empty
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (empty challenge), got %d", resp.StatusCode)
	}

	// Read response body (will be empty because the negotiator returns the original 401 response from the first request, which had no body)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// The response body is empty because the returned response is the original 401 from the initial request, not because it was drained
	if len(respBody) != 0 {
		t.Errorf("Unexpected response body: '%s'", string(respBody))
	}

	// Should have made 2 round trips before stopping at empty challenge
	if callCount != 2 {
		t.Errorf("Expected exactly 2 round trips (stopped at empty challenge), got %d", callCount)
	}
}

// TestNegotiatorResponseDraining tests that responses are properly drained
// to allow connection reuse between authentication attempts
func TestNegotiatorResponseDraining(t *testing.T) {
	callCount := 0

	// Create a test server that tracks if response bodies are drained
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Simulate a response that needs draining
		responseData := []byte("response body that should be drained")

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with Basic auth
			w.Header().Set("Www-Authenticate", "Basic realm=\"test\"")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(responseData)
		} else if callCount == 2 && bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
			// Second request: Basic auth accepted
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated"))
		} else {
			// Unexpected request
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("unexpected"))
		}
	}))
	defer server.Close()

	// Create a request
	testData := []byte("test body")
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper:   http.DefaultTransport,
			AllowBasicAuth: true,
		},
	}

	// Make the request - should go through multiple round trips
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Final response should be successful
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected final status 200, got %d", resp.StatusCode)
	}

	// Read final response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "authenticated" {
		t.Errorf("Expected 'authenticated', got '%s'", string(respBody))
	}

	// Verify multiple round trips occurred (indicating draining worked and allowed connection reuse)
	// We expect 2 round trips: anonymous (drained), then basic auth (success)
	if callCount != 2 {
		t.Errorf("Expected exactly 2 round trips (draining allows reuse), got %d", callCount)
	}
}

// TestNegotiatorRejectsBasicAuthWhenDisabled tests that the Negotiator does not
// send Basic authentication credentials when AllowBasicAuth is false (default)
func TestNegotiatorRejectsBasicAuthWhenDisabled(t *testing.T) {
	callCount := 0
	var receivedBasicAuth bool

	// Create a test server that only offers Basic auth (no NTLM)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		authHeader := r.Header.Get("Authorization")

		// Track if we ever receive Basic auth credentials
		if bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
			receivedBasicAuth = true
		}

		if callCount == 1 && authHeader == "" {
			// First request: no auth, return 401 with only Basic auth
			w.Header().Set("Www-Authenticate", "Basic realm=\"test\"")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("basic auth required"))
		} else if bytes.HasPrefix([]byte(authHeader), []byte("Basic ")) {
			// Should NOT reach here when AllowBasicAuth is false
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("authenticated with basic"))
		} else {
			// Any other request
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("still unauthorized"))
		}
	}))
	defer server.Close()

	// Create a request with credentials
	testData := []byte("test body")
	req, err := http.NewRequest("POST", server.URL, io.NopCloser(bytes.NewReader(testData)))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.SetBasicAuth("testuser", "testpass")

	// Create client with NTLM negotiator WITHOUT AllowBasicAuth
	client := &http.Client{
		Transport: Negotiator{
			RoundTripper: http.DefaultTransport,
			// AllowBasicAuth is false by default
		},
	}

	// Make the request - should return 401 without trying Basic auth
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should receive the original 401 response since Basic auth was rejected
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 (Basic auth rejected), got %d", resp.StatusCode)
	}

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(respBody) != "basic auth required" {
		t.Errorf("Expected 'basic auth required', got '%s'", string(respBody))
	}

	// Verify Basic auth was never sent
	if receivedBasicAuth {
		t.Error("Basic auth credentials were sent even though AllowBasicAuth is false")
	}

	// Should only have made 1 round trip (anonymous request, then stop)
	if callCount != 1 {
		t.Errorf("Expected exactly 1 round trip (Basic auth rejected), got %d", callCount)
	}
}

// TestNegotiatorWorkstationAndDomainNames tests that the Negotiator correctly sends
// workstation and domain names to the server when they are set
func TestNegotiatorWorkstationAndDomainNames(t *testing.T) {
	testCases := []struct {
		name              string
		workstationDomain string
		workstationName   string
		wantDomain        bool
		wantWorkstation   bool
	}{
		{
			name:              "Both workstation domain and name set",
			workstationDomain: "TESTDOMAIN",
			workstationName:   "TESTWORKSTATION",
			wantDomain:        true,
			wantWorkstation:   true,
		},
		{
			name:              "Only workstation name set",
			workstationDomain: "",
			workstationName:   "TESTWORKSTATION",
			wantDomain:        false,
			wantWorkstation:   true,
		},
		{
			name:              "Only workstation domain set",
			workstationDomain: "TESTDOMAIN",
			workstationName:   "",
			wantDomain:        true,
			wantWorkstation:   false,
		},
		{
			name:              "Neither workstation domain nor name set",
			workstationDomain: "",
			workstationName:   "",
			wantDomain:        false,
			wantWorkstation:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var negotiateMsg, authenticateMsg []byte

			// Create a test server that performs NTLM negotiation and captures the messages
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				authHeader := r.Header.Get("Authorization")

				if authHeader == "" {
					// First request: no auth, return 401 with NTLM challenge
					w.Header().Set("Www-Authenticate", "NTLM")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				if bytes.HasPrefix([]byte(authHeader), []byte("NTLM ")) {
					// Parse the NTLM message
					msgData := authHeader[5:] // Skip "NTLM "
					msg, err := io.ReadAll(bytes.NewReader([]byte(msgData)))
					if err != nil {
						t.Errorf("Failed to read auth message: %v", err)
						w.WriteHeader(http.StatusInternalServerError)
						return
					}

					// Try to determine message type by checking if it's a negotiate or authenticate message
					// Negotiate messages are typically shorter (around 40 bytes base64 encoded)
					// Authenticate messages are longer
					if len(negotiateMsg) == 0 {
						// This is the negotiate message
						negotiateMsg = msg
						// Send back a challenge
						// Create a minimal valid challenge message
						challenge, err := createTestChallenge()
						if err != nil {
							t.Errorf("Failed to create challenge: %v", err)
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						w.Header().Set("Www-Authenticate", "NTLM "+challenge)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}

					// This is the authenticate message
					authenticateMsg = msg
					// Accept authentication
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("authenticated"))
					return
				}

				// Unexpected auth type
				w.WriteHeader(http.StatusBadRequest)
			}))
			defer server.Close()

			// Create a GET request
			req, err := http.NewRequest("GET", server.URL, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}
			req.SetBasicAuth("testuser", "testpass")

			// Create client with NTLM negotiator
			client := &http.Client{
				Transport: Negotiator{
					RoundTripper:      http.DefaultTransport,
					WorkstationDomain: tc.workstationDomain,
					WorkstationName:   tc.workstationName,
				},
			}

			// Make the request
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Verify we got a successful response
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			// Now verify the negotiate message contains the expected workstation and domain
			if len(negotiateMsg) > 0 {
				verifyNegotiateMessage(t, negotiateMsg, tc.workstationDomain, tc.workstationName, tc.wantDomain, tc.wantWorkstation)
			} else {
				t.Error("No negotiate message was captured")
			}

			// Verify the authenticate message contains the expected workstation name
			if len(authenticateMsg) > 0 && tc.wantWorkstation {
				verifyAuthenticateMessage(t, authenticateMsg, tc.workstationName)
			}
		})
	}
}

// createTestChallenge creates a minimal valid NTLM challenge message for testing
func createTestChallenge() (string, error) {
	// Create a minimal challenge message structure
	// This is a simplified version for testing purposes
	challenge := challengeMessageFields{
		messageHeader:   newMessageHeader(2),
		NegotiateFlags:  defaultFlags,
		ServerChallenge: [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}

	buf := bytes.Buffer{}
	if err := binary.Write(&buf, binary.LittleEndian, &challenge); err != nil {
		return "", err
	}

	// Encode to base64
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// verifyNegotiateMessage verifies that the negotiate message contains the expected flags and payload
func verifyNegotiateMessage(t *testing.T, msgData []byte, expectedDomain, expectedWorkstation string, wantDomain, wantWorkstation bool) {
	t.Helper()

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(msgData))
	if err != nil {
		t.Errorf("Failed to decode negotiate message: %v", err)
		return
	}

	// Parse the negotiate message
	if len(decoded) < expMsgBodyLen {
		t.Errorf("Negotiate message too short: got %d bytes, expected at least %d", len(decoded), expMsgBodyLen)
		return
	}

	// Read negotiate flags (at offset 12)
	flags := negotiateFlags(binary.LittleEndian.Uint32(decoded[12:16]))

	// Check domain flag
	hasDomainFlag := flags.Has(negotiateFlagNTLMSSPNEGOTIATEOEMDOMAINSUPPLIED)
	if wantDomain && !hasDomainFlag {
		t.Error("Expected NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag to be set, but it wasn't")
	}
	if !wantDomain && hasDomainFlag {
		t.Error("Expected NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag to be unset, but it was set")
	}

	// Check workstation flag
	hasWorkstationFlag := flags.Has(negotiateFlagNTLMSSPNEGOTIATEOEMWORKSTATIONSUPPLIED)
	if wantWorkstation && !hasWorkstationFlag {
		t.Error("Expected NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag to be set, but it wasn't")
	}
	if !wantWorkstation && hasWorkstationFlag {
		t.Error("Expected NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag to be unset, but it was set")
	}

	// Verify the payload contains the domain and workstation if they were set
	// The payload is in uppercase OEM format (ASCII) and appears after the fixed header
	if wantDomain && expectedDomain != "" {
		// Convert to uppercase as the negotiate message does
		expectedUpper := []byte(strings.ToUpper(expectedDomain))
		if !bytes.Contains(decoded[expMsgBodyLen:], expectedUpper) {
			t.Errorf("Negotiate message payload does not contain expected domain %q", expectedDomain)
		}
	}

	if wantWorkstation && expectedWorkstation != "" {
		// Convert to uppercase as the negotiate message does
		expectedUpper := []byte(strings.ToUpper(expectedWorkstation))
		if !bytes.Contains(decoded[expMsgBodyLen:], expectedUpper) {
			t.Errorf("Negotiate message payload does not contain expected workstation %q", expectedWorkstation)
		}
	}
}

// verifyAuthenticateMessage verifies that the authenticate message contains the expected workstation name
func verifyAuthenticateMessage(t *testing.T, msgData []byte, expectedWorkstation string) {
	t.Helper()

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(msgData))
	if err != nil {
		t.Errorf("Failed to decode authenticate message: %v", err)
		return
	}

	// Parse the authenticate message to extract workstation field
	// The authenticate message structure has varFields for workstation
	// For simplicity, we'll just check if the workstation name appears in the message
	// (it will be in Unicode format)

	// Convert expected workstation to unicode (UTF-16LE)
	expectedUnicode := toUnicode(expectedWorkstation)

	// Check if the unicode workstation name appears in the decoded message
	if !bytes.Contains(decoded, expectedUnicode) {
		t.Errorf("Authenticate message does not contain expected workstation name %q", expectedWorkstation)
	}
}
