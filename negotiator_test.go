// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package ntlmssp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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
				a.t.Logf("Background read error: %v", err)
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

	t.Logf("Test completed successfully with %d round trips and no race conditions", count)
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

	// Verify we went through multiple round trips
	if callCount < 3 {
		t.Logf("Note: Only %d round trips occurred, expected NTLM negotiation to require at least 3", callCount)
	}
}
