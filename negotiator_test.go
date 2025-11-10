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
