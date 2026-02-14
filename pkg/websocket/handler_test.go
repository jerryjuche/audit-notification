// pkg/websocket/handler_test.go
package websocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuditHandler_InvalidMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	w := httptest.NewRecorder()

	AuditHandler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestAuditHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/audit", strings.NewReader("invalid json"))
	w := httptest.NewRecorder()

	AuditHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestAuditHandler_MissingFields(t *testing.T) {
	// Initialize DB for testing
	InitDB()

	payload := AuditRequest{
		TargetUser: "",
		Requester:  "tester",
		Details:    "test",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/audit", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	AuditHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUserExistsInGitea_MockMode(t *testing.T) {
	// Set mock mode
	t.Setenv("MOCK_AUTH", "true")

	tests := []struct {
		username string
		expected bool
	}{
		{"jerry", true},
		{"admin", true},
		{"test", true},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			result := userExistsInGitea(tt.username)
			if result != tt.expected {
				t.Errorf("userExistsInGitea(%s) = %v, want %v", tt.username, result, tt.expected)
			}
		})
	}
}
