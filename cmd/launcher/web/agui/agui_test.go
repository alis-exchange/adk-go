package agui
import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ag-ui-protocol/ag-ui/sdks/community/go/pkg/core/types"
)

func TestParse_PathPrefixNormalization(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantPrefix string
	}{
		{
			name:       "default",
			args:       nil,
			wantPrefix: "/agui",
		},
		{
			name:       "custom without leading slash",
			args:       []string{"--path_prefix", "custom"},
			wantPrefix: "/custom",
		},
		{
			name:       "custom with leading slash",
			args:       []string{"--path_prefix", "/api/agui"},
			wantPrefix: "/api/agui",
		},
		{
			name:       "trailing slash trimmed",
			args:       []string{"--path_prefix", "/agui/"},
			wantPrefix: "/agui",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLauncher("test-app").(*aguiLauncher)
			_, err := l.Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if l.config.pathPrefix != tt.wantPrefix {
				t.Errorf("pathPrefix = %q, want %q", l.config.pathPrefix, tt.wantPrefix)
			}
		})
	}
}

func TestKeyword(t *testing.T) {
	l := NewLauncher("app").(*aguiLauncher)
	if got := l.Keyword(); got != "agui" {
		t.Errorf("Keyword() = %v, want agui", got)
	}
}

func TestSimpleDescription(t *testing.T) {
	l := NewLauncher("app").(*aguiLauncher)
	if got := l.SimpleDescription(); got == "" {
		t.Error("SimpleDescription() should not be empty")
	}
}

func TestConvertMultimodalInput(t *testing.T) {
	t.Run("inline base64 data", func(t *testing.T) {
		data := base64.StdEncoding.EncodeToString([]byte("hello"))
		ic := types.InputContent{
			Type:     "image",
			Data:     data,
			MimeType: "image/png",
		}
		part, err := convertMultimodalInput(ic)
		if err != nil {
			t.Fatalf("convertMultimodalInput() error = %v", err)
		}
		if part.InlineData == nil {
			t.Fatal("expected InlineData to be set")
		}
		if string(part.InlineData.Data) != "hello" {
			t.Errorf("InlineData.Data = %q, want 'hello'", part.InlineData.Data)
		}
		if part.InlineData.MIMEType != "image/png" {
			t.Errorf("InlineData.MIMEType = %v, want image/png", part.InlineData.MIMEType)
		}
	})

	t.Run("URL reference", func(t *testing.T) {
		ic := types.InputContent{
			Type:     "image",
			URL:      "https://example.com/img.png",
			MimeType: "image/png",
		}
		part, err := convertMultimodalInput(ic)
		if err != nil {
			t.Fatalf("convertMultimodalInput() error = %v", err)
		}
		if part.FileData == nil {
			t.Fatal("expected FileData to be set")
		}
		if part.FileData.FileURI != "https://example.com/img.png" {
			t.Errorf("FileData.FileURI = %v, want https://example.com/img.png", part.FileData.FileURI)
		}
	})

	t.Run("no data or url", func(t *testing.T) {
		ic := types.InputContent{
			Type:     "image",
			MimeType: "image/png",
		}
		_, err := convertMultimodalInput(ic)
		if err == nil {
			t.Error("expected error when no data or url")
		}
	})

	t.Run("invalid base64", func(t *testing.T) {
		ic := types.InputContent{
			Type:     "image",
			Data:     "not-valid-base64!!",
			MimeType: "image/png",
		}
		_, err := convertMultimodalInput(ic)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	l := &aguiLauncher{
		config: &AGUIConfig{
			cors: &CORSConfig{
				AllowedOrigins: []string{"https://app.example.com"},
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called for preflight")
	})

	handler := l.corsMiddleware(inner)
	req := httptest.NewRequest(http.MethodOptions, "/run_sse", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %v, want https://app.example.com", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "POST, OPTIONS" {
		t.Errorf("Allow-Methods = %v, want 'POST, OPTIONS'", got)
	}
}

func TestCORSMiddleware_Credentials(t *testing.T) {
	l := &aguiLauncher{
		config: &AGUIConfig{
			cors: &CORSConfig{
				AllowedOrigins:   []string{"*"},
				AllowCredentials: true,
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := l.corsMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/run_sse", nil)
	req.Header.Set("Origin", "https://some-origin.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// With credentials, should echo exact origin, not "*".
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://some-origin.com" {
		t.Errorf("Allow-Origin = %v, want https://some-origin.com (exact origin with credentials)", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Allow-Credentials = %v, want true", got)
	}
}

func TestCORSMiddleware_WildcardWithoutCredentials(t *testing.T) {
	l := &aguiLauncher{
		config: &AGUIConfig{
			cors: &CORSConfig{
				AllowedOrigins: []string{"*"},
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := l.corsMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/run_sse", nil)
	req.Header.Set("Origin", "https://any.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %v, want * (wildcard without credentials)", got)
	}
}

func TestCORSMiddleware_DisallowedOrigin(t *testing.T) {
	l := &aguiLauncher{
		config: &AGUIConfig{
			cors: &CORSConfig{
				AllowedOrigins: []string{"https://allowed.com"},
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := l.corsMiddleware(inner)
	req := httptest.NewRequest(http.MethodOptions, "/run_sse", nil)
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should still return 204 but without CORS headers.
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Allow-Origin should be empty for disallowed origin, got %v", got)
	}
}

func TestCORSMiddleware_ExposeHeaders(t *testing.T) {
	l := &aguiLauncher{
		config: &AGUIConfig{
			cors: &CORSConfig{
				AllowedOrigins: []string{"https://app.com"},
				ExposeHeaders:  []string{"X-Request-Id", "X-Trace-Id"},
			},
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := l.corsMiddleware(inner)
	req := httptest.NewRequest(http.MethodPost, "/run_sse", nil)
	req.Header.Set("Origin", "https://app.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-Id, X-Trace-Id" {
		t.Errorf("Expose-Headers = %v, want 'X-Request-Id, X-Trace-Id'", got)
	}
}

func TestCapabilitiesHandler(t *testing.T) {
	name := "test-agent"
	caps := Capabilities{
		Identity: &IdentityCapabilities{
			Name: &name,
		},
	}
	l := &aguiLauncher{
		config: &AGUIConfig{
			capabilities: &caps,
		},
	}

	handler := l.capabilitiesHandler()
	req := httptest.NewRequest(http.MethodGet, "/capabilities", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", ct)
	}

	var decoded Capabilities
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if decoded.Identity == nil || decoded.Identity.Name == nil || *decoded.Identity.Name != "test-agent" {
		t.Error("expected identity.name = test-agent in response")
	}
}
