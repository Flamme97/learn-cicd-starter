package auth

import (
	"errors"
	"net/http"
	"testing"
)


func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error
	}{
		{
			name:    "Valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			wantKey: "my-secret-key",
			wantErr: nil,
		},
		{
			name:    "Missing Authorization Header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "Malformed Authorization Header",
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "Incomplete Authorization Header",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("Expected key: %v, Got: %v", tt.wantKey, gotKey)
			}

			if gotErr != nil && tt.wantErr != nil && gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("Expected error: %v, Got: %v", tt.wantErr, gotErr)
			}

			if (gotErr == nil) != (tt.wantErr == nil) {
				t.Errorf("Expected error presence: %v, Got: %v", tt.wantErr == nil, gotErr == nil)
			}
		})
	}
}
