package ingress

import "testing"

func TestDetectOpaqueTCPProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
		want detectedProtocol
	}{
		{
			name: "mysql server greeting",
			data: []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', '6', 0x00},
			want: detectedProtocol{
				Protocol:   "mysql",
				Source:     "first_bytes",
				Confidence: "definite",
			},
		},
		{
			name: "postgres ssl request",
			data: []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f},
			want: detectedProtocol{
				Protocol:   "postgres",
				Source:     "first_bytes",
				Confidence: "definite",
			},
		},
		{
			name: "postgres startup message",
			data: []byte{0x00, 0x00, 0x00, 0x1b, 0x00, 0x03, 0x00, 0x00, 'u', 's', 'e', 'r', 0x00},
			want: detectedProtocol{
				Protocol:   "postgres",
				Source:     "first_bytes",
				Confidence: "probable",
			},
		},
		{
			name: "redis resp",
			data: []byte("*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"),
			want: detectedProtocol{
				Protocol:   "redis",
				Source:     "first_bytes",
				Confidence: "probable",
			},
		},
		{
			name: "ssh banner",
			data: []byte("SSH-2.0-OpenSSH_9.8\r\n"),
			want: detectedProtocol{
				Protocol:   "ssh",
				Source:     "first_bytes",
				Confidence: "definite",
			},
		},
		{
			name: "tls client hello stays opaque",
			data: []byte{0x16, 0x03, 0x03, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b},
			want: detectedProtocol{
				Protocol:   "tls_non_http",
				Source:     "tls_client_hello",
				Confidence: "probable",
			},
		},
		{
			name: "unknown bytes",
			data: []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02},
			want: detectedProtocol{
				Protocol:   "unknown",
				Source:     "first_bytes",
				Confidence: "unknown",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := detectOpaqueTCPProtocol(tc.data)
			if got != tc.want {
				t.Fatalf("detectOpaqueTCPProtocol(%x) = %#v want %#v", tc.data, got, tc.want)
			}
		})
	}
}
