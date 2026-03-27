package helperproto

import (
	"bytes"
	"encoding/gob"
	"testing"
)

func TestExecRequestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)

	want := ExecRequest{
		Argv: []string{"/usr/bin/curl", "-v", "http://example.com"},
		Env:  []string{"HTTP_PROXY=http://127.0.0.1:31111"},
	}
	if err := enc.Encode(&want); err != nil {
		t.Fatal(err)
	}

	var got ExecRequest
	if err := dec.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Argv) != 3 {
		t.Fatalf("unexpected argv: %#v", got.Argv)
	}
}
