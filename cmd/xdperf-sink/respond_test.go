package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestParseRespond(t *testing.T) {
	for in, want := range map[string]respondSpec{
		"100:10k": {request: 100, response: 10000},
		"0:1m":    {request: 0, response: 1000000},
		"1g:1":    {request: 1000000000, response: 1},
	} {
		got, err := parseRespond(in, 0)
		if err != nil || *got != want {
			t.Fatalf("%q: %+v %v", in, got, err)
		}
	}
	// 18446744073709552k parses as a uint64 but overflows once multiplied.
	for _, in := range []string{"100", "100:0", "x:1", "1:-1", ":1", "1:", "18446744073709552k:1", "1:1K"} {
		if _, err := parseRespond(in, 0); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
	if s, err := parseRespond("", 0); s != nil || err != nil {
		t.Fatalf("empty: %+v %v", s, err)
	}
	if _, err := parseRespond("", 1); err == nil {
		t.Fatal("accepted -close-after without -respond")
	}
	if s, err := parseRespond("1:1", 3); err != nil || s.closeAfter != 3 {
		t.Fatalf("close-after: %+v %v", s, err)
	}
}

// respondPair runs serveRespond on one end of a loopback TCP connection,
// reading with a buffer of bufSize bytes.
func respondPair(t *testing.T, spec respondSpec, bufSize int) (*net.TCPConn, *counters, chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var c counters
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		serveRespond(conn, &spec, make([]byte, bufSize), &c)
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := conn.(*net.TCPConn)
	t.Cleanup(func() { client.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, &c, done
}

func waitServed(t *testing.T, done chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveRespond did not return")
	}
}

// expectEOF checks that the server sends nothing more and then closes.
func expectEOF(t *testing.T, client *net.TCPConn) {
	t.Helper()
	var b [1]byte
	if n, err := client.Read(b[:]); n != 0 || err != io.EOF {
		t.Fatalf("expected EOF, got %d bytes, %v", n, err)
	}
}

func TestServeRespondRounds(t *testing.T) {
	// A 7-byte buffer splits each 10-byte request across reads.
	client, c, done := respondPair(t, respondSpec{request: 10, response: 3000000}, 7)
	resp := make([]byte, 3000000)
	for round := 0; round < 3; round++ {
		// One request in two writes: the response must wait for all 10 bytes.
		if _, err := client.Write(make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(make([]byte, 6)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, resp); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	waitServed(t, done)
	if c.Responses.Load() != 3 || c.RespBytes.Load() != 3*3000000 || c.Bytes.Load() != 30 || c.Errors.Load() != 0 {
		t.Fatalf("counters: responses %d bytes %d request bytes %d errors %d",
			c.Responses.Load(), c.RespBytes.Load(), c.Bytes.Load(), c.Errors.Load())
	}
}

func TestServeRespondPipelined(t *testing.T) {
	// Two and a half requests arrive in one read: two responses, and the
	// half request is an error when the peer closes.
	client, c, done := respondPair(t, respondSpec{request: 10, response: 100}, 4096)
	if _, err := client.Write(make([]byte, 25)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, make([]byte, 200)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	waitServed(t, done)
	if c.Responses.Load() != 2 || c.Bytes.Load() != 25 || c.Errors.Load() != 1 {
		t.Fatalf("counters: responses %d request bytes %d errors %d", c.Responses.Load(), c.Bytes.Load(), c.Errors.Load())
	}
}

func TestServeRespondDownload(t *testing.T) {
	client, c, done := respondPair(t, respondSpec{request: 0, response: 12345}, 4096)
	if _, err := io.ReadFull(client, make([]byte, 12345)); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	waitServed(t, done)
	if c.Responses.Load() != 1 || c.RespBytes.Load() != 12345 || c.Errors.Load() != 0 {
		t.Fatalf("counters: %d %d %d", c.Responses.Load(), c.RespBytes.Load(), c.Errors.Load())
	}
}

func TestServeRespondCloseAfter(t *testing.T) {
	// HTTP/1.0 style: one response, then the server closes first.
	client, _, done := respondPair(t, respondSpec{request: 0, response: 5000, closeAfter: 1}, 4096)
	if _, err := io.ReadFull(client, make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	// The server half-closes and waits for our FIN.
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitServed(t, done)
	// Rounds: the server closes after the second response. A third request
	// already in flight is read and dropped, not answered with RST.
	client, c, done := respondPair(t, respondSpec{request: 5, response: 50, closeAfter: 2}, 4096)
	for i := 0; i < 2; i++ {
		if _, err := client.Write(make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, make([]byte, 50)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write(make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	expectEOF(t, client)
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitServed(t, done)
	if c.Responses.Load() != 2 || c.Errors.Load() != 0 || c.Bytes.Load() != 15 {
		t.Fatalf("counters: %d %d %d", c.Responses.Load(), c.Errors.Load(), c.Bytes.Load())
	}
}
