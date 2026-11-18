package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestParseRespond(t *testing.T) {
	for in, want := range map[string]respondSpec{
		"100:10k": {100, 10000},
		"0:1m":    {0, 1000000},
		"1g:1":    {1000000000, 1},
	} {
		got, err := parseRespond(in)
		if err != nil || *got != want {
			t.Fatalf("%q: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"100", "100:0", "x:1", "1:-1", ":1", "1:", "99999999999999999999k:1"} {
		if _, err := parseRespond(in); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
	if s, err := parseRespond(""); s != nil || err != nil {
		t.Fatalf("empty: %+v %v", s, err)
	}
}

// respondPair runs serveRespond on one end of a loopback TCP connection.
func respondPair(t *testing.T, spec respondSpec) (net.Conn, *counters, chan struct{}) {
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
		serveRespond(conn, &spec, make([]byte, 7), &c) // a small buffer splits requests across reads
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client, &c, done
}

func TestServeRespondRounds(t *testing.T) {
	client, c, done := respondPair(t, respondSpec{request: 10, response: 3000000})
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
	// Two requests at once (pipelined) get two responses.
	if _, err := client.Write(make([]byte, 20)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := io.ReadFull(client, resp); err != nil {
			t.Fatal(err)
		}
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(resp); n != 0 || err != io.EOF {
		t.Fatalf("extra response bytes: %d %v", n, err)
	}
	<-done
	if c.Responses.Load() != 5 || c.RespBytes.Load() != 5*3000000 || c.Bytes.Load() != 50 {
		t.Fatalf("counters: responses %d bytes %d request bytes %d", c.Responses.Load(), c.RespBytes.Load(), c.Bytes.Load())
	}
}

func TestServeRespondDownload(t *testing.T) {
	client, c, done := respondPair(t, respondSpec{request: 0, response: 12345})
	got, err := io.ReadAll(io.LimitReader(client, 12345))
	if err != nil || len(got) != 12345 {
		t.Fatalf("download: %d %v", len(got), err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	<-done
	if c.Responses.Load() != 1 || c.RespBytes.Load() != 12345 {
		t.Fatalf("counters: %d %d", c.Responses.Load(), c.RespBytes.Load())
	}
}
