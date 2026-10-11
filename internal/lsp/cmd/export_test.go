// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

const ExampleOffset = exampleOffset

// TestServeNoPortFlag checks that the -port debugging flag, which bound the
// LSP server to all network interfaces, no longer exists (CVE-2026-42503).
func TestServeNoPortFlag(t *testing.T) {
	typ := reflect.TypeOf(Serve{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if name, ok := field.Tag.Lookup("flag"); ok && name == "port" {
			t.Errorf("Serve.%s still declares the -port flag", field.Name)
		}
	}
}

// TestServeListenRejectsImplicitAllInterfaces checks that -listen=:port,
// which would implicitly bind all network interfaces, is rejected before any
// listener is created (CVE-2026-42503).
func TestServeListenRejectsImplicitAllInterfaces(t *testing.T) {
	for _, addr := range []string{":0", ":"} {
		s := &Serve{Address: addr, app: &Application{}}
		errc := make(chan error, 1)
		go func() { errc <- s.Run(context.Background()) }()
		select {
		case err := <-errc:
			if err == nil {
				t.Errorf("-listen=%s: got nil error, want rejection", addr)
			} else if !strings.Contains(err.Error(), "implicitly binds all network interfaces") {
				t.Errorf("-listen=%s: got error %q, want it to mention implicitly binding all network interfaces", addr, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatalf("-listen=%s: server did not return; it is listening on all network interfaces", addr)
		}
	}
}
