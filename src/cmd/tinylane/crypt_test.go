package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCryptVectors(t *testing.T) {
	for _, v := range cryptVectors {
		ok, err := cryptVerify(v[1], v[0])
		if err != nil || !ok {
			t.Errorf("vector %q %q: ok=%v err=%v", v[0], v[1][:12], ok, err)
		}
		if bad, _ := cryptVerify(v[1], v[0]+"x"); bad {
			t.Errorf("wrong pw accepted for %q", v[1][:12])
		}
	}
	if _, err := cryptVerify("$y$j9T$abc$def", "x"); err != errCryptUnsupported {
		t.Error("yescrypt should be unsupported")
	}
}

func TestShadow(t *testing.T) {
	p := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(p, []byte("daemon:*:0:0:99999:7:::\nroot:"+cryptVectors[0][1]+":20000:0:99999:7:::\nlocked:!:1::::::\n"), 0600)
	if ok, err := verifyShadowPassword(p, "root", cryptVectors[0][0]); !ok || err != nil {
		t.Fatal("root should verify", err)
	}
	if ok, _ := verifyShadowPassword(p, "root", "nope"); ok {
		t.Fatal("wrong accepted")
	}
	if ok, _ := verifyShadowPassword(p, "locked", ""); ok {
		t.Fatal("locked accepted")
	}
	if ok, _ := verifyShadowPassword(p, "daemon", "x"); ok {
		t.Fatal("* accepted")
	}
}
