package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestM9MemLimit(t *testing.T) {
	if coreMemLimitMB(&Config{}) != 40 {
		t.Fatal("default")
	}
	z := 0
	if effMemLimitMB(coreMemLimitMB(&Config{CoreMemLimitMB: &z})) != 96 {
		t.Fatal("off")
	}
	for _, v := range []int{0, 30, 120} {
		if validMemLimit(v) != nil {
			t.Fatal(v)
		}
	}
	for _, v := range []int{-1, 10, 29, 121} {
		if validMemLimit(v) == nil {
			t.Fatal(v)
		}
	}
	dir := t.TempDir()
	d := &Daemon{runDir: dir}
	v := 55
	d.writeMemLimit(&Config{CoreMemLimitMB: &v})
	applyMemLimitFile(dir)
	if curMemLimit.Load() != 55<<20 {
		t.Fatal(curMemLimit.Load())
	}
	os.WriteFile(filepath.Join(dir, memLimitFile), []byte("0"), 0o600)
	applyMemLimitFile(dir)
	if curMemLimit.Load() != 96<<20 {
		t.Fatal("off file")
	}
	m := &MemHist{}
	m.addTraffic(10, 100)
	m.sample(os.Getpid())
	m.addTraffic(1, 2)
	m.sample(os.Getpid())
	p := m.snapshot()
	if len(p) != 2 || p[0].Down != 100 || p[1].Down != 2 || p[1].Up != 1 || p[0].Core <= 0 || p[0].Avail <= 0 {
		t.Fatalf("%+v", p)
	}
}
