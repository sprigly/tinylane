package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestM7bOOMAdj(t *testing.T) {
	c := exec.Command("sleep", "30")
	if err := c.Start(); err != nil {
		t.Skip(err)
	}
	defer c.Process.Kill()
	setOOMAdj(c.Process.Pid, coreOOMAdj)
	b, _ := os.ReadFile("/proc/" + strconv.Itoa(c.Process.Pid) + "/oom_score_adj")
	if strings.TrimSpace(string(b)) != "-800" {
		t.Fatalf("core oom_score_adj=%q", b)
	}
}


func TestM7bMemAvail(t *testing.T) {
	if a := memAvailableMB(); a <= 0 {
		t.Fatalf("MemAvailable=%d", a)
	}
}

func TestM7bMeasureLowMem(t *testing.T) {
	dir := t.TempDir()
	sc := filepath.Join(dir, "sqm.sh")
	os.WriteFile(sc, []byte("#!/bin/sh\necho '{\"error\":\"low_mem\",\"avail_mb\":31,\"min_mb\":40}'\n"), 0o755)
	d := &Daemon{sqmScript: sc, runDir: dir}
	_, err := d.sqmMeasure()
	if err == nil || !strings.Contains(err.Error(), "内存只有 31 MB") {
		t.Fatalf("err=%v", err)
	}
	os.WriteFile(sc, []byte("#!/bin/sh\necho '{\"down_mbit\":100,\"up_mbit\":50}'\n"), 0o755)
	r, err := d.sqmMeasure()
	if err != nil || r["down_mbit"] != 100 {
		t.Fatalf("r=%v err=%v", r, err)
	}
}
