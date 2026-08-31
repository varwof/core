// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

// Command bench runs an embedded varwof-core load test.
//
// It starts a full core server in-process against a SQLite database,
// signs admin/user certificates under a Root→People CA hierarchy, and hammers
// the real /api/v1/certs endpoint with either regular (tls-client) or AIC
// (agent-proxy) issuance.
//
// Usage:
//
//	bench -mode stress -scenario aic -duration 5m -agents 100
//	bench -mode random -scenario regular -interval 90s -agents 1000 -duration 20m
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"
)

func main() {
	var (
		mode      = flag.String("mode", "stress", "load mode: stress | random")
		scenario  = flag.String("scenario", "regular", "cert scenario: regular | aic")
		duration  = flag.Duration("duration", 5*time.Minute, "test duration (e.g. 5m 10m 20m)")
		agents    = flag.Int("agents", 100, "number of concurrent agent workers")
		users     = flag.Int("users", 0, "number of user certs for AIC (default = agents)")
		qps       = flag.Float64("qps", 0, "global target QPS for stress mode (0 = unlimited)")
		interval  = flag.Duration("interval", 10*time.Minute, "mean request interval per agent (random mode)")
		dbPath    = flag.String("db", "", "SQLite database path (default: bench-work/bench.db)")
		port      = flag.Int("port", 0, "HTTP listen port (0 = auto)")
		jsonOut   = flag.Bool("json", false, "emit JSON report only")
		outFile   = flag.String("out", "", "write report to file (JSON)")
		maxpend   = flag.Int("maxpending", 0, "record-buffer max pending (0 = server default 20000)")
		syncWr    = flag.Bool("sync", false, "disable record buffer (synchronous DB writes)")
		useEngine = flag.Bool("engine", false, "enable in-memory engine (memory-is-truth + async persist, production architecture)")
		cpuProf   = flag.String("cpuprofile", "", "write a golang CPU profile to file (pprof)")
		memProf   = flag.String("memprofile", "", "write a golang heap profile to file (pprof)")
		verbose   = flag.Bool("v", false, "verbose progress output")
		profile   = flag.String("profile", "", "device_profile preset applied to the embedded server config (\"\" | low_mem | high_throughput)")
	)
	flag.Parse()

	if *mode != "stress" && *mode != "random" {
		fatalf("invalid -mode %q (want stress or random)", *mode)
	}
	if *scenario != "regular" && *scenario != "aic" {
		fatalf("invalid -scenario %q (want regular or aic)", *scenario)
	}
	if *agents < 1 {
		fatalf("-agents must be >= 1")
	}
	if *users == 0 {
		*users = *agents
	}
	if *dbPath == "" {
		*dbPath = filepath.Join("bench-work", "bench.db")
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		fatalf("create work dir: %v", err)
	}

	opts := Options{
		Mode:          *mode,
		Scenario:      *scenario,
		Duration:      *duration,
		Agents:        *agents,
		Users:         *users,
		QPS:           *qps,
		Interval:      *interval,
		DBPath:        *dbPath,
		Port:          *port,
		MaxPending:    *maxpend,
		Sync:          *syncWr,
		Engine:        *useEngine,
		Verbose:       *verbose,
		DeviceProfile: *profile,
	}

	env, err := NewEnv(opts)
	if err != nil {
		fatalf("setup: %v", err)
	}

	var cpuF *os.File
	if *cpuProf != "" {
		cpuF, err = os.Create(*cpuProf)
		if err != nil {
			fatalf("create cpuprofile: %v", err)
		}
		if err := pprof.StartCPUProfile(cpuF); err != nil {
			fatalf("start cpuprofile: %v", err)
		}
	}

	fmt.Printf("server up: http://%s (db=%s peak=%s ca=people)\n",
		env.Addr, env.DBPath, formatBytes(env.DBSize()))

	rep, err := env.Run(opts)
	if err != nil {
		fatalf("run: %v", err)
	}

	// Stop the CPU profile right after the timed load loop so the sample covers
	// the request path (the shutdown drain can take longer than the run itself).
	if cpuF != nil {
		pprof.StopCPUProfile()
		cpuF.Close()
	}

	env.Close()
	// After graceful shutdown the record buffer is drained and the SQLite WAL
	// is checkpointed; report the settled on-disk footprint and row count.
	rep.Totals.DBSize = env.DBSize()
	rep.Totals.CertCount = CountCertsInFile(opts.DBPath)

	if *memProf != "" {
		mf, err := os.Create(*memProf)
		if err == nil {
			runtime.GC()
			pprof.WriteHeapProfile(mf)
			mf.Close()
		}
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(rep.JSON()), 0o644); err != nil {
			fatalf("write report: %v", err)
		}
	}

	if *jsonOut {
		fmt.Println(rep.JSON())
	} else {
		fmt.Print(rep.Text())
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "bench: "+format+"\n", args...)
	os.Exit(1)
}

// Options carries the full load-test configuration.
type Options struct {
	Mode          string
	Scenario      string
	Duration      time.Duration
	Agents        int
	Users         int
	QPS           float64
	Interval      time.Duration
	DBPath        string
	Port          int
	MaxPending    int
	Sync          bool
	Engine        bool
	Verbose       bool
	DeviceProfile string
}

func (o Options) String() string {
	return strings.Join([]string{
		"mode=" + o.Mode,
		"scenario=" + o.Scenario,
		"duration=" + o.Duration.String(),
		"agents=" + fmt.Sprint(o.Agents),
		"users=" + fmt.Sprint(o.Users),
		fmt.Sprintf("qps=%.0f", o.QPS),
		"interval=" + o.Interval.String(),
		"db=" + o.DBPath,
		fmt.Sprintf("maxpending=%d", o.MaxPending),
		fmt.Sprintf("sync=%v", o.Sync),
		fmt.Sprintf("engine=%v", o.Engine),
		"profile=" + o.DeviceProfile,
	}, " ")
}
