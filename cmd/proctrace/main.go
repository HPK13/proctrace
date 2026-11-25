// Command proctrace is a lightweight process-monitoring agent. It watches
// process starts, validates parent/child lineage, hashes executables, scores
// each process against detection rules, and writes the results locally or
// forwards them to a central collector.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/HPK13/proctrace/internal/collector"
	"github.com/HPK13/proctrace/internal/config"
	"github.com/HPK13/proctrace/internal/detect"
	"github.com/HPK13/proctrace/internal/enrich"
	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/harden"
	"github.com/HPK13/proctrace/internal/output"
	"github.com/HPK13/proctrace/internal/redact"
	"github.com/HPK13/proctrace/rules"
)

// version is set at build time: -ldflags "-X main.version=v0.2.0".
var version = "dev"

func main() {
	var (
		cfgPath     = flag.String("config", "", "path to JSON config (defaults apply if omitted)")
		rulesPath   = flag.String("rules", "", "use this rule file instead of the built-in rules")
		once        = flag.Bool("once", false, "scan running processes once, print results and exit")
		alertsOnly  = flag.Bool("alerts", false, "only output processes that matched a rule")
		dumpRules   = flag.Bool("dump-rules", false, "print the built-in rules (to start a custom rule file) and exit")
		allowUnsafe = flag.Bool("allow-unsafe-paths", false, "run elevated even if non-admin users can modify the agent's files (testing only)")
		showVer     = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("proctrace: ")

	switch {
	case *showVer:
		fmt.Println("proctrace", version)
		return
	case *dumpRules:
		os.Stdout.Write(rules.Default)
		return
	}

	exe, exeDir := executable()

	cfg := config.Default()
	configDir := exeDir
	if *cfgPath != "" {
		abs, err := filepath.Abs(*cfgPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if cfg, err = config.Load(abs); err != nil {
			log.Fatalf("config: %v", err)
		}
		*cfgPath, configDir = abs, filepath.Dir(abs)
	}
	cfg.Resolve(configDir, exeDir)
	if *rulesPath != "" {
		abs, err := filepath.Abs(*rulesPath)
		if err != nil {
			log.Fatalf("rules: %v", err)
		}
		cfg.RulesPath = abs
	}
	if *alertsOnly {
		cfg.OnlyAlerts = true
	}

	// Refuse to run with admin rights from files a normal user can change.
	targets := []harden.Target{{Path: exe, Role: "executable"}}
	if *cfgPath != "" {
		targets = append(targets, harden.Target{Path: *cfgPath, Role: "config"})
	}
	if cfg.RulesPath != "" {
		targets = append(targets, harden.Target{Path: cfg.RulesPath, Role: "rules"})
	}
	if !*once {
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			log.Fatalf("data_dir: %v", err)
		}
		targets = append(targets, harden.Target{Path: cfg.DataDir, Dir: true, Role: "data folder"})
	}
	for _, f := range []string{cfg.Forward.CAFile, cfg.Forward.CertFile, cfg.Forward.KeyFile} {
		if cfg.Mode == config.ModeForward && f != "" {
			targets = append(targets, harden.Target{Path: f, Role: "certificate"})
		}
	}
	safetyCheck(targets, *allowUnsafe)

	engine, err := loadRules(cfg.RulesPath)
	if err != nil {
		log.Fatalf("rules: %v", err)
	}

	sinks, err := buildSinks(cfg, *once)
	if err != nil {
		log.Fatalf("output: %v", err)
	}
	defer func() {
		for _, s := range sinks {
			if err := s.Close(); err != nil {
				log.Printf("close: %v", err)
			}
		}
	}()

	enricher := enrich.New(cfg.Hash.Enabled, cfg.Hash.MaxFileMB<<20)
	host := event.LocalHost()

	handle := func(p event.Process, initial bool) {
		enricher.Enrich(&p)
		// Detection sees the full command line; only the output is redacted.
		dets, score := engine.Evaluate(p)
		if cfg.OnlyAlerts && len(dets) == 0 {
			return
		}
		p.CommandLine = privacy(p.CommandLine, cfg.Privacy)
		ev := event.New(p, dets, score, initial, host, version)
		for _, s := range sinks {
			if err := s.Write(ev); err != nil {
				log.Printf("write: %v", err)
			}
		}
	}

	snap := collector.NewSnapshot(cfg.ScanInterval.Duration)

	if *once {
		procs, err := snap.Once()
		if err != nil {
			log.Fatalf("scan: %v", err)
		}
		for _, p := range procs {
			handle(p, true)
		}
		return
	}

	log.Printf("%s starting: mode=%s data=%s rules=%d from %s (sha256 %s) interval=%s",
		version, cfg.Mode, cfg.DataDir, engine.Len(), engine.Source, engine.SHA256[:16], cfg.ScanInterval)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := snap.Run(ctx, handle); err != nil {
		log.Fatalf("collector: %v", err)
	}
	log.Printf("stopped")
}

// executable returns the agent's own path (symlinks resolved) and folder.
func executable() (string, string) {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot locate own executable: %v", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return exe, filepath.Dir(exe)
}

func safetyCheck(targets []harden.Target, allowUnsafe bool) {
	if !harden.Elevated() {
		return
	}
	problems := harden.Check(targets)
	if len(problems) == 0 {
		return
	}
	for _, p := range problems {
		log.Printf("unsafe: %s", p)
	}
	if allowUnsafe {
		log.Printf("WARNING: running elevated anyway (-allow-unsafe-paths). A non-admin user who can change these files can run code as admin.")
		return
	}
	log.Fatalf("refusing to run with admin rights: non-admin users can modify the files above. " +
		"Install proctrace in an admin-only folder such as C:\\Program Files\\proctrace (see README, \"Installing safely\").")
}

func loadRules(path string) (*detect.Engine, error) {
	if path == "" {
		return detect.Load(rules.Default, "built-in rules")
	}
	return detect.LoadFile(path)
}

func privacy(cmd string, p config.Privacy) string {
	if p.DropCommandLines {
		return ""
	}
	if p.RedactCommandLines {
		cmd = redact.CommandLine(cmd)
	}
	return redact.Truncate(cmd, p.MaxCommandLine)
}

// buildSinks returns stdout (if enabled) plus the mode's sink. A one-off
// scan only prints to stdout.
func buildSinks(cfg config.Config, once bool) ([]output.Sink, error) {
	if once {
		return []output.Sink{output.NewWriter(os.Stdout)}, nil
	}
	var sinks []output.Sink
	if cfg.Stdout {
		sinks = append(sinks, output.NewWriter(os.Stdout))
	}
	switch cfg.Mode {
	case config.ModeLocal:
		f, err := output.OpenFile(cfg.LocalFile(), cfg.Local.MaxSizeMB<<20)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, f)
	case config.ModeForward:
		fwd := cfg.Forward
		fwd.SpoolPath = cfg.SpoolFile()
		f, err := output.NewForwarder(fwd)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, f)
	}
	return sinks, nil
}
