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
	"syscall"

	"github.com/HPK13/proctrace/internal/collector"
	"github.com/HPK13/proctrace/internal/config"
	"github.com/HPK13/proctrace/internal/detect"
	"github.com/HPK13/proctrace/internal/enrich"
	"github.com/HPK13/proctrace/internal/event"
	"github.com/HPK13/proctrace/internal/output"
)

// version is set at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	var (
		cfgPath    = flag.String("config", "", "path to JSON config (defaults apply if omitted)")
		rulesPath  = flag.String("rules", "", "override rules_path from the config")
		once       = flag.Bool("once", false, "scan running processes once, print results and exit")
		alertsOnly = flag.Bool("alerts", false, "only output processes that matched a rule")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("proctrace: ")

	if *showVer {
		fmt.Println("proctrace", version)
		return
	}

	cfg := config.Default()
	if *cfgPath != "" {
		var err error
		if cfg, err = config.Load(*cfgPath); err != nil {
			log.Fatalf("config: %v", err)
		}
	}
	if *rulesPath != "" {
		cfg.RulesPath = *rulesPath
	}
	if *alertsOnly {
		cfg.OnlyAlerts = true
	}

	engine, err := detect.LoadFile(cfg.RulesPath)
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

	var hasher *enrich.Hasher
	if cfg.Hash.Enabled {
		hasher = enrich.NewHasher(cfg.Hash.MaxFileMB << 20)
	}
	host := event.LocalHost()

	handle := func(p event.Process, initial bool) {
		if hasher != nil {
			hasher.Enrich(&p)
		}
		dets, score := engine.Evaluate(p)
		if cfg.OnlyAlerts && len(dets) == 0 {
			return
		}
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

	log.Printf("%s starting: mode=%s rules=%d interval=%s", version, cfg.Mode, engine.Len(), cfg.ScanInterval)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := snap.Run(ctx, handle); err != nil {
		log.Fatalf("collector: %v", err)
	}
	log.Printf("stopped")
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
		f, err := output.OpenFile(cfg.Local.Path, cfg.Local.MaxSizeMB<<20)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, f)
	case config.ModeForward:
		f, err := output.NewForwarder(cfg.Forward)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, f)
	}
	return sinks, nil
}
