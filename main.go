package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web/*
var webFS embed.FS

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-version") {
		fmt.Println("webauthnproxy", version)
		return
	}
	log.Printf("webauthnproxy %s", version)
	cfg, err := LoadConfig()
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	store, err := OpenStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	secret, err := loadSecret(cfg.DataDir, cfg.SessionSecret)
	if err != nil {
		log.Fatalf("session secret: %v", err)
	}

	uv := protocol.VerificationRequired
	if getenv("USER_VERIFICATION", "required") == "preferred" {
		uv = protocol.VerificationPreferred
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: uv,
		},
	})
	if err != nil {
		log.Fatalf("webauthn: %v", err)
	}

	if err := watchImports(store, filepath.Join(cfg.DataDir, "import"), cfg.RPID, uv == protocol.VerificationRequired); err != nil {
		log.Fatalf("import folder: %v", err)
	}

	app := &App{
		cfg:      cfg,
		store:    store,
		wa:       wa,
		sessions: &Sessions{secret: secret, ttl: cfg.SessionTTL},
		login:    NewCeremonies[webauthn.SessionData](),
		enroll:   NewCeremonies[enrollState](),
	}

	servers := []*http.Server{{Addr: cfg.Listen, Handler: app.publicHandler()}}
	if cfg.EnrollEnabled {
		servers = append(servers, &http.Server{Addr: cfg.EnrollListen, Handler: app.enrollHandler()})
		if store.CredentialCount() == 0 {
			app.bootstrapToken()
		}
	}
	if cfg.ToolEnabled {
		servers = append(servers, &http.Server{Addr: cfg.ToolListen, Handler: app.toolHandler()})
	}
	for _, s := range servers {
		s.ReadHeaderTimeout = 10 * time.Second
		go func() {
			log.Printf("listening on %s", s.Addr)
			if err := s.ListenAndServe(); err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}
	if cfg.Mode == "forward" {
		log.Printf("forwardAuth: GET %s/_wap/verify (%d registered passkey(s))", cfg.Listen, store.Count())
	} else {
		log.Printf("proxy -> %s (%d registered passkey(s))", cfg.Upstream, store.Count())
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(ctx)
	}
}
