package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"grok-oauth-api/internal/config"
	"grok-oauth-api/internal/oauth"
	"grok-oauth-api/internal/server"
	"grok-oauth-api/internal/store"
)

func Main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "start":
		runStart()
	case "oauth":
		runOAuth()
	case "status":
		runStatus()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`grok-oauth-api - xAI Grok OpenAI-compatible OAuth proxy

Usage:
  grok-oauth-api <command>

Commands:
  start    Start the proxy server
  oauth    Perform automatic browser OAuth login and save tokens
  status   Show saved token status
  help     Show this help message

Examples:
  grok-oauth-api start
  grok-oauth-api oauth
  grok-oauth-api status`)
}

func runStart() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	srv := server.New(cfg)

	go func() {
		addr := fmt.Sprintf(":%s", cfg.Port)
		fmt.Printf("grok-oauth-proxy listening on %s\n", addr)
		if err := srv.Listen(addr); err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\nshutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown error: %v\n", err)
		os.Exit(1)
	}
}

func runOAuth() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	oauthClient := oauth.NewClient(
		cfg.XAIClientID,
		cfg.XAIAuthorize,
		cfg.XAITokenURL,
		cfg.XAIDeviceURL,
		cfg.XAIRedirectURI,
		cfg.XAIScope,
		cfg.UserAgent,
	)
	tokenStore := store.New(cfg.TokenPath, oauthClient)
	_ = tokenStore.Load()

	callbackServer := oauth.NewCallbackServer()
	if _, err := callbackServer.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start callback server: %v\n", err)
		os.Exit(1)
	}
	defer callbackServer.Stop()

	pkce, err := oauth.GeneratePKCE()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate PKCE: %v\n", err)
		os.Exit(1)
	}
	state, err := oauth.GenerateState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate state: %v\n", err)
		os.Exit(1)
	}
	nonce, err := oauth.GenerateState()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate nonce: %v\n", err)
		os.Exit(1)
	}

	authURL := oauthClient.BuildAuthorizeURL(pkce, state, nonce)

	fmt.Println("Opening browser for xAI OAuth login...")
	if err := oauth.OpenBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "failed to open browser: %v\n", err)
		fmt.Printf("Please open this URL manually:\n%s\n", authURL)
	}

	tokens, err := callbackServer.WaitForCallback(pkce, state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OAuth failed: %v\n", err)
		os.Exit(1)
	}

	if err := tokenStore.SetTokens(tokens); err != nil {
		fmt.Fprintf(os.Stderr, "failed to save tokens: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OAuth completed successfully. Tokens saved to %s\n", cfg.TokenPath)
}

func runStatus() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	oauthClient := oauth.NewClient(
		cfg.XAIClientID,
		cfg.XAIAuthorize,
		cfg.XAITokenURL,
		cfg.XAIDeviceURL,
		cfg.XAIRedirectURI,
		cfg.XAIScope,
		cfg.UserAgent,
	)
	tokenStore := store.New(cfg.TokenPath, oauthClient)
	if err := tokenStore.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load tokens: %v\n", err)
		os.Exit(1)
	}

	data := tokenStore.Get()
	if data.AccessToken == "" {
		fmt.Println("No access token found. Run 'grok-oauth-api oauth' to log in.")
		return
	}

	status := map[string]interface{}{
		"token_path":    cfg.TokenPath,
		"has_access":    data.AccessToken != "",
		"has_refresh":   data.RefreshToken != "",
		"expires_at":    data.ExpiresAt.Format(time.RFC3339),
		"expired":       data.IsExpired(0),
		"needs_refresh": data.IsExpired(oauth.RefreshSkew),
	}

	b, _ := json.MarshalIndent(status, "", "  ")
	fmt.Println(string(b))
}
