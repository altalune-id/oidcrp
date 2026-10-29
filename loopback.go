package oidcrp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

const (
	loopbackReadHeaderTimeout = 10 * time.Second
	loopbackShutdownTimeout   = 2 * time.Second
)

// LoopbackConfig tunes RunLoopback.
type LoopbackConfig struct {
	// Port is the loopback port to bind; 0 picks a free one.
	Port      int
	Prompt    string
	LoginHint string
	// Open shows the authorization URL to the person, for example by printing it and calling OpenBrowser; it is required.
	Open func(ctx context.Context, authURL string) error
}

// RunLoopback signs a native client in through a loopback redirect (RFC 8252 §7.3) on Config.RedirectURI, registered with no port
// such as http://127.0.0.1/callback, and returns the validated tokens once one callback arrives or ctx ends.
func (c *Client) RunLoopback(ctx context.Context, lc LoopbackConfig) (*TokenSet, error) {
	if lc.Open == nil {
		return nil, &Error{Reason: ReasonMisconfigured, Err: errors.New("LoopbackConfig.Open is required")}
	}
	base, err := loopbackRedirect(c.cfg.RedirectURI)
	if err != nil {
		return nil, err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", net.JoinHostPort(base.Hostname(), strconv.Itoa(lc.Port)))
	if err != nil {
		return nil, &Error{Reason: ReasonMisconfigured, Err: fmt.Errorf("bind the loopback redirect: %w", err)}
	}
	redirect := *base
	redirect.Host = ln.Addr().String()
	run := &Client{cfg: c.cfg, src: c.src}
	run.cfg.RedirectURI = redirect.String()

	req, err := NewAuthRequest(lc.Prompt, lc.LoginHint)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	authURL, err := run.AuthCodeURL(ctx, req)
	if err != nil {
		_ = ln.Close()
		return nil, err
	}

	got := make(chan Callback, 1)
	srv := &http.Server{Handler: loopbackHandler(redirect.Path, req.State, got), ReadHeaderTimeout: loopbackReadHeaderTimeout}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = srv.Serve(ln)
	}()
	defer func() {
		stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), loopbackShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(stop)
		<-served
	}()

	if err := lc.Open(ctx, authURL); err != nil {
		return nil, &Error{Reason: ReasonMisconfigured, Err: fmt.Errorf("open the authorization URL: %w", err)}
	}
	select {
	case cb := <-got:
		out, tok, err := run.exchange(ctx, cb, req)
		if err != nil {
			return nil, err
		}
		set, err := run.tokenSet(out, c.cfg.Scopes)
		if err != nil {
			return nil, err
		}
		set.IDToken = tok
		return set, nil
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, &Error{Reason: ReasonCancelled, Err: ctx.Err()}
		}
		return nil, &Error{Reason: ReasonTimeout, Err: ctx.Err()}
	}
}

// SECURITY: RFC 8252 §8.3: bind an IP literal, never "localhost", which a hosts file or resolver may point elsewhere.
func loopbackRedirect(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, &Error{Reason: ReasonMisconfigured, Err: fmt.Errorf("the loopback redirect URI: %w", err)}
	}
	host := u.Hostname()
	if u.Scheme != "http" || host != "127.0.0.1" && host != "::1" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		err := errors.New("the redirect URI must be http on 127.0.0.1 or [::1] with no port, userinfo, query or fragment")
		return nil, &Error{Reason: ReasonMisconfigured, Err: err}
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// SECURITY: a request without this attempt's state is refused and the wait goes on, so a stray local request can't end the sign-in.
func loopbackHandler(path, state string, got chan<- Callback) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		cb := ParseCallback(r.URL.Query())
		if subtle.ConstantTimeCompare([]byte(cb.State), []byte(state)) != 1 {
			http.Error(w, "This sign-in link is not for this terminal.", http.StatusBadRequest)
			return
		}
		select {
		case got <- cb:
		default:
			http.Error(w, "This sign-in was already received.", http.StatusConflict)
			return
		}
		if cb.Error != "" {
			_, _ = fmt.Fprintf(w, "Sign-in failed (%s). You can close this window.\n", errorCode(cb.Error))
			return
		}
		_, _ = fmt.Fprintln(w, "Sign-in received. You can close this window and return to the terminal.")
	})
}

// OpenBrowser opens an http or https URL in the system browser.
func OpenBrowser(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
		return errors.New("oidcrp: OpenBrowser needs an absolute http or https URL")
	}
	name, args := browserCommand(runtime.GOOS, u.String())
	//nolint:gosec // G204: a fixed launcher per OS, and the URL was parsed and re-serialized above.
	if err := exec.CommandContext(ctx, name, args...).Run(); err != nil {
		return fmt.Errorf("oidcrp: open the browser: %w", err)
	}
	return nil
}

func browserCommand(goos, target string) (name string, args []string) {
	switch goos {
	case "darwin":
		return "open", []string{target}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", target}
	default:
		return "xdg-open", []string{target}
	}
}
