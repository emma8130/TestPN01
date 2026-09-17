package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort = "2053"
	DataFolder  = "/app/data"
	ConfigFile  = "/app/data/settings.json"
	CookieName  = "bermuda_session"
	SaltKey     = "BERMUDA1998_SECURE_SALT_V2"
	XHTTPPath   = "/x7f3a9b"
	WSPath      = "/ws"
)

type Settings struct {
	UserHash  string `json:"user_hash"`
	PassHash  string `json:"pass_hash"`
	IsDefault bool   `json:"is_default"`
	Host      string `json:"host"`
	Port      string `json:"port"`
}

func getInitialHash() string {
	raw := string([]byte{67, 97, 122, 97, 114, 115, 101, 110, 115, 101, 49, 50, 51, 52})
	return hashString(raw)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s + ":" + SaltKey))
	return hex.EncodeToString(h[:])
}

func sessionSecret(s Settings) string {
	h := sha256.Sum256([]byte(s.UserHash + ":" + s.PassHash + ":" + SaltKey))
	return hex.EncodeToString(h[:])
}

func superviseXray() {
	for {
		cmd := exec.Command("/usr/local/bin/xray", "run", "-config", "/app/config.json")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Printf("[CRITICAL] Xray startup failed: %v. Retrying in 5s...\n", err)
			time.Sleep(5 * time.Second)
			continue
		}
		fmt.Printf("[INFO] Xray-core daemon started successfully (PID: %d)\n", cmd.Process.Pid)
		_ = cmd.Wait()
		fmt.Println("[WARNING] Xray process crashed or terminated. Respawning in 2s...")
		time.Sleep(2 * time.Second)
	}
}

func getSettings() Settings {
	initH := getInitialHash()
	s := Settings{
		UserHash:  initH,
		PassHash:  initH,
		IsDefault: true,
	}

	b, err := os.ReadFile(ConfigFile)
	if err == nil {
		_ = json.Unmarshal(b, &s)
		if s.UserHash == "" || s.PassHash == "" {
			s.UserHash = initH
			s.PassHash = initH
			s.IsDefault = true
			saveSettings(s)
		}
	} else {
		saveSettings(s)
	}
	return s
}

func saveSettings(s Settings) {
	_ = os.MkdirAll(DataFolder, 0755)
	b, _ := json.Marshal(s)
	_ = os.WriteFile(ConfigFile, b, 0644)
}

func checkAuth(r *http.Request, s Settings) bool {
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	expected := sessionSecret(s)
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expected)) == 1
}

func setAuthCookie(w http.ResponseWriter, r *http.Request, s Settings) {
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    sessionSecret(s),
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 30,
	})
}

func parseEndpoint(input string) (string, string) {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "tcp://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")

	if strings.Contains(s, ":") {
		parts := strings.Split(s, ":")
		if len(parts) == 2 {
			host := strings.TrimSpace(parts[0])
			port := strings.TrimSpace(parts[1])
			if _, err := strconv.Atoi(port); err == nil {
				return host, port
			}
		}
	}
	return s, "443"
}

func newStreamingReverseProxy(target string) *httputil.ReverseProxy {
	u, _ := url.Parse(target)
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = 50 * time.Millisecond
	return proxy
}

func main() {
	go superviseXray()

	xhttpProxy := newStreamingReverseProxy("http://127.0.0.1:443")
	wsProxy := newStreamingReverseProxy("http://127.0.0.1:8080")

	http.HandleFunc(XHTTPPath, func(w http.ResponseWriter, r *http.Request) {
		xhttpProxy.ServeHTTP(w, r)
	})

	http.HandleFunc(WSPath, func(w http.ResponseWriter, r *http.Request) {
		wsProxy.ServeHTTP(w, r)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()
		if !checkAuth(r, current) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if current.IsDefault {
			http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodPost {
			action := r.FormValue("action")
			if action == "save_connection" {
				endpoint := r.FormValue("endpoint")
				h, p := parseEndpoint(endpoint)
				if h != "" && p != "" {
					current.Host = h
					current.Port = p
					saveSettings(current)
				}
			} else if action == "save_security" {
				newU := strings.TrimSpace(r.FormValue("new_username"))
				newP := strings.TrimSpace(r.FormValue("new_password"))
				if newU != "" && newP != "" {
					current.UserHash = hashString(newU)
					current.PassHash = hashString(newP)
					current.IsDefault = false
					saveSettings(current)
					setAuthCookie(w, r, current)
				}
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		displayEndpoint := ""
		if current.Host != "" && current.Port != "" {
			displayEndpoint = current.Host + ":" + current.Port
		}

		html := strings.ReplaceAll(dashboardHTML, "{{ENDPOINT}}", displayEndpoint)
		html = strings.ReplaceAll(html, "{{HOST}}", current.Host)
		html = strings.ReplaceAll(html, "{{PORT}}", current.Port)
		html = strings.ReplaceAll(html, "{{XHTTP_PATH}}", XHTTPPath)
		html = strings.ReplaceAll(html, "{{WS_PATH}}", WSPath)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()

		if r.Method == http.MethodPost {
			user := strings.TrimSpace(r.FormValue("username"))
			pass := strings.TrimSpace(r.FormValue("password"))

			validUser := subtle.ConstantTimeCompare([]byte(hashString(user)), []byte(current.UserHash)) == 1
			validPass := subtle.ConstantTimeCompare([]byte(hashString(pass)), []byte(current.PassHash)) == 1

			if validUser && validPass {
				setAuthCookie(w, r, current)
				if current.IsDefault {
					http.Redirect(w, r, "/onboarding", http.StatusSeeOther)
					return
				}
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
			return
		}

		errNotice := ""
		if r.URL.Query().Get("error") == "1" {
			errNotice = `<div class="error-msg">Invalid credentials. Please check your username and password.</div>`
		}

		html := strings.ReplaceAll(loginHTML, "{{ERROR}}", errNotice)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/onboarding", func(w http.ResponseWriter, r *http.Request) {
		current := getSettings()
		if !checkAuth(r, current) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		if !current.IsDefault {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if r.Method == http.MethodPost {
			newU := strings.TrimSpace(r.FormValue("new_username"))
			newP := strings.TrimSpace(r.FormValue("new_password"))
			initH := getInitialHash()

			if newU != "" && newP != "" && (hashString(newU) != initH || hashString(newP) != initH) {
				current.UserHash = hashString(newU)
				current.PassHash = hashString(newP)
				current.IsDefault = false
				saveSettings(current)
				setAuthCookie(w, r, current)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/onboarding?error=1", http.StatusSeeOther)
			return
		}

		errNotice := ""
		if r.URL.Query().Get("error") == "1" {
			errNotice = `<div class="error-msg">New credentials cannot match default values or be left blank.</div>`
		}

		html := strings.ReplaceAll(onboardingHTML, "{{ERROR}}", errNotice)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, html)
	})

	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})

	listenPort := os.Getenv("PORT")
	if listenPort == "" {
		listenPort = DefaultPort
	}
	if !strings.HasPrefix(listenPort, ":") {
		listenPort = ":" + listenPort
	}

	fmt.Printf("[INFO] BERMUDA1998 Engine listening on port %s\n", listenPort)
	if err := http.ListenAndServe(listenPort, nil); err != nil {
		fmt.Printf("[FATAL] Web server terminated: %v\n", err)
	}
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign In - BERMUDA1998</title>
<style>
  body { background: #060913; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { background: #0f172a; padding: 2.2rem; border-radius: 1rem; width: 100%; max-width: 360px; box-shadow: 0 25px 50px rgba(0,0,0,0.7); border: 1px solid #1e293b; }
  h2 { text-align: center; margin-bottom: 1.2rem; color: #38bdf8; font-size: 1.25rem; font-weight: 700; }
  .error-msg { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; font-size: 0.8rem; padding: 0.6rem; border-radius: 0.4rem; margin-bottom: 1rem; text-align: center; }
  label { display: block; font-size: 0.8rem; margin-bottom: 0.35rem; color: #94a3b8; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 0.5rem; border: 1px solid #334155; background: #060913; color: white; box-sizing: border-box; font-size: 0.9rem; }
  input:focus { border-color: #38bdf8; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 0.5rem; border: none; background: #38bdf8; color: #060913; font-weight: 700; cursor: pointer; font-size: 0.95rem; }
  button:hover { background: #0284c7; }
</style>
</head>
<body>
<div class="card">
  <h2>BERMUDA1998 Panel</h2>
  {{ERROR}}
  <form method="POST">
    <label>Username</label>
    <input type="text" name="username" required autofocus>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>`

const onboardingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Setup - BERMUDA1998</title>
<style>
  body { background: #060913; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
  .card { background: #0f172a; padding: 2.2rem; border-radius: 1rem; width: 100%; max-width: 380px; box-shadow: 0 25px 50px rgba(0,0,0,0.7); border: 1px solid #1e293b; }
  h2 { text-align: center; margin-bottom: 0.5rem; color: #38bdf8; font-size: 1.25rem; font-weight: 700; }
  p { font-size: 0.82rem; color: #94a3b8; text-align: center; margin-bottom: 1.2rem; line-height: 1.4; }
  .error-msg { background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444; color: #fca5a5; font-size: 0.8rem; padding: 0.6rem; border-radius: 0.4rem; margin-bottom: 1rem; text-align: center; }
  label { display: block; font-size: 0.8rem; margin-bottom: 0.35rem; color: #94a3b8; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 1.2rem; border-radius: 0.5rem; border: 1px solid #334155; background: #060913; color: white; box-sizing: border-box; font-size: 0.9rem; }
  input:focus { border-color: #38bdf8; outline: none; }
  button { width: 100%; padding: 0.8rem; border-radius: 0.5rem; border: none; background: #10b981; color: #060913; font-weight: 700; cursor: pointer; font-size: 0.95rem; }
  button:hover { background: #059669; }
</style>
</head>
<body>
<div class="card">
  <h2>Action Required</h2>
  <p>Default credentials must be updated before accessing your panel dashboard.</p>
  {{ERROR}}
  <form method="POST">
    <label>New Username</label>
    <input type="text" name="new_username" required autofocus>
    <label>New Password</label>
    <input type="password" name="new_password" required>
    <button type="submit">Activate Dashboard</button>
  </form>
</div>
</body>
</html>`

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BERMUDA1998 Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
  body { background: #060913; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 1.5rem 1rem; display: flex; justify-content: center; }
  .box { width: 100%; max-width: 500px; background: #0f172a; padding: 1.8rem; border-radius: 1.2rem; box-shadow: 0 25px 50px rgba(0,0,0,0.7); border: 1px solid #1e293b; }
  .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.4rem; }
  .top-bar h1 { font-size: 1.2rem; color: #38bdf8; margin: 0; font-weight: 700; }
  .exit { color: #f87171; text-decoration: none; font-size: 0.8rem; border: 1px solid #ef4444; padding: 0.25rem 0.65rem; border-radius: 0.4rem; }

  .step-label { display: block; font-size: 0.85rem; margin-bottom: 0.4rem; color: #cbd5e1; font-weight: 600; }
  input { width: 100%; padding: 0.75rem; margin-bottom: 0.8rem; border-radius: 0.5rem; border: 1px solid #334155; background: #060913; color: white; box-sizing: border-box; font-family: monospace; font-size: 0.85rem; }
  input:focus { border-color: #38bdf8; outline: none; }

  .btn-save { width: 100%; padding: 0.75rem; border-radius: 0.5rem; border: none; background: #0284c7; color: white; font-weight: 600; cursor: pointer; font-size: 0.9rem; margin-bottom: 1.4rem; }
  .btn-save:hover { background: #0369a1; }

  .selector-row { display: flex; background: #060913; border-radius: 0.75rem; padding: 0.35rem; margin-bottom: 1.2rem; border: 1px solid #1e293b; gap: 0.35rem; }
  .sel-btn { flex: 1; text-align: center; padding: 0.65rem 0.4rem; font-size: 0.8rem; font-weight: 600; border-radius: 0.5rem; cursor: pointer; color: #94a3b8; transition: 0.2s; user-select: none; }
  .sel-btn.active { background: #38bdf8; color: #060913; font-weight: 700; }

  .qr-frame { background: white; padding: 0.8rem; border-radius: 0.65rem; width: fit-content; margin: 0 auto 1rem auto; display: flex; justify-content: center; }
  .btn-copy { width: 100%; padding: 0.85rem; border-radius: 0.5rem; border: none; background: #10b981; color: #060913; font-weight: 700; font-size: 0.95rem; cursor: pointer; margin-bottom: 1.5rem; }
  .btn-copy:hover { background: #059669; }

  .divider { border-top: 1px solid #1e293b; margin: 1.5rem 0 1.2rem 0; }
  .section-title { font-size: 0.9rem; font-weight: 600; color: #cbd5e1; margin-bottom: 0.8rem; }
  .tip-box { font-size: 0.75rem; color: #64748b; background: #060913; padding: 0.6rem; border-radius: 0.4rem; margin-bottom: 1.2rem; border-left: 3px solid #38bdf8; }
</style>
</head>
<body>
<div class="box">
  <div class="top-bar">
    <h1>BERMUDA1998 Panel</h1>
    <a href="/logout" class="exit">Sign Out</a>
  </div>

  <form method="POST">
    <input type="hidden" name="action" value="save_connection">
    <label class="step-label">Step 1: Domain / TCP Endpoint</label>
    <input type="text" name="endpoint" value="{{ENDPOINT}}" placeholder="e.g. your-subdomain.up.railway.app:443" required>
    <button type="submit" class="btn-save">Save Connection</button>
  </form>

  <label class="step-label">Step 2: Transport Protocol</label>
  <div class="selector-row">
    <div class="sel-btn active" id="btnXHTTP" onclick="setTransport('xhttp')">XHTTP (Throne/PC)</div>
    <div class="sel-btn" id="btnWS" onclick="setTransport('ws')">WebSocket (NVP/Mobile)</div>
  </div>

  <label class="step-label">Step 3: Security & Encryption</label>
  <div class="selector-row">
    <div class="sel-btn active" id="btnTLS" onclick="setSecurity('tls')">TLS (Port 443 / Domain)</div>
    <div class="sel-btn" id="btnNone" onclick="setSecurity('none')">Plain (TCP Proxy / High-Port)</div>
  </div>

  <label class="step-label">Step 4: Traffic Profile</label>
  <div class="selector-row">
    <div class="sel-btn active" id="btnNormal" onclick="setProfile('normal')">Standard (Dual-Stack)</div>
    <div class="sel-btn" id="btnAI" onclick="setProfile('ai')">AI Shield (IPv6 Clean)</div>
  </div>

  <div class="tip-box" id="clientTip">
    Optimized for Throne (Windows 11) and NVP (Android 16). No flow parameter applied.
  </div>

  <div class="qr-frame" id="qrcode"></div>
  <button class="btn-copy" onclick="copyConfig()">Copy Config URL</button>

  <div class="divider"></div>
  <div class="section-title">Account Security</div>
  <form method="POST">
    <input type="hidden" name="action" value="save_security">
    <label>New Username</label>
    <input type="text" name="new_username" placeholder="Update Username" required>
    <label>New Password</label>
    <input type="password" name="new_password" placeholder="Update Password" required>
    <button type="submit" class="btn-save" style="background:#475569;margin-bottom:0;">Update Credentials</button>
  </form>
</div>

<script>
  let currentTransport = 'xhttp';
  let currentSecurity = 'tls';
  let currentProfile = 'normal';

  const idNormal = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d";
  const idAI     = "f9e8d7c6-b5a4-3210-fedc-ba9876543210";
  const h = "{{HOST}}";
  const p = "{{PORT}}";
  const xhttpPath = "{{XHTTP_PATH}}";
  const wsPath = "{{WS_PATH}}";
  let vlessURL = "";

  function setTransport(t) {
    currentTransport = t;
    document.getElementById('btnXHTTP').classList.toggle('active', t === 'xhttp');
    document.getElementById('btnWS').classList.toggle('active', t === 'ws');
    updateTip();
    render();
  }

  function setSecurity(s) {
    currentSecurity = s;
    document.getElementById('btnTLS').classList.toggle('active', s === 'tls');
    document.getElementById('btnNone').classList.toggle('active', s === 'none');
    render();
  }

  function setProfile(pr) {
    currentProfile = pr;
    document.getElementById('btnNormal').classList.toggle('active', pr === 'normal');
    document.getElementById('btnAI').classList.toggle('active', pr === 'ai');
    render();
  }

  function updateTip() {
    const tip = document.getElementById('clientTip');
    if (currentTransport === 'xhttp') {
      tip.innerText = "XHTTP Mode: Maximum resilience against DPI packet analysis. Recommended for Throne (Win 11) and modern NVP.";
    } else {
      tip.innerText = "WebSocket Mode: Maximum compatibility for all mobile clients including older NapsternetV/NVP.";
    }
  }

  function render() {
    if (!h || !p) {
      document.getElementById('qrcode').innerHTML = '<span style="color:#000;font-size:12px">Configure Domain/IP above</span>';
      return;
    }

    const uid = (currentProfile === 'ai') ? idAI : idNormal;
    const tagSuffix = (currentProfile === 'ai') ? " [AI-Clean]" : "";
    let params = [];

    if (currentTransport === 'xhttp') {
      params.push("type=xhttp");
      params.push("path=" + encodeURIComponent(xhttpPath));
      params.push("mode=auto");
      if (currentSecurity === 'tls') {
        params.push("security=tls");
        params.push("sni=" + encodeURIComponent(h));
        params.push("host=" + encodeURIComponent(h));
        params.push("fp=chrome");
        params.push("alpn=h2,http/1.1");
      } else {
        params.push("security=none");
        params.push("host=" + encodeURIComponent(h));
      }
    } else {
      params.push("type=ws");
      params.push("path=" + encodeURIComponent(wsPath));
      if (currentSecurity === 'tls') {
        params.push("security=tls");
        params.push("sni=" + encodeURIComponent(h));
        params.push("host=" + encodeURIComponent(h));
        params.push("fp=chrome");
      } else {
        params.push("security=none");
        params.push("host=" + encodeURIComponent(h));
      }
    }

    const tag = encodeURIComponent("BERMUDA - " + currentTransport.toUpperCase() + tagSuffix);
    vlessURL = "vless://" + uid + "@" + h + ":" + p + "?" + params.join("&") + "#" + tag;

    document.getElementById('qrcode').innerHTML = '';
    new QRCode(document.getElementById('qrcode'), { text: vlessURL, width: 180, height: 180 });
  }

  function copyConfig() {
    if (!vlessURL) return alert('Please configure host and port first.');
    navigator.clipboard.writeText(vlessURL);
    alert('VLESS Config URL copied to clipboard.');
  }

  if (p && p !== "443") {
    setSecurity('none');
  } else {
    render();
  }
</script>
</body>
</html>`
