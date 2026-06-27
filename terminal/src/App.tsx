import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { wsUrl, serverBase, setServerBase, register, login, createTerminal } from "./api";
import "@xterm/xterm/css/xterm.css";
import "./App.css";

type Tab = { id: string; name: string };

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem("nt_token"));
  const onAuth = (t: string) => {
    localStorage.setItem("nt_token", t);
    setToken(t);
  };
  if (!token) return <Login onAuth={onAuth} />;
  return <Workspace token={token} />;
}

function Login({ onAuth }: { onAuth: (token: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [server, setServer] = useState(serverBase());
  const [mode, setMode] = useState<"login" | "register">("login");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setServerBase(server);
    try {
      const { token } = await (mode === "login" ? login : register)(email, password);
      onAuth(token);
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="centered">
      <form className="login" onSubmit={submit}>
        <h2>{mode === "login" ? "Sign in" : "Create account"}</h2>
        <input placeholder="server (https://…)" value={server} onChange={(e) => setServer(e.target.value)} />
        <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <input type="password" placeholder="password (>=6)" value={password} onChange={(e) => setPassword(e.target.value)} />
        {err && <div className="err">{err}</div>}
        <button type="submit" disabled={busy || !email || !password}>
          {busy ? "…" : mode === "login" ? "Sign in" : "Register"}
        </button>
        <button type="button" className="link" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Need an account? Register" : "Have an account? Sign in"}
        </button>
      </form>
    </div>
  );
}

// Each tab is its own terminal (PTY + relay host connection). Tabs persist
// across launches; their PTYs are re-spawned on restore.
function Workspace({ token }: { token: string }) {
  const [tabs, setTabs] = useState<Tab[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("nt_tabs") || "[]");
    } catch {
      return [];
    }
  });
  const [active, setActive] = useState<string | null>(tabs[0]?.id ?? null);
  const [code, setCode] = useState("");
  const [copied, setCopied] = useState(false);
  const creating = useRef(false);

  useEffect(() => {
    localStorage.setItem("nt_tabs", JSON.stringify(tabs));
  }, [tabs]);
  useEffect(() => {
    invoke<string>("pairing_code").then(setCode).catch(() => {});
  }, []);

  const addTab = async () => {
    if (creating.current) return;
    creating.current = true;
    try {
      const t = await createTerminal(token, `tab ${tabs.length + 1}`);
      setTabs((ts) => [...ts, { id: t.id, name: t.name }]);
      setActive(t.id);
    } catch {
      /* offline / auth — ignore, button can be retried */
    } finally {
      creating.current = false;
    }
  };

  // Start with one tab if none were restored.
  useEffect(() => {
    if (tabs.length === 0) addTab();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const closeTab = (id: string) => {
    invoke("pty_close", { id }).catch(() => {});
    setTabs((ts) => {
      const next = ts.filter((t) => t.id !== id);
      setActive((a) => (a === id ? next[next.length - 1]?.id ?? null : a));
      return next;
    });
  };

  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="app">
      <div className="bar">
        <div className="tabs">
          {tabs.map((t) => (
            <span key={t.id} className={"tab" + (t.id === active ? " active" : "")} onClick={() => setActive(t.id)}>
              {t.name}
              <span className="tab-x" onClick={(e) => { e.stopPropagation(); closeTab(t.id); }}>×</span>
            </span>
          ))}
          <span className="tab new" onClick={addTab}>+</span>
        </div>
        <span className="bar-spacer" />
        <span className="bar-label">pairing code</span>
        <code className="bar-code" title={code}>{code ? code.slice(0, 12) + "…" : "—"}</code>
        <button className="bar-btn" onClick={copy} disabled={!code}>{copied ? "copied" : "copy"}</button>
      </div>
      <div className="panes">
        {tabs.map((t) => (
          <TabView key={t.id} id={t.id} token={token} active={t.id === active} />
        ))}
      </div>
    </div>
  );
}

function TabView({ id, token, active }: { id: string; token: string; active: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const termRef = useRef<Terminal | null>(null);

  useEffect(() => {
    if (!hostRef.current) return;
    const term = new Terminal({ fontFamily: "Menlo, monospace", fontSize: 13, cursorBlink: true, theme: { background: "#1e1e1e" } });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    try {
      term.loadAddon(new WebglAddon());
    } catch {
      /* canvas fallback */
    }
    fit.fit();
    termRef.current = term;
    fitRef.current = fit;

    // Filter the shared pty events down to this session.
    const dataUnlisten = listen<{ session: string; data: number[] }>("pty:data", (e) => {
      if (e.payload.session === id) term.write(new Uint8Array(e.payload.data));
    });
    const exitUnlisten = listen<{ session: string }>("pty:exit", (e) => {
      if (e.payload.session === id) term.write("\r\n[process exited]\r\n");
    });

    const enc = new TextEncoder();
    const write = (b: Uint8Array) => invoke("pty_write", { id, data: Array.from(b) }).catch(() => {});
    term.onData((s) => write(enc.encode(s)));

    let spawned = false;
    invoke("pty_spawn", { id, cmd: null, cols: term.cols, rows: term.rows })
      .then(() => {
        spawned = true;
        invoke("pty_resize", { id, cols: term.cols, rows: term.rows }).catch(() => {});
      })
      .catch((e) => term.write(`\r\n[spawn failed: ${e}]\r\n`));
    invoke("relay_connect", { id, url: wsUrl(), token, terminal: id }).catch(() => {});

    const dropUnlisten = getCurrentWebview().onDragDropEvent((e) => {
      if (!active || e.payload.type !== "drop") return;
      const text = e.payload.paths.map((p) => (/\s/.test(p) ? `'${p}'` : p)).join(" ") + " ";
      write(enc.encode(text));
    });

    const ro = new ResizeObserver(() => {
      fit.fit();
      if (spawned) invoke("pty_resize", { id, cols: term.cols, rows: term.rows }).catch(() => {});
    });
    ro.observe(hostRef.current);

    return () => {
      ro.disconnect();
      dataUnlisten.then((f) => f());
      exitUnlisten.then((f) => f());
      dropUnlisten.then((f) => f());
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Refit when this tab becomes visible (a hidden pane has zero size).
  useEffect(() => {
    if (active && fitRef.current && termRef.current) {
      fitRef.current.fit();
      invoke("pty_resize", { id, cols: termRef.current.cols, rows: termRef.current.rows }).catch(() => {});
    }
  }, [active, id]);

  return <div ref={hostRef} className="term" style={{ display: active ? "block" : "none" }} />;
}
