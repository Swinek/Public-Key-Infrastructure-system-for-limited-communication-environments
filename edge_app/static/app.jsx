const { useState, useEffect } = React;

// Example edge app: it only takes what it needs from its edge client and authenticates with another edge app.

function ShieldCheckIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

const PEERS = ["app_1", "app_2", "app_3"];

const errorText = (data) => {
  const d = data?.detail;
  if (!d) return "Error";
  if (typeof d === "string") return d;
  return d.error || JSON.stringify(d);
};

function Direction({ title, result }) {
  const ok = result?.authenticated;
  return (
    <div className={`p-3 rounded-lg text-xs leading-relaxed border ${ok ? "bg-emerald-50 border-emerald-200" : "bg-rose-50 border-rose-200"}`}>
      <div className="font-semibold text-slate-800">{ok ? "✓" : "✗"} {title}</div>
      <div className="text-slate-700">{result?.reason}</div>
    </div>
  );
}

function App() {
  const [appId, setAppId] = useState(null);
  const [peer, setPeer] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  useEffect(() => {
    fetch("/api/pki/status")
      .then((res) => res.json())
      .then((data) => {
        setAppId(data.app_id);
        setPeer(PEERS.find((p) => p !== data.app_id));
      })
      .catch(() => {});
  }, []);

  const handleAuth = async (e) => {
    e.preventDefault();
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch("/api/auth/peer", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ peer }),
      });
      const data = await res.json();
      setResult(res.ok ? data : { error: errorText(data) });
    } catch (err) {
      setResult({ error: `Connection error: ${err.message}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans flex items-start justify-center p-6">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl p-6 shadow-xs mt-16">
        <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
          <ShieldCheckIcon className="w-5 h-5 text-indigo-600" />
          Edge App {appId && <span className="text-slate-400 font-medium">{appId}</span>}
        </h1>
        <p className="text-xs text-slate-500 mt-1 mb-5">
          Takes its certificate from the edge client and authenticates with another edge app.
        </p>
        <form onSubmit={handleAuth} className="space-y-3">
          <select
            value={peer}
            onChange={(e) => setPeer(e.target.value)}
            className="w-full bg-white border border-slate-200 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs text-slate-700 outline-none"
          >
            {PEERS.filter((p) => p !== appId).map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button
            type="submit"
            disabled={busy || !peer}
            className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded-lg text-xs shadow-xs transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50"
          >
            {busy ? "Authenticating..." : "Authenticate"}
          </button>
        </form>

        {result?.error && (
          <div className="mt-4 p-3 rounded-lg text-xs bg-rose-50 border border-rose-200 text-rose-800">{result.error}</div>
        )}
        {result && !result.error && (
          <div className="mt-4 space-y-2">
            <div className={`text-sm font-semibold ${result.authenticated ? "text-emerald-700" : "text-rose-700"}`}>
              {result.authenticated ? "Authenticated" : "Not authenticated"}
              {result.certificate_serial && <span className="text-slate-400 font-normal text-xs"> · own certificate {result.certificate_serial}</span>}
            </div>
            {result.warning && <div className="text-[11px] text-amber-700">{result.warning}</div>}
            <Direction title={`${result.peer} accepted us`} result={result.peer_verified_us} />
            <Direction title={`We accepted ${result.peer}`} result={result.we_verified_peer} />
          </div>
        )}
      </div>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
