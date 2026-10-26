const { useState, useEffect } = React;

// Example edge app: it takes its certificate from its edge client and uses it for signed, encrypted messages.

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

const selectClass = "w-full bg-white border border-slate-200 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs text-slate-700 outline-none";

// Messages encrypted for the recipient's certificate, sent over the radio links by the edge client:
// only the recipient's private key opens them, carriers on the way see ciphertext.
function SecretMessages({ appId }) {
  const others = PEERS.filter((p) => p !== appId);
  const [to, setTo] = useState(others[others.length - 1]);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [sendResult, setSendResult] = useState(null);
  const [inbox, setInbox] = useState([]);

  const loadInbox = () =>
    fetch("/api/messages/inbox")
      .then((res) => res.json())
      .then((data) => setInbox(data.messages || []))
      .catch(() => {});

  useEffect(() => { loadInbox(); }, []);

  const handleSend = async (e) => {
    e.preventDefault();
    setBusy(true);
    setSendResult(null);
    try {
      const res = await fetch("/api/messages/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ to, text }),
      });
      const data = await res.json();
      setSendResult(res.ok ? { ok: `Encrypted for ${data.to} (certificate ${data.envelope.recipient_serial}): ${data.status}, ${data.plaintext_bytes} B text → ${data.radio_bytes} B on the radio link.` } : { error: errorText(data) });
      if (res.ok) { setText(""); loadInbox(); }
    } catch (err) {
      setSendResult({ error: `Connection error: ${err.message}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <form onSubmit={handleSend} className="space-y-2">
        <select value={to} onChange={(e) => setTo(e.target.value)} className={selectClass}>
          {others.map((p) => <option key={p} value={p}>to {p}</option>)}
        </select>
        <textarea value={text} onChange={(e) => setText(e.target.value)} rows={2} placeholder="Message text"
          className={`${selectClass} resize-none`} />
        <button type="submit" disabled={busy || !text.trim()}
          className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded-lg text-xs shadow-xs transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50">
          {busy ? "Encrypting..." : "Encrypt and send"}
        </button>
      </form>
      {sendResult?.error && <div className="mt-3 p-3 rounded-lg text-xs bg-rose-50 border border-rose-200 text-rose-800">{sendResult.error}</div>}
      {sendResult?.ok && <div className="mt-3 p-3 rounded-lg text-xs bg-emerald-50 border border-emerald-200 text-emerald-800">{sendResult.ok}</div>}

      <div className="flex items-center justify-between mt-5 mb-2">
        <h3 className="text-xs font-semibold text-slate-700">Held by this node</h3>
        <button onClick={loadInbox} className="text-xs text-indigo-600 hover:underline cursor-pointer">Refresh</button>
      </div>
      {inbox.length === 0 && <div className="text-xs text-slate-400">No messages.</div>}
      <div className="space-y-2">
        {inbox.map((m, i) => (
          <div key={i} className={`p-3 rounded-lg text-xs border ${m.readable ? (m.sender_verified ? "bg-emerald-50 border-emerald-200" : "bg-rose-50 border-rose-200") : "bg-slate-50 border-slate-200"}`}>
            <div className="text-slate-500 mb-1">{m.from} → {m.to} · {m.role}{m.route?.length ? ` · ${m.route.join(" → ")}` : ""}</div>
            {m.readable
              ? <>
                  <div className="text-slate-900 font-medium">{m.text}</div>
                  <div className={`mt-1 ${m.sender_verified ? "text-emerald-700" : "text-rose-700"}`}>
                    {m.sender_verified ? "✓ " : "✗ Sender not verified: "}{m.sender_reason}
                  </div>
                </>
              : <>
                  <div className="font-mono text-[11px] text-slate-600 break-all">{m.ciphertext}</div>
                  <div className="text-rose-700 mt-1">{m.reason}</div>
                </>}
          </div>
        ))}
      </div>
    </div>
  );
}

function App() {
  const [appId, setAppId] = useState(null);

  useEffect(() => {
    fetch("/api/pki/status")
      .then((res) => res.json())
      .then((data) => setAppId(data.app_id))
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans flex items-start justify-center p-6">
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl p-6 shadow-xs mt-16">
        <h1 className="text-base font-bold text-slate-900 flex items-center gap-2">
          <ShieldCheckIcon className="w-5 h-5 text-indigo-600" />
          Edge App {appId && <span className="text-slate-400 font-medium">{appId}</span>}
        </h1>
        <p className="text-xs text-slate-500 mt-1 mb-5">
          Signed with the own certificate, encrypted with the recipient's, sent over the radio links. Carriers only see ciphertext.
        </p>
        {appId && <SecretMessages appId={appId} />}
      </div>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
