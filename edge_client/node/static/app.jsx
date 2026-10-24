const { useState, useEffect, useRef } = React;

function RadioIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
    </svg>
  );
}

function RefreshCwIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
      <path d="M3 21v-5h5" />
    </svg>
  );
}

function UploadIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="17 8 12 3 7 8" />
      <line x1="12" y1="3" x2="12" y2="15" />
    </svg>
  );
}

function ShieldCheckIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function DownloadIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
      <polyline points="7 10 12 15 17 10" />
      <line x1="12" y1="15" x2="12" y2="3" />
    </svg>
  );
}

const VERDICT_STYLES = {
  valid: { label: "VALID", cls: "bg-emerald-50 text-emerald-700 border-emerald-200" },
  revoked: { label: "REVOKED", cls: "bg-rose-50 text-rose-700 border-rose-200" },
  invalid: { label: "INVALID", cls: "bg-rose-50 text-rose-700 border-rose-200" },
  unknown: { label: "UNKNOWN", cls: "bg-amber-50 text-amber-800 border-amber-200" }
};

function VerdictBadge({ status }) {
  const s = VERDICT_STYLES[status] || { label: status || "-", cls: "bg-slate-50 text-slate-600 border-slate-200" };
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold border ${s.cls}`}>{s.label}</span>
  );
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : "-");

const fmtDay = (iso) => (iso ? new Date(iso).toLocaleDateString() : "-");
const cn = (subject) => (subject?.match(/CN=([^,]+)/) || [])[1] || subject || "-";

const errorText = (data) => {
  const d = data?.detail;
  if (!d) return data?.error || "Error";
  if (typeof d === "string") return d;
  return d.error || JSON.stringify(d);
};

const card = "bg-white border border-slate-200 rounded-xl shadow-xs";
const button = "bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg text-xs cursor-pointer disabled:opacity-50 flex items-center justify-center gap-1.5";
const input = "bg-white border border-slate-200 focus:border-indigo-500 rounded-lg px-2.5 py-1.5 text-xs text-slate-700 outline-none";

function Feedback({ result }) {
  if (!result) return null;
  return (
    <div className={`px-3 py-2 rounded-lg text-[11px] leading-snug border ${
      result.ok ? "bg-emerald-50 border-emerald-200 text-emerald-800" : "bg-rose-50 border-rose-200 text-rose-800"}`}>
      {result.text}
    </div>
  );
}

const REQUEST_STYLES = {
  NEW: "bg-slate-50 text-slate-600 border-slate-200",
  PENDING: "bg-amber-50 text-amber-800 border-amber-200",
  RELAYED: "bg-sky-50 text-sky-700 border-sky-200",
  APPROVED: "bg-emerald-50 text-emerald-700 border-emerald-200",
  REJECTED: "bg-rose-50 text-rose-700 border-rose-200"
};

// The key is generated here and only the request (CSR) goes to the CA; the certificate arrives by itself on a WAN
// contact once the administrator approves the request. No certificate, key or Root CA is uploaded by hand.
function RequestCard({ store, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const request = store?.request;

  const newRequest = async () => {
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch("/api/certs/csr", { method: "POST" });
      const data = await res.json();
      if (res.ok) {
        setResult({ ok: true, text: "New key generated – the request goes to the CA on the next WAN contact." });
        onChanged(data.status);
      } else {
        setResult({ ok: false, text: errorText(data) });
      }
    } catch (err) {
      setResult({ ok: false, text: `Connection error: ${err.message}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`${card} p-4 space-y-3`}>
      <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
        <ShieldCheckIcon className="w-4 h-4 text-indigo-600" /> Certificate request
      </h3>
      {!store?.ca_pinned && (
        <p className="text-[11px] text-rose-700">Root CA is not pinned (CA_FINGERPRINT) – the node accepts no CA.</p>
      )}
      {request ? (
        <div className="space-y-1 text-[11px] text-slate-600">
          <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-semibold border ${
            REQUEST_STYLES[request.status] || REQUEST_STYLES.NEW}`}>{request.status}</span>
          <div className="font-mono break-all" title="SHA-256 of the public key">{request.key_fingerprint}</div>
          <div>Created {fmtDate(request.created_at)}{request.reason ? ` – ${request.reason}` : ""}</div>
          {request.status === "RELAYED" && (
            <div className="text-sky-700">
              Carried to the CA by the neighbours. The CA panel shows this key fingerprint with the route – compare
              them out of band before the administrator approves.
            </div>
          )}
        </div>
      ) : (
        <p className="text-[11px] text-slate-500">
          No pending request. A request is filed automatically when the node has no valid certificate.
        </p>
      )}
      <Feedback result={result} />
      <button type="button" onClick={newRequest} disabled={busy} className={`${button} w-full`}>
        {busy ? "Generating..." : "New key + request"}
      </button>
    </div>
  );
}

// CRL delivered out of band (e.g. on a USB stick): stored only if signed by the Root CA and newer.
function CrlUploadCard({ onStored }) {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const handleUpload = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append("crl", file);
    setBusy(true);
    setResult(null);
    try {
      const res = await fetch("/api/certs/crl", { method: "POST", body: formData });
      const data = await res.json();
      if (res.ok) {
        setResult({ ok: true, text: data.stored.length ? "CRL stored." : data.warnings.join(" ") });
        setFile(null);
        if (inputRef.current) inputRef.current.value = "";
        onStored(data.status);
      } else {
        setResult({ ok: false, text: errorText(data) });
      }
    } catch (err) {
      setResult({ ok: false, text: `Connection error: ${err.message}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleUpload} className={`${card} p-4 space-y-3`}>
      <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
        <UploadIcon className="w-4 h-4 text-indigo-600" /> CRL from removable media
      </h3>
      <input ref={inputRef} type="file" onChange={(e) => setFile(e.target.files[0] || null)}
        className="w-full text-xs text-slate-600" />
      <Feedback result={result} />
      <button type="submit" disabled={busy || !file} className={`${button} w-full`}>
        {busy ? "Uploading..." : "Upload CRL"}
      </button>
    </form>
  );
}

// Offline check: the stored certificate (or any other file) against the stored Root CA and CRL.
function CheckCard() {
  const [file, setFile] = useState(null);
  const [at, setAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [verdict, setVerdict] = useState(null);

  const handleCheck = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    if (file) formData.append("cert", file);
    if (at) formData.append("at", new Date(at).toISOString());
    setBusy(true);
    setVerdict(null);
    try {
      const res = await fetch("/api/certs/verify", { method: "POST", body: formData });
      const data = await res.json();
      setVerdict(res.ok ? data : { status: "error", reason: errorText(data) });
    } catch (err) {
      setVerdict({ status: "error", reason: `Connection error: ${err.message}` });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={handleCheck} className={`${card} p-4 space-y-3`}>
      <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
        <ShieldCheckIcon className="w-4 h-4 text-indigo-600" /> Check offline
      </h3>
      <input type="file" onChange={(e) => setFile(e.target.files[0] || null)} className="w-full text-xs text-slate-600"
        title="Empty = the stored certificate" />
      <input type="datetime-local" value={at} onChange={(e) => setAt(e.target.value)} className={`${input} w-full`}
        title="Check at this moment (empty = now)" />
      {verdict && (
        <div className="flex items-start gap-2 text-[11px] leading-snug text-slate-700">
          <VerdictBadge status={verdict.status} />
          <span>{verdict.reason}</span>
        </div>
      )}
      <button type="submit" disabled={busy} className={`${button} w-full`}>
        {busy ? "Checking..." : file ? "Check file" : "Check stored certificate"}
      </button>
    </form>
  );
}

function Field({ label, children, mono = false }) {
  return (
    <div>
      <div className="text-[11px] text-slate-400">{label}</div>
      <div className={`text-xs text-slate-800 break-all ${mono ? "font-mono" : "font-medium"}`}>{children}</div>
    </div>
  );
}

function CertificateCard({ store }) {
  const cert = store?.certificate;
  const crlStale = store?.crl?.next_update && new Date(store.crl.next_update) < new Date();
  return (
    <div className={`${card} overflow-hidden`}>
      <div className="px-4 py-3 border-b border-slate-100 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <ShieldCheckIcon className="w-4 h-4 text-indigo-600" /> Certificate
          {cert && <VerdictBadge status={cert.verdict?.status} />}
        </h3>
        <div className="flex gap-2 text-[11px]">
          <span className="px-2 py-0.5 rounded-full border border-slate-200 bg-slate-50 text-slate-600" title={store?.ca?.fingerprint}>
            Root CA: {store?.ca ? cn(store.ca.subject) : "none"}
          </span>
          <span className={`px-2 py-0.5 rounded-full border ${crlStale
            ? "border-amber-200 bg-amber-50 text-amber-800" : "border-slate-200 bg-slate-50 text-slate-600"}`}
            title={store?.crl ? `next update ${fmtDate(store.crl.next_update)}` : ""}>
            CRL: {store?.crl ? `#${store.crl.number}${crlStale ? " (expired)" : ""}` : "none"}
          </span>
        </div>
      </div>
      {!cert ? (
        <p className="text-xs text-slate-400 py-10 text-center">No certificate yet – it arrives once the CA approves the request.</p>
      ) : (
        <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-x-6 gap-y-3">
            <Field label="Subject">{cn(cert.subject)}</Field>
            <Field label="Serial" mono>{cert.serial_number}</Field>
            <Field label="Valid">{fmtDay(cert.not_before)} – {fmtDay(cert.not_after)}</Field>
            <Field label="Installed">{fmtDate(cert.installed_at)}</Field>
          </div>
          <div className="flex items-center justify-between gap-4 pt-3 border-t border-slate-100">
            <span className="text-[11px] text-slate-500">{cert.verdict?.reason}</span>
            <a href="/api/certs/certificate"
              className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-indigo-700 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200">
              <DownloadIcon className="w-3.5 h-3.5" /> Download
            </a>
          </div>
        </div>
      )}
    </div>
  );
}

function CertificatesPanel() {
  const [store, setStore] = useState(null);

  useEffect(() => {
    fetch("/api/certs").then((res) => res.json()).then(setStore).catch(() => {});
  }, []);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 items-start">
      <div className="lg:col-span-2"><CertificateCard store={store} /></div>
      <div className="space-y-5">
        <RequestCard store={store} onChanged={setStore} />
        <CrlUploadCard onStored={setStore} />
        <CheckCard />
      </div>
    </div>
  );
}

function NeighboursPanel({ peers }) {
  return (
    <div className={`${card} overflow-hidden`}>
      <table className="w-full text-xs">
        <thead className="text-[11px] text-slate-400 bg-slate-50/60">
          <tr>
            {["Node", "ID", "Address", "Connected since"].map((h) => <th key={h} className="text-left font-medium px-4 py-2">{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {peers.map((p) => (
            <tr key={p.id} className="border-t border-slate-100">
              <td className="px-4 py-2 font-semibold text-slate-900">{p.name}</td>
              <td className="px-4 py-2 font-mono text-[11px] text-slate-500">{p.id}</td>
              <td className="px-4 py-2 font-mono text-[11px]">{p.ip}:{p.port}</td>
              <td className="px-4 py-2">{new Date(p.connected_since * 1000).toLocaleTimeString()}</td>
            </tr>
          ))}
          {peers.length === 0 && (
            <tr><td colSpan="4" className="text-center py-10 text-slate-400">No neighbours in radio range.</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function App() {
  const [status, setStatus] = useState(null);
  const [activeTab, setActiveTab] = useState("certificates");

  useEffect(() => {
    const load = () => fetch("/api/status").then((res) => res.json()).then(setStatus).catch(() => {});
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);

  if (!status) {
    return (
      <div className="min-h-screen flex items-center justify-center gap-2 text-slate-500 text-sm">
        <RefreshCwIcon className="w-5 h-5 animate-spin text-indigo-600" /> Connecting to node...
      </div>
    );
  }

  const peers = status.peers || [];
  const online = Boolean(status.has_internet ?? status.has_default_gateway);
  const tabs = [["certificates", "Certificates"], ["neighbours", `Radio neighbours (${peers.length})`]];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans">
      <nav className="bg-white border-b border-slate-200">
        <div className="max-w-7xl mx-auto px-6 py-2.5 flex flex-wrap items-center gap-x-6 gap-y-2">
          <div className="flex items-center gap-2">
            <RadioIcon className="w-5 h-5 text-indigo-600" />
            <h1 className="text-sm font-bold text-slate-900">{status.node_name}</h1>
            <span className="text-[11px] font-mono text-slate-400" title="P2P address">
              {(status.local_ips || []).join(", ") || "no radio link"}
            </span>
          </div>
          <div className="flex bg-slate-100 p-0.5 rounded-lg border border-slate-200">
            {tabs.map(([id, label]) => (
              <button key={id} onClick={() => setActiveTab(id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md cursor-pointer ${
                  activeTab === id ? "bg-white text-slate-900 shadow-xs" : "text-slate-600 hover:text-slate-900"}`}>
                {label}
              </button>
            ))}
          </div>
          <span className={`ml-auto inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 rounded-full border ${
            online ? "text-emerald-700 bg-emerald-50 border-emerald-200" : "text-rose-700 bg-rose-50 border-rose-200"}`}
            title="WAN link to the centre (client.sh internet on|off)">
            <span className={`w-2 h-2 rounded-full ${online ? "bg-emerald-500" : "bg-rose-500"}`}></span>
            {online ? "ONLINE" : "OFFLINE"}
          </span>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-5">
        {activeTab === "certificates" && <CertificatesPanel />}
        {activeTab === "neighbours" && <NeighboursPanel peers={peers} />}
      </main>
    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
