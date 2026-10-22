const { useState, useEffect, useRef } = React;

function RadioIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="2" />
      <path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14" />
    </svg>
  );
}

function FileTextIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

function CheckCircleIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
      <polyline points="22 4 12 14.01 9 11.01" />
    </svg>
  );
}

function AlertTriangleIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
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

function SendIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
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

function EyeIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
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

function XIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  );
}

function CopyIcon({ className = "w-4 h-4" }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
      <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
    </svg>
  );
}

function App() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("neighbours");

  const [inbox, setInbox] = useState([]);
  const [recipient, setRecipient] = useState("");
  const [outboundMessage, setOutboundMessage] = useState("");
  const [sendingMsg, setSendingMsg] = useState(false);
  const [msgFeedback, setMsgFeedback] = useState(null);

  const [files, setFiles] = useState([]);
  const [fileToUpload, setFileToUpload] = useState(null);
  const [transferringFile, setTransferringFile] = useState(false);
  const [fileFeedback, setFileFeedback] = useState(null);
  const fileInputRef = useRef(null);

  const [previewFile, setPreviewFile] = useState(null);
  const [previewContent, setPreviewContent] = useState(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [copiedText, setCopiedText] = useState(false);

  const [eventLogs, setEventLogs] = useState([]);

  const addLog = (text, type = "info") => {
    const timeStr = new Date().toISOString().split("T")[1].slice(0, 8);
    setEventLogs((prev) => [
      { time: timeStr, text, type },
      ...prev.slice(0, 49)
    ]);
  };

  const destinations = status?.destinations || [];
  const destinationLabel = (id) => {
    const d = destinations.find((x) => x.id === id);
    if (!d) return id || "?";
    return `${d.name} (in range)`;
  };

  useEffect(() => {
    if (destinations.length > 0 && !destinations.some((d) => d.id === recipient)) {
      setRecipient(destinations[0].id);
    }
  }, [status]);

  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      }
    } catch (err) {
      addLog(`Error fetching status: ${err.message}`, "error");
    } finally {
      setLoading(false);
    }
  };

  const fetchInbox = async () => {
    try {
      const res = await fetch("/api/p2p/inbox");
      if (res.ok) {
        const data = await res.json();
        setInbox(data.messages || []);
      }
    } catch (err) {}
  };

  const fetchFiles = async () => {
    try {
      const res = await fetch("/api/p2p/files");
      if (res.ok) {
        const data = await res.json();
        setFiles(data.files || []);
      }
    } catch (err) {}
  };

  useEffect(() => {
    fetchStatus();
    fetchInbox();
    fetchFiles();
    addLog("Client console initialized successfully.", "info");

    const timer = setInterval(() => {
      fetchStatus();
      fetchInbox();
      fetchFiles();
    }, 3000);

    return () => clearInterval(timer);
  }, []);

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!outboundMessage.trim()) return;

    setSendingMsg(true);
    setMsgFeedback(null);
    addLog(`Sending P2P message to ${destinationLabel(recipient)}...`, "info");
    try {
      const res = await fetch("/api/p2p/send-message", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: outboundMessage.trim(), to: recipient })
      });
      const data = await res.json();
      if (res.ok) {
        const route = (data.route || []).join(" → ");
        addLog(`Message delivered to ${recipient} (ID: ${data.delivery_confirmation?.inbox_id}, route: ${route})`, "success");
        setMsgFeedback({ success: true, text: `Message successfully delivered to ${recipient}. Route: ${route}` });
        setOutboundMessage("");
      } else {
        addLog(`Message rejected: ${data.detail || "Error"}`, "error");
        setMsgFeedback({ success: false, text: `Failed to send message: ${data.detail}` });
      }
    } catch (err) {
      addLog(`P2P send error: ${err.message}`, "error");
      setMsgFeedback({ success: false, text: `Connection error: ${err.message}` });
    } finally {
      setSendingMsg(false);
    }
  };

  const handleSendFile = async (e) => {
    e.preventDefault();
    if (!fileToUpload) return;

    setTransferringFile(true);
    setFileFeedback(null);
    addLog(`Sending file '${fileToUpload.name}' to ${destinationLabel(recipient)}...`, "info");

    const formData = new FormData();
    formData.append("file", fileToUpload);
    formData.append("to", recipient);

    try {
      const res = await fetch("/api/p2p/send-file", {
        method: "POST",
        body: formData
      });
      const data = await res.json();
      if (res.ok) {
        const route = (data.route || []).join(" → ");
        addLog(`File '${data.filename}' transferred successfully to ${data.recipient} (route: ${route}).`, "success");
        setFileFeedback({
          success: true,
          text: `File '${data.filename}' (${formatFileSize(data.size_bytes)}) transferred to ${data.recipient}. Route: ${route}`
        });
        setFileToUpload(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
      } else {
        addLog(`File rejected: ${data.detail || "Error"}`, "error");
        setFileFeedback({ success: false, text: `File transfer error: ${data.detail}` });
      }
    } catch (err) {
      addLog(`File transfer failed: ${err.message}`, "error");
      setFileFeedback({ success: false, text: `Network error: ${err.message}` });
    } finally {
      setTransferringFile(false);
    }
  };

  const isImageFile = (filename) => {
    return /\.(jpg|jpeg|png|gif|webp|svg|bmp)$/i.test(filename || "");
  };

  const isTextFile = (filename) => {
    return /\.(txt|pem|crl|crt|key|csr|json|log|md|sh|py|conf|yml|yaml|xml|html|css|js)$/i.test(filename || "");
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 B";
    if (!bytes) return "-";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(i === 0 ? 0 : 1)} ${sizes[i]}`;
  };

  const openPreview = async (f) => {
    setPreviewFile(f);
    setPreviewContent(null);
    setCopiedText(false);

    if (isTextFile(f.filename)) {
      setPreviewLoading(true);
      try {
        const res = await fetch(`/api/p2p/files/${encodeURIComponent(f.filename)}?inline=true`);
        if (res.ok) {
          const txt = await res.text();
          setPreviewContent(txt);
        } else {
          setPreviewContent(`[Error loading text: HTTP ${res.status}]`);
        }
      } catch (err) {
        setPreviewContent(`[Network error: ${err.message}]`);
      } finally {
        setPreviewLoading(false);
      }
    }
  };

  const closePreview = () => {
    setPreviewFile(null);
    setPreviewContent(null);
  };

  if (loading && !status) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="flex items-center gap-3 text-slate-500 text-sm font-medium">
          <RefreshCwIcon className="w-5 h-5 animate-spin text-indigo-600" />
          Connecting to node...
        </div>
      </div>
    );
  }

  const isOnline = Boolean(status?.has_internet ?? status?.has_default_gateway);
  const NODE_COLORS = {
    client_1: { icon: "bg-indigo-50 border-indigo-200 text-indigo-600", badge: "bg-indigo-50 text-indigo-700 border-indigo-200" },
    client_2: { icon: "bg-emerald-50 border-emerald-200 text-emerald-700", badge: "bg-emerald-50 text-emerald-800 border-emerald-200" },
    client_3: { icon: "bg-amber-50 border-amber-200 text-amber-700", badge: "bg-amber-50 text-amber-800 border-amber-200" }
  };
  const nodeColor = NODE_COLORS[status?.node_id || status?.client_id] || {
    icon: "bg-slate-50 border-slate-200 text-slate-600", badge: "bg-slate-50 text-slate-700 border-slate-200"
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans">
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col sm:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${
              nodeColor.icon
            }`}>
              <RadioIcon className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-slate-900">
                  {status?.node_name || status?.client_name || "Client"}
                </h1>
                <span className={`inline-flex px-2 py-0.5 rounded text-[11px] font-semibold border ${
                  nodeColor.badge
                }`}>
                  {status?.node_id || status?.client_id}
                </span>
              </div>
              <p className="text-xs text-slate-500">
                P2P Address: <code className="text-slate-700 font-mono font-medium">{(status?.local_ips || []).map((ip) => `${ip}:${status?.local_port}`).join(", ")}</code>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            {isOnline ? (
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 px-3 py-1.5 rounded-full border border-emerald-200 shadow-2xs">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
                ONLINE
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-700 bg-rose-50 px-3 py-1.5 rounded-full border border-rose-200 shadow-2xs">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                OFFLINE
              </span>
            )}
          </div>
        </div>
      </nav>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="bg-white border border-slate-200 rounded-xl p-4 mb-8 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex bg-slate-100 p-1 rounded-lg w-fit border border-slate-200">
            <button 
              onClick={() => setActiveTab('neighbours')}
              className={`px-4 py-2 text-xs font-medium rounded-md transition-all cursor-pointer ${
                activeTab === 'neighbours' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Radio Neighbours ({(status?.peers || []).length})
            </button>
            <button 
              onClick={() => setActiveTab('messages')}
              className={`px-4 py-2 text-xs font-medium rounded-md transition-all cursor-pointer ${
                activeTab === 'messages' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              P2P Messages ({inbox.length})
            </button>
            <button 
              onClick={() => setActiveTab('files')}
              className={`px-4 py-2 text-xs font-medium rounded-md transition-all cursor-pointer ${
                activeTab === 'files' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              File Transfer ({files.length})
            </button>
            <button 
              onClick={() => setActiveTab('logs')}
              className={`px-4 py-2 text-xs font-medium rounded-md transition-all cursor-pointer ${
                activeTab === 'logs' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Event Log ({eventLogs.length})
            </button>
          </div>

        </div>

        {activeTab === 'neighbours' && (
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
              <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
                <RadioIcon className="w-4 h-4 text-indigo-600" />
                Radio Neighbours
              </h3>
              <span className="text-xs text-slate-400 font-medium">
                {(status?.peers || []).length} in range
              </span>
            </div>
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-100 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-slate-50/50">
                  <th className="py-3 px-4">Node</th>
                  <th className="py-3 px-4">ID</th>
                  <th className="py-3 px-4">Address</th>
                  <th className="py-3 px-4">Connected since</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {(status?.peers || []).map((p) => (
                  <tr key={p.id}>
                    <td className="py-3 px-4 font-semibold text-slate-900">{p.name}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-500">{p.id}</td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-700">{p.ip}:{p.port}</td>
                    <td className="py-3 px-4">
                      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                        {new Date(p.connected_since * 1000).toLocaleTimeString()}
                      </span>
                    </td>
                  </tr>
                ))}
                {(status?.peers || []).length === 0 && (
                  <tr>
                    <td colSpan="4" className="text-center py-8 text-slate-400 text-xs">No neighbours in radio range.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'messages' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs h-fit">
              <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2 border-b border-slate-100 pb-3">
                <SendIcon className="w-4 h-4 text-indigo-600" />
                Send P2P Message
              </h3>
              
              <form onSubmit={handleSendMessage} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Recipient</label>
                  <select
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    className="w-full bg-white border border-slate-200 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs font-medium text-slate-700 outline-none"
                    required
                  >
                    {destinations.length === 0 && <option value="">No known destinations</option>}
                    {destinations.map((d) => (
                      <option key={d.id} value={d.id}>{destinationLabel(d.id)}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Message Content</label>
                  <textarea 
                    rows="4"
                    placeholder="Enter P2P message content..."
                    value={outboundMessage}
                    onChange={(e) => setOutboundMessage(e.target.value)}
                    className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg px-3 py-2 text-xs outline-none transition-all text-slate-900 bg-white"
                    required
                  />
                </div>

                {msgFeedback && (
                  <div className={`p-3 rounded-lg text-xs ${
                    msgFeedback.success 
                      ? "bg-emerald-50 border border-emerald-200 text-emerald-800" 
                      : "bg-rose-50 border border-rose-200 text-rose-800"
                  }`}>
                    {msgFeedback.text}
                  </div>
                )}

                <button 
                  type="submit" 
                  disabled={sendingMsg || !outboundMessage.trim() || !recipient}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded-lg text-xs shadow-xs transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <SendIcon className="w-3.5 h-3.5" />
                  {sendingMsg ? "Sending..." : "Send P2P Message"}
                </button>
              </form>
            </div>

            <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
              <div className="p-5 border-b border-slate-100 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Received Messages Inbox</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Messages delivered to this node (directly or forwarded by neighbours)</p>
                </div>
                <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2.5 py-1 rounded-full border border-slate-200">
                  {inbox.length} messages
                </span>
              </div>

              {inbox.length === 0 ? (
                <div className="p-12 text-center text-slate-400 text-xs">
                  No received messages. Send a message from the other client!
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50/70 border-b border-slate-200 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                        <th className="px-6 py-3.5">ID</th>
                        <th className="px-6 py-3.5">Sender</th>
                        <th className="px-6 py-3.5">Route</th>
                        <th className="px-6 py-3.5">Content</th>
                        <th className="px-6 py-3.5 text-right">Received (UTC)</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-xs">
                      {inbox.map((msg) => (
                        <tr key={msg.msg_id || msg.id} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-6 py-4 font-mono text-slate-400">#{msg.id}</td>
                          <td className="px-6 py-4 font-semibold text-slate-900">{msg.origin_name || msg.sender_name}</td>
                          <td className="px-6 py-4 font-mono text-[11px] text-slate-500">
                            {(msg.route || [msg.sender_id]).join(" → ")}
                          </td>
                          <td className="px-6 py-4 text-slate-700">{msg.message}</td>
                          <td className="px-6 py-4 text-right font-mono text-slate-500">
                            {msg.received_at?.split("T")[1]?.slice(0, 8) || msg.received_at}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'files' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs h-fit">
              <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2 border-b border-slate-100 pb-3">
                <UploadIcon className="w-4 h-4 text-indigo-600" />
                Send File via P2P
              </h3>
              
              <form onSubmit={handleSendFile} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Target Node</label>
                  <select
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    className="w-full bg-white border border-slate-200 focus:border-indigo-500 rounded-lg px-3 py-2 text-xs font-medium text-slate-700 outline-none"
                    required
                  >
                    {destinations.length === 0 && <option value="">No known destinations</option>}
                    {destinations.map((d) => (
                      <option key={d.id} value={d.id}>{destinationLabel(d.id)}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Select file from disk</label>
                  <input 
                    type="file" 
                    ref={fileInputRef}
                    onChange={(e) => setFileToUpload(e.target.files[0] || null)}
                    className="w-full text-xs text-slate-600 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border file:border-slate-200 file:text-xs file:font-medium file:bg-slate-50 file:text-slate-700 hover:file:bg-slate-100 cursor-pointer"
                    required
                  />
                </div>

                {fileFeedback && (
                  <div className={`p-3 rounded-lg text-xs leading-relaxed ${
                    fileFeedback.success 
                      ? "bg-emerald-50 border border-emerald-200 text-emerald-800" 
                      : "bg-rose-50 border border-rose-200 text-rose-800"
                  }`}>
                    {fileFeedback.text}
                  </div>
                )}

                <button 
                  type="submit" 
                  disabled={transferringFile || !fileToUpload || !recipient}
                  className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded-lg text-xs shadow-xs transition-all active:scale-[0.98] cursor-pointer disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  <UploadIcon className="w-3.5 h-3.5" />
                  {transferringFile ? "Sending file..." : "Send File"}
                </button>
              </form>
            </div>

            <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl shadow-xs overflow-hidden">
              <div className="p-5 border-b border-slate-100 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-900">Received Files Storage</h3>
                  <p className="text-xs text-slate-500 mt-0.5">Files received via direct P2P link</p>
                </div>
                <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2.5 py-1 rounded-full border border-slate-200">
                  {files.length} files
                </span>
              </div>

              {files.length === 0 ? (
                <div className="p-12 text-center text-slate-400 text-xs">
                  No received files in storage. Send a file from the other client!
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50/70 border-b border-slate-200 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                        <th className="px-6 py-3.5">Plik</th>
                        <th className="px-6 py-3.5">Rozmiar</th>
                        <th className="px-6 py-3.5 text-right">Akcje</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 text-xs">
                      {files.map((f, idx) => (
                        <tr key={idx} className="hover:bg-slate-50/50 transition-colors">
                          <td className="px-6 py-4 font-semibold text-slate-900">
                            <div className="flex items-center gap-3">
                              {isImageFile(f.filename) ? (
                                <img
                                  src={`/api/p2p/files/${encodeURIComponent(f.filename)}?inline=true`}
                                  alt={f.filename}
                                  onClick={() => openPreview(f)}
                                  className="w-10 h-10 rounded-lg object-cover border border-slate-200 cursor-pointer hover:ring-2 hover:ring-indigo-500 transition-all bg-slate-100 flex-shrink-0"
                                  title="Kliknij, aby otworzyć podgląd"
                                />
                              ) : (
                                <div 
                                  onClick={() => openPreview(f)}
                                  className="w-10 h-10 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center flex-shrink-0 text-slate-500 cursor-pointer hover:bg-slate-100 transition-colors"
                                  title="Kliknij, aby otworzyć podgląd"
                                >
                                  <FileTextIcon className="w-5 h-5 text-slate-400" />
                                </div>
                              )}
                              <div className="min-w-0">
                                <div 
                                  className="truncate font-semibold text-slate-900 cursor-pointer hover:text-indigo-600 transition-colors"
                                  onClick={() => openPreview(f)}
                                  title={f.filename}
                                >
                                  {f.filename}
                                </div>
                                <div className="text-[11px] text-slate-400 font-normal">
                                  {isImageFile(f.filename) ? "Obraz" : isTextFile(f.filename) ? "Dokument / Certyfikat" : "Plik"}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td className="px-6 py-4 font-mono text-slate-500 whitespace-nowrap">
                            {formatFileSize(f.size_bytes)}
                          </td>
                          <td className="px-6 py-4 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                type="button"
                                onClick={() => openPreview(f)}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-slate-700 hover:text-indigo-600 bg-slate-50 hover:bg-indigo-50 rounded-lg border border-slate-200 hover:border-indigo-200 transition-all cursor-pointer"
                                title="Podgląd pliku"
                              >
                                <EyeIcon className="w-3.5 h-3.5" />
                                Podgląd
                              </button>
                              <a
                                href={`/api/p2p/files/${encodeURIComponent(f.filename)}`}
                                download={f.filename}
                                className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow-2xs transition-all cursor-pointer"
                                title="Pobierz plik na dysk"
                              >
                                <DownloadIcon className="w-3.5 h-3.5" />
                                Pobierz
                              </a>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'logs' && (
          <div className="bg-white border border-slate-200 rounded-xl shadow-xs p-6">
            <div className="flex items-center justify-between pb-4 border-b border-slate-100 mb-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">Event Log (Live Log)</h3>
                <p className="text-xs text-slate-500">Record of operations, P2P connections, and link state changes</p>
              </div>
              <button 
                onClick={() => setEventLogs([])}
                className="text-xs text-slate-500 hover:text-slate-800 bg-slate-50 hover:bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
              >
                Clear log
              </button>
            </div>

            <div className="bg-slate-900 text-slate-100 font-mono text-xs rounded-xl p-4 h-96 overflow-y-auto space-y-1.5">
              {eventLogs.length === 0 ? (
                <div className="text-slate-500">Waiting for events...</div>
              ) : (
                eventLogs.map((log, idx) => (
                  <div key={idx} className="flex gap-2 leading-relaxed">
                    <span className="text-slate-500">[{log.time}]</span>
                    <span className={`font-semibold ${
                      log.type === "success" 
                        ? "text-emerald-400" 
                        : log.type === "error" 
                          ? "text-rose-400" 
                          : "text-blue-400"
                    }`}>
                      [{log.type.toUpperCase()}]
                    </span>
                    <span className="text-slate-200">{log.text}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {previewFile && (
          <div 
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs"
            onClick={closePreview}
          >
            <div 
              className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-3xl w-full overflow-hidden flex flex-col max-h-[90vh]"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Header */}
              <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/50">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="p-2 rounded-lg bg-indigo-50 border border-indigo-100 text-indigo-600">
                    {isImageFile(previewFile.filename) ? (
                      <EyeIcon className="w-5 h-5" />
                    ) : (
                      <FileTextIcon className="w-5 h-5" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <h3 className="text-sm font-bold text-slate-900 truncate" title={previewFile.filename}>
                      {previewFile.filename}
                    </h3>
                    <p className="text-xs text-slate-500 font-mono">
                      {formatFileSize(previewFile.size_bytes)} ({previewFile.size_bytes.toLocaleString()} B)
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={closePreview}
                  className="p-1.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded-lg transition-colors cursor-pointer"
                  title="Zamknij podgląd"
                >
                  <XIcon className="w-5 h-5" />
                </button>
              </div>

              {/* Body */}
              <div className="p-6 overflow-y-auto flex-1 flex flex-col items-center justify-center min-h-[240px] bg-slate-50/30">
                {isImageFile(previewFile.filename) ? (
                  <div className="w-full flex flex-col items-center justify-center">
                    <img 
                      src={`/api/p2p/files/${encodeURIComponent(previewFile.filename)}?inline=true`} 
                      alt={previewFile.filename} 
                      className="max-h-[55vh] max-w-full rounded-xl object-contain shadow-md border border-slate-200 bg-white"
                    />
                  </div>
                ) : isTextFile(previewFile.filename) ? (
                  <div className="w-full">
                    {previewLoading ? (
                      <div className="py-12 flex flex-col items-center justify-center gap-3 text-slate-400 text-xs">
                        <RefreshCwIcon className="w-5 h-5 animate-spin text-indigo-600" />
                        Ładowanie zawartości pliku...
                      </div>
                    ) : (
                      <div className="relative">
                        <div className="absolute top-2 right-2 flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              if (previewContent) {
                                navigator.clipboard.writeText(previewContent);
                                setCopiedText(true);
                                setTimeout(() => setCopiedText(false), 2000);
                              }
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 text-[10px] font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 shadow-xs transition-colors cursor-pointer"
                          >
                            <CopyIcon className="w-3 h-3" />
                            {copiedText ? "Skopiowano!" : "Kopiuj tekst"}
                          </button>
                        </div>
                        <pre className="w-full bg-slate-950 text-emerald-400 font-mono text-xs p-4 rounded-xl overflow-x-auto max-h-[50vh] leading-relaxed border border-slate-800 selection:bg-indigo-600 selection:text-white">
                          {previewContent}
                        </pre>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="py-12 text-center text-slate-500 text-xs flex flex-col items-center gap-2">
                    <FileTextIcon className="w-10 h-10 text-slate-300" />
                    <p className="font-medium text-slate-700">Podgląd bezpośredni niedostępny dla tego typu pliku.</p>
                    <p className="text-slate-400 text-[11px]">Możesz pobrać ten plik bezpośrednio na swój dysk za pomocą przycisku poniżej.</p>
                  </div>
                )}
              </div>

              {/* Footer */}
              <div className="px-6 py-4 border-t border-slate-100 flex items-center justify-between bg-white">
                <span className="text-xs text-slate-400">
                  Magazyn: <code className="font-mono text-slate-600">/app/received_files/{previewFile.filename}</code>
                </span>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={closePreview}
                    className="px-4 py-2 text-xs font-medium text-slate-600 hover:text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors cursor-pointer"
                  >
                    Zamknij
                  </button>
                  <a
                    href={`/api/p2p/files/${encodeURIComponent(previewFile.filename)}`}
                    download={previewFile.filename}
                    className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg shadow-xs transition-colors cursor-pointer"
                  >
                    <DownloadIcon className="w-3.5 h-3.5" />
                    Pobierz plik
                  </a>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

    </div>
  );
}

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
