import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { CheckCircle, XCircle, RefreshCw, Key } from 'lucide-react';

const formatDate = (iso) => (iso ? new Date(iso).toLocaleString('pl-PL') : '—');

const STATUS_STYLES = {
  PENDING: 'bg-amber-50 text-amber-800 border-amber-200',
  APPROVED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  REJECTED: 'bg-rose-50 text-rose-700 border-rose-200'
};

// Wnioski CSR węzłów: węzeł sam generuje klucz, a certyfikat powstaje dopiero po zatwierdzeniu wniosku tutaj.
// Zatwierdzenie zastępuje poprzedni certyfikat węzła (stary zostaje odwołany, nowa CRL) i budzi węzły online.
export default function CsrPanel({ apiUrl, onChanged }) {
  const [requests, setRequests] = useState([]);
  const [busyId, setBusyId] = useState(null);
  const [notice, setNotice] = useState(null);

  const load = async () => {
    try {
      const res = await axios.get(`${apiUrl}/csr`);
      setRequests(res.data);
    } catch (err) {
      setNotice({ ok: false, text: 'Nie udało się pobrać wniosków CSR.' });
    }
  };

  useEffect(() => { load(); }, []);

  const decide = async (req, action) => {
    let body = {};
    if (action === 'reject') {
      const reason = window.prompt(`Powód odrzucenia wniosku ${req.node_id}:`, 'Wniosek nieoczekiwany');
      if (reason === null) return;
      body = { reason };
    }
    setBusyId(req.id);
    setNotice(null);
    try {
      const res = await axios.post(`${apiUrl}/csr/${req.id}/${action}`, body);
      if (action === 'approve') {
        const replaced = res.data.superseded?.length
          ? ` Poprzedni certyfikat odwołany (CRL nr ${res.data.crl_number}).` : '';
        setNotice({ ok: true, text: `Wydano certyfikat ${res.data.serial_number} dla ${req.node_id}.${replaced}` });
      } else {
        setNotice({ ok: true, text: `Wniosek ${req.node_id} odrzucony.` });
      }
      onChanged?.();
      load();
    } catch (err) {
      setNotice({ ok: false, text: err.response?.data?.error || 'Błąd przy rozpatrywaniu wniosku.' });
    } finally {
      setBusyId(null);
    }
  };

  const pending = requests.filter((r) => r.status === 'PENDING').length;

  return (
    <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
      <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
        <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <Key className="w-4 h-4 text-indigo-600" /> Wnioski o certyfikat (CSR)
          {pending > 0 && <span className="text-xs text-amber-700 font-medium">oczekujące: {pending}</span>}
        </h3>
        <button onClick={load} className="text-xs text-slate-500 hover:text-slate-900 flex items-center gap-1 cursor-pointer">
          <RefreshCw className="w-3.5 h-3.5" /> Odśwież
        </button>
      </div>
      {notice && (
        <div className={`mx-6 mt-4 px-4 py-2 rounded-lg text-xs border ${notice.ok
          ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-rose-50 border-rose-200 text-rose-800'}`}>
          {notice.text}
        </div>
      )}
      {requests.length === 0 ? (
        <p className="text-xs text-slate-400 py-10 text-center">
          Brak wniosków. Węzeł wysyła wniosek sam przy kontakcie WAN (albo przez sąsiadów), gdy nie ma ważnego certyfikatu.
        </p>
      ) : (
        <table className="w-full text-xs">
          <thead className="text-slate-400 text-left">
            <tr>
              <th className="px-6 py-3 font-medium">Węzeł (CN)</th>
              <th className="px-6 py-3 font-medium">Odcisk klucza (SHA-256)</th>
              <th className="px-6 py-3 font-medium">Złożony</th>
              <th className="px-6 py-3 font-medium">Status</th>
              <th className="px-6 py-3 font-medium text-right">Decyzja</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {requests.map((r) => (
              <tr key={r.id}>
                <td className="px-6 py-3">
                  <div className="font-semibold text-slate-900">{r.node_id}</div>
                  {r.relayed_via && (
                    <div className="text-[10px] text-amber-700 mt-1" title="Wniosek przynieśli sąsiedzi – pośrednik nie jest zaufany">
                      przez {r.relayed_via.split(',').join(' → ')}
                    </div>
                  )}
                </td>
                <td className="px-6 py-3 font-mono text-slate-500 break-all" title={r.key_fingerprint}>
                  {r.relayed_via ? r.key_fingerprint : `${r.key_fingerprint.slice(0, 24)}…`}
                  {r.relayed_via && r.status === 'PENDING' && (
                    <div className="font-sans text-[10px] text-amber-700 mt-1">
                      Porównaj odcisk z panelem węzła (np. przez radio) przed zatwierdzeniem.
                    </div>
                  )}
                </td>
                <td className="px-6 py-3 text-slate-500">{formatDate(r.created_at)}</td>
                <td className="px-6 py-3">
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${STATUS_STYLES[r.status]}`}>
                    {r.status}
                  </span>
                  {r.serial_number && <div className="font-mono text-[10px] text-slate-400 mt-1">#{r.serial_number}</div>}
                  {r.reason && <div className="text-[10px] text-slate-400 mt-1">{r.reason}</div>}
                </td>
                <td className="px-6 py-3 text-right">
                  {r.status === 'PENDING' && (
                    <div className="flex justify-end gap-2">
                      <button onClick={() => decide(r, 'approve')} disabled={busyId === r.id}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white font-medium cursor-pointer disabled:opacity-50">
                        <CheckCircle className="w-3.5 h-3.5" /> Zatwierdź
                      </button>
                      <button onClick={() => decide(r, 'reject')} disabled={busyId === r.id}
                        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white border border-rose-200 text-rose-700 hover:bg-rose-50 font-medium cursor-pointer disabled:opacity-50">
                        <XCircle className="w-3.5 h-3.5" /> Odrzuć
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
