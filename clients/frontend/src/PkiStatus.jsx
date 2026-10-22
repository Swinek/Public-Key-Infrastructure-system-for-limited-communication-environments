import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Database, Download } from 'lucide-react';

const formatHex = (hex) => (hex ? hex.match(/.{1,2}/g).join(':').toUpperCase() : '—');

const formatDate = (iso) => (iso ? new Date(iso).toLocaleString('pl-PL') : '—');

const remaining = (iso) => {
  const hours = (new Date(iso) - new Date()) / 36e5;
  if (hours < 0) return { text: `przeterminowana ${Math.abs(hours).toFixed(1)} h temu`, ok: false };
  if (hours < 48) return { text: `ważna jeszcze ${hours.toFixed(1)} h`, ok: true };
  return { text: `ważna jeszcze ${(hours / 24).toFixed(1)} dni`, ok: true };
};

const downloadBlob = async (url, filename) => {
  const res = await axios.get(url, { responseType: 'blob' });
  const href = URL.createObjectURL(res.data);
  const link = document.createElement('a');
  link.href = href;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(href);
};

const Stat = ({ label, value, sub, subClass = 'text-slate-500' }) => (
  <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{label}</p>
    <p className="text-lg font-bold text-slate-900 mt-0.5">{value}</p>
    {sub && <p className={`text-[11px] font-medium ${subClass}`}>{sub}</p>}
  </div>
);

// Stan danych PKI udostępnianych węzłom (GET /pki/summary) - te same metadane, które węzeł
// porównuje z lokalnymi przed pobraniem CA / CRL.
export default function PkiStatus({ portalUrl, refreshKey }) {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get(`${portalUrl}/pki/summary`)
      .then((res) => { setSummary(res.data); setError(null); })
      .catch(() => setError('Nie udało się pobrać stanu PKI z portalu.'));
  }, [portalUrl, refreshKey]);

  const crlState = summary?.crl ? remaining(summary.crl.next_update) : null;

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs">
      <div className="flex justify-between items-center mb-4 pb-3 border-b border-slate-100">
        <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
          <Database className="w-4 h-4 text-indigo-600" />
          Stan PKI dla węzłów
        </h3>
        <code className="text-[10px] text-slate-400">GET /pki/summary</code>
      </div>

      {error && <p className="text-xs text-rose-600">{error}</p>}

      {summary && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat
              label="CRLNumber"
              value={summary.crl ? `#${summary.crl.number}` : '—'}
              sub={summary.crl ? `${summary.crl.revoked_count} odwołanych` : 'brak CRL'}
            />
            <Stat
              label="nextUpdate"
              value={summary.crl ? new Date(summary.crl.next_update).toLocaleDateString('pl-PL') : '—'}
              sub={crlState?.text}
              subClass={crlState?.ok ? 'text-emerald-600' : 'text-rose-600'}
            />
            <Stat
              label="Rozmiar CRL (DER)"
              value={summary.crl ? `${summary.crl.size} B` : '—'}
              sub={summary.ca ? `Root CA: ${summary.ca.size} B` : null}
            />
            <Stat
              label="Certyfikaty"
              value={summary.certs.active}
              sub={`aktywne, ${summary.certs.revoked} odwołanych`}
            />
          </div>

          {summary.ca && (
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-3">
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                Fingerprint SHA-256 Root CA (do przypięcia przy instalacji węzła)
              </p>
              <p className="text-[11px] font-mono text-slate-700 mt-0.5 break-all">{formatHex(summary.ca.fingerprint)}</p>
              <p className="text-[11px] text-slate-500 mt-1">{summary.ca.subject}</p>
            </div>
          )}

          {summary.crl && (
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-[11px] text-slate-500 mr-2">
                thisUpdate: {formatDate(summary.crl.this_update)}
              </p>
              <button
                onClick={() => downloadBlob(`${portalUrl}/pki/crl`, 'crl.der')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-lg border border-emerald-200 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" /> CRL (DER)
              </button>
              <button
                onClick={() => downloadBlob(`${portalUrl}/pki/ca`, 'ca_certificate.der')}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" /> Root CA (DER)
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
