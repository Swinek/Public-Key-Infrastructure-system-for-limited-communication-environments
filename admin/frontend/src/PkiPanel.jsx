import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  ShieldCheck,
  FileText,
  History,
  RefreshCw,
  Download,
  X,
  Fingerprint
} from 'lucide-react';

const TRIGGER_LABELS = {
  startup: 'Start CA',
  new_ca: 'Nowe CA',
  revocation: 'Odwołanie',
  scheduled: 'Okresowa',
  manual: 'Ręczna'
};

const KEY_USAGE_LABELS = {
  digital_signature: 'digitalSignature',
  content_commitment: 'nonRepudiation',
  key_encipherment: 'keyEncipherment',
  data_encipherment: 'dataEncipherment',
  key_agreement: 'keyAgreement',
  key_cert_sign: 'keyCertSign',
  crl_sign: 'cRLSign'
};

const formatDate = (iso) => (iso ? new Date(iso).toLocaleString('pl-PL') : '—');

const formatHex = (hex) => (hex ? hex.match(/.{1,2}/g).join(':').toUpperCase() : '—');

const relativeHours = (iso) => {
  if (!iso) return '';
  const hours = (new Date(iso) - new Date()) / 36e5;
  if (hours < 0) return `${Math.abs(hours).toFixed(1)} h temu`;
  if (hours < 48) return `za ${hours.toFixed(1)} h`;
  return `za ${(hours / 24).toFixed(1)} dni`;
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

const Field = ({ label, children, mono = false }) => (
  <div>
    <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">{label}</p>
    <p className={`text-xs text-slate-800 mt-0.5 break-all ${mono ? 'font-mono text-[11px]' : ''}`}>{children}</p>
  </div>
);

const KeyUsageBadges = ({ usages }) => (
  <div className="flex flex-wrap gap-1 mt-1">
    {usages.length === 0 && <span className="text-xs text-rose-600">brak rozszerzenia KeyUsage</span>}
    {usages.map((u) => (
      <span key={u} className="px-2 py-0.5 rounded-md text-[10px] font-semibold bg-indigo-50 text-indigo-700 border border-indigo-200">
        {KEY_USAGE_LABELS[u] || u}
      </span>
    ))}
  </div>
);

const SizeBar = ({ der, pem }) => {
  const max = Math.max(der, pem) || 1;
  return (
    <div className="space-y-1.5">
      {[['DER', der, 'bg-emerald-500'], ['PEM', pem, 'bg-slate-400']].map(([label, size, color]) => (
        <div key={label} className="flex items-center gap-2 text-[11px]">
          <span className="w-8 font-semibold text-slate-500">{label}</span>
          <div className="flex-1 h-2 bg-slate-100 rounded-full overflow-hidden">
            <div className={`h-full ${color} rounded-full`} style={{ width: `${(size / max) * 100}%` }} />
          </div>
          <span className="w-14 text-right font-mono text-slate-700">{size} B</span>
        </div>
      ))}
    </div>
  );
};

export function CertDetailsModal({ apiUrl, cert, onClose }) {
  const [details, setDetails] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    axios.get(`${apiUrl}/pki/certificates/${cert.id}`)
      .then((res) => setDetails(res.data))
      .catch((err) => setError(err.response?.data?.error || 'Nie udało się odczytać certyfikatu.'));
  }, [apiUrl, cert.id]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
      <div className="w-full max-w-lg bg-white border border-slate-200 rounded-xl p-6 shadow-xl">
        <div className="flex justify-between items-center mb-4 border-b border-slate-100 pb-3">
          <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <FileText className="w-4 h-4 text-indigo-600" />
            Rozszerzenia X.509 – {cert.username}
          </h3>
          <button onClick={onClose} className="p-1 text-slate-400 hover:text-slate-700 cursor-pointer">
            <X className="w-4 h-4" />
          </button>
        </div>
        {error && <p className="text-xs text-rose-600">{error}</p>}
        {!details && !error && <p className="text-xs text-slate-400">Wczytywanie…</p>}
        {details && (
          <div className="grid grid-cols-2 gap-4">
            <Field label="Algorytm klucza">{details.key_algorithm}</Field>
            <Field label="Algorytm podpisu">{details.signature_algorithm}</Field>
            <div className="col-span-2"><Field label="Podmiot" mono>{details.subject}</Field></div>
            <Field label="Numer seryjny" mono>{details.serial_number}</Field>
            <Field label="Rozmiar">{details.size_der} B (DER) / {details.size_pem} B (PEM)</Field>
            <div className="col-span-2"><Field label="SKI (Subject Key Identifier)" mono>{formatHex(details.subject_key_identifier)}</Field></div>
            <div className="col-span-2"><Field label="AKI (Authority Key Identifier = SKI Root CA)" mono>{formatHex(details.authority_key_identifier)}</Field></div>
            <div className="col-span-2">
              <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">KeyUsage</p>
              <KeyUsageBadges usages={details.key_usage} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// view: 'overview' (Root CA + bieżąca CRL) | 'entries' (wpisy bieżącej CRL) | 'history' (historia CRL)
export default function PkiPanel({ apiUrl, refreshKey, view = 'overview' }) {
  const [ca, setCa] = useState(null);
  const [crl, setCrl] = useState(null);
  const [history, setHistory] = useState([]);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const [caRes, crlRes, historyRes] = await Promise.all([
        axios.get(`${apiUrl}/pki/ca`),
        axios.get(`${apiUrl}/pki/crl`),
        axios.get(`${apiUrl}/pki/crls`)
      ]);
      setCa(caRes.data);
      setCrl(crlRes.data);
      setHistory(historyRes.data);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.error || 'Nie udało się pobrać stanu PKI.');
    }
  };

  useEffect(() => {
    load();
  }, [refreshKey]);

  const handleIssueCrl = async () => {
    try {
      setIssuing(true);
      await axios.post(`${apiUrl}/pki/crl`);
      await load();
    } catch (err) {
      alert(err.response?.data?.error || 'Nie udało się wystawić CRL.');
    } finally {
      setIssuing(false);
    }
  };

  const crlExpired = crl && new Date(crl.next_update) < new Date();

  return (
    <div className="space-y-6">
      {error && (
        <div className="bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-lg px-4 py-3">{error}</div>
      )}

      {view === 'overview' && <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Root CA */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs">
          <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2 border-b border-slate-100 pb-3">
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
            Root CA
          </h3>
          {ca && (
            <div className="grid grid-cols-2 gap-4">
              <div className="col-span-2"><Field label="Podmiot" mono>{ca.subject}</Field></div>
              <Field label="Algorytm klucza">{ca.key_algorithm}</Field>
              <Field label="Algorytm podpisu">{ca.signature_algorithm}</Field>
              <Field label="Ważny od">{formatDate(ca.not_before)}</Field>
              <Field label="Ważny do">{formatDate(ca.not_after)}</Field>
              <div className="col-span-2">
                <Field label="Fingerprint SHA-256 (do przypięcia w węzłach)" mono>{formatHex(ca.fingerprint_sha256)}</Field>
              </div>
              <div className="col-span-2"><Field label="SKI (Subject Key Identifier)" mono>{formatHex(ca.subject_key_identifier)}</Field></div>
              <div className="col-span-2">
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">KeyUsage (krytyczne)</p>
                <KeyUsageBadges usages={ca.key_usage} />
              </div>
              <div className="col-span-2">
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Rozmiar certyfikatu</p>
                <SizeBar der={ca.size_der} pem={ca.size_pem} />
              </div>
            </div>
          )}
        </div>

        {/* Bieżąca CRL */}
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs">
          <div className="flex justify-between items-center mb-4 border-b border-slate-100 pb-3">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <FileText className="w-4 h-4 text-rose-600" />
              Bieżąca CRL
            </h3>
            <button
              onClick={handleIssueCrl}
              disabled={issuing}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-60 rounded-lg transition-colors cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${issuing ? 'animate-spin' : ''}`} />
              Wystaw nową CRL
            </button>
          </div>
          {crl && (
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">CRLNumber</p>
                <p className="text-3xl font-bold text-slate-900 mt-0.5">#{crl.crl_number}</p>
              </div>
              <div>
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Odwołane certyfikaty</p>
                <p className="text-3xl font-bold text-rose-600 mt-0.5">{crl.revoked_count}</p>
              </div>
              <Field label="thisUpdate">{formatDate(crl.this_update)}</Field>
              <div>
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">nextUpdate</p>
                <p className="text-xs text-slate-800 mt-0.5">{formatDate(crl.next_update)}</p>
                <p className={`text-[11px] font-semibold ${crlExpired ? 'text-rose-600' : 'text-emerald-600'}`}>
                  {relativeHours(crl.next_update)}
                </p>
              </div>
              <Field label="Algorytm podpisu">{crl.signature_algorithm}</Field>
              <Field label="Ponowne podpisanie">co {crl.reissue_hours} h i przy każdym odwołaniu</Field>
              <div className="col-span-2">
                <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1.5">Rozmiar listy</p>
                <SizeBar der={crl.size_der} pem={crl.size_pem} />
              </div>
              <div className="col-span-2 flex gap-2">
                <button
                  onClick={() => downloadBlob(`${apiUrl}/certificates/crl?format=der`, 'crl.der')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-lg border border-emerald-200 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" /> Pobierz DER
                </button>
                <button
                  onClick={() => downloadBlob(`${apiUrl}/certificates/crl?format=pem`, 'crl.pem')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-300 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" /> Pobierz PEM
                </button>
              </div>
            </div>
          )}
        </div>
      </div>}

      {/* Wpisy bieżącej CRL */}
      {view === 'entries' && crl && (
        <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
          <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
            <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
              <Fingerprint className="w-4 h-4 text-slate-500" />
              Wpisy CRL #{crl.crl_number}
            </h3>
            <span className="text-xs text-slate-400 font-medium">Razem: {crl.entries.length}</span>
          </div>
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-100 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-slate-50/50">
                <th className="py-3 px-4">Numer seryjny</th>
                <th className="py-3 px-4">Data odwołania</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-xs">
              {crl.entries.map((e) => (
                <tr key={e.serial_number}>
                  <td className="py-2.5 px-4 font-mono text-[11px] text-slate-700">{e.serial_number}</td>
                  <td className="py-2.5 px-4 text-slate-500">{formatDate(e.revocation_date)}</td>
                </tr>
              ))}
              {crl.entries.length === 0 && (
                <tr>
                  <td colSpan="2" className="text-center py-6 text-slate-400 text-xs">Lista nie zawiera odwołanych certyfikatów.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Historia CRL */}
      {view === 'history' && <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
        <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
          <h3 className="text-sm font-semibold text-slate-900 flex items-center gap-2">
            <History className="w-4 h-4 text-slate-500" />
            Historia wystawionych CRL
          </h3>
          <span className="text-xs text-slate-400 font-medium">Ostatnie {history.length}</span>
        </div>
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-100 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-slate-50/50">
              <th className="py-3 px-4">CRLNumber</th>
              <th className="py-3 px-4">Powód</th>
              <th className="py-3 px-4">thisUpdate</th>
              <th className="py-3 px-4">nextUpdate</th>
              <th className="py-3 px-4 text-right">Wpisy</th>
              <th className="py-3 px-4 text-right">Rozmiar DER</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 text-xs">
            {history.map((h) => (
              <tr key={h.crl_number} className="hover:bg-slate-50/60">
                <td className="py-2.5 px-4 font-bold text-slate-900">#{h.crl_number}</td>
                <td className="py-2.5 px-4">
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-200">
                    {TRIGGER_LABELS[h.trigger] || h.trigger}
                  </span>
                </td>
                <td className="py-2.5 px-4 text-slate-500">{formatDate(h.this_update)}</td>
                <td className="py-2.5 px-4 text-slate-500">{formatDate(h.next_update)}</td>
                <td className="py-2.5 px-4 text-right text-slate-700">{h.revoked_count}</td>
                <td className="py-2.5 px-4 text-right font-mono text-slate-700">{h.size_der} B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>}
    </div>
  );
}
