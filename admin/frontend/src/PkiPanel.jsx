import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  ShieldCheck,
  FileText,
  RefreshCw,
  Download
} from 'lucide-react';

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

// Root CA + bieżąca CRL
export default function PkiPanel({ apiUrl, refreshKey }) {
  const [ca, setCa] = useState(null);
  const [crl, setCrl] = useState(null);
  const [issuing, setIssuing] = useState(false);
  const [error, setError] = useState(null);

  const load = async () => {
    try {
      const [caRes, crlRes] = await Promise.all([
        axios.get(`${apiUrl}/pki/ca`),
        axios.get(`${apiUrl}/pki/crl`)
      ]);
      setCa(caRes.data);
      setCrl(crlRes.data);
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
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
      </div>
    </div>
  );
}
