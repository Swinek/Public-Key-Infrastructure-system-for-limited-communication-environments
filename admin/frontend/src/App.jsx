import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Users, 
  ShieldCheck, 
  ShieldAlert, 
  Trash2, 
  Search, 
  CheckCircle, 
  AlertTriangle, 
  Download,
  Key,
  Info
} from 'lucide-react';
import PkiPanel, { CertDetailsModal } from './PkiPanel';

const API_URL = 'http://localhost:5000/api';

const downloadFile = (filename, content, mimeType = 'application/x-pem-file') => {
  if (!content) return;
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};

function App() {
  const [users, setUsers] = useState([]);
  const [certs, setCerts] = useState([]);
  const [activeTab, setActiveTab] = useState('users');

  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState(null);
  const [revocationReason, setRevocationReason] = useState('');

  const [searchQuery, setSearchQuery] = useState('');
  const [newlyIssuedCert, setNewlyIssuedCert] = useState(null);
  const [crlNotice, setCrlNotice] = useState(null);
  const [pkiRefreshKey, setPkiRefreshKey] = useState(0);
  const [detailsCert, setDetailsCert] = useState(null);

  const handleDownloadCaCert = async () => {
    try {
      const res = await axios.get(`${API_URL}/certificates/ca/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'ca_certificate.pem';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Nie udało się pobrać certyfikatu Root CA.');
    }
  };

  const handleDownloadCrl = async () => {
    try {
      const res = await axios.get(`${API_URL}/certificates/crl/download`, { responseType: 'blob' });
      const url = URL.createObjectURL(res.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'crl.pem';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Nie udało się pobrać listy unieważnień CRL.');
    }
  };

  useEffect(() => {
    fetchUsers();
    fetchCerts();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await axios.get(`${API_URL}/users`);
      setUsers(res.data);
    } catch (err) {
      console.error('Error fetching users:', err);
    }
  };

  const fetchCerts = async () => {
    try {
      const res = await axios.get(`${API_URL}/certificates`);
      setCerts(res.data);
    } catch (err) {
      console.error('Error fetching certificates:', err);
    }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm('Usunąć użytkownika? Jego aktywny certyfikat zostanie odwołany (nowa CRL), a wpisy certyfikatów zostaną w rejestrze.')) return;
    try {
      await axios.delete(`${API_URL}/users/${id}`);
      setPkiRefreshKey((k) => k + 1);
      fetchUsers();
      fetchCerts();
    } catch (err) {
      console.error(err);
    }
  };

  const handleIssueCert = async (userId) => {
    try {
      const res = await axios.post(`${API_URL}/certificates`, { userId });
      fetchUsers();
      fetchCerts();
      const targetUser = users.find(u => u.id === userId);
      setNewlyIssuedCert({
        ...res.data,
        targetUsername: targetUser ? targetUser.username : 'node'
      });
    } catch (err) {
      alert(err.response?.data?.error || 'Error generating certificate.');
    }
  };

  const openRevokeModal = (certId) => {
    setSelectedCertId(certId);
    setRevocationReason('Administrative access revocation');
    setShowRevokeModal(true);
  };

  const handleRevokeCert = async () => {
    try {
      const res = await axios.post(`${API_URL}/certificates/revoke`, {
        certId: selectedCertId,
        reason: revocationReason
      });
      setShowRevokeModal(false);
      setCrlNotice(`Certyfikat ${res.data.serial_number} odwołany – podpisano CRL #${res.data.crl_number}.`);
      setPkiRefreshKey((k) => k + 1);
      fetchUsers();
      fetchCerts();
    } catch (err) {
      alert(err.response?.data?.error || 'Error revoking certificate.');
    }
  };

  const filteredUsers = users.filter(user => 
    user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
    user.email.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredCerts = certs.filter(cert => 
    cert.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
    cert.serial_number.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans">
      
      {/* Top Navbar */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-600 text-white rounded-xl shadow-xs">
              <Key className="w-5 h-5" />
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200">
              Panel Administratora
            </span>
          </div>

          {/* Metrics */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-blue-50 border border-blue-100 rounded-lg">
              <Users className="w-4 h-4 text-blue-600" />
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Total Users</span>
              <span className="text-sm font-bold text-slate-900">{users.length}</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-50 border border-emerald-100 rounded-lg">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Active Certificates</span>
              <span className="text-sm font-bold text-emerald-600">
                {certs.filter(c => c.status === 'ACTIVE').length}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 bg-rose-50 border border-rose-100 rounded-lg">
              <ShieldAlert className="w-4 h-4 text-rose-600" />
              <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">Revoked (CRL)</span>
              <span className="text-sm font-bold text-rose-600">
                {certs.filter(c => c.status === 'REVOKED').length}
              </span>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Admin Dashboard Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">

        {/* Action Bar and Navigation Tabs */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <div className="flex bg-slate-200/70 p-1 rounded-lg">
            <button 
              onClick={() => { setActiveTab('users'); setSearchQuery(''); }}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'users' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Users & Edge Nodes
            </button>
            <button 
              onClick={() => { setActiveTab('certs'); setSearchQuery(''); }}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'certs' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Certificate Registry (CRL)
            </button>
            <button
              onClick={() => { setActiveTab('pki'); setSearchQuery(''); }}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'pki'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              PKI / CRL
            </button>
            <button
              onClick={() => { setActiveTab('crl-entries'); setSearchQuery(''); }}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'crl-entries'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Wpisy CRL
            </button>
            <button
              onClick={() => { setActiveTab('crl-history'); setSearchQuery(''); }}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'crl-history'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Historia CRL
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {(activeTab === 'users' || activeTab === 'certs') && <div className="relative min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input 
                type="text"
                placeholder={activeTab === 'users' ? 'Search by username or email...' : 'Search by name or serial number...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 hover:border-slate-300 focus:bg-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-4 py-2 text-xs outline-none transition-all text-slate-900"
              />
            </div>}
          </div>
        </div>

        {crlNotice && (
          <div className="mb-6 flex justify-between items-center bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-medium rounded-lg px-4 py-3">
            <span>{crlNotice}</span>
            <button onClick={() => setCrlNotice(null)} className="text-emerald-600 hover:text-emerald-900 cursor-pointer">✕</button>
          </div>
        )}

        {activeTab === 'pki' || activeTab === 'crl-entries' || activeTab === 'crl-history' ? (
          <PkiPanel
            apiUrl={API_URL}
            refreshKey={pkiRefreshKey}
            view={{ pki: 'overview', 'crl-entries': 'entries', 'crl-history': 'history' }[activeTab]}
          />
        ) : activeTab === 'users' ? (
            <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
              <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                <h3 className="text-sm font-semibold text-slate-900">Registered Edge Nodes</h3>
                <span className="text-xs text-slate-400 font-medium">Count: {filteredUsers.length}</span>
              </div>
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-slate-100 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-slate-50/50">
                    <th className="py-3 px-4">Node / User</th>
                    <th className="py-3 px-4">Role</th>
                    <th className="py-3 px-4">Certificate Status</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-xs">
                  {filteredUsers.map((user) => (
                    <tr key={user.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-slate-900">{user.username}</div>
                        <div className="text-slate-400 text-[11px]">{user.email}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-600 border border-slate-200">
                          {user.role}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                          user.cert_status === 'ACTIVE' 
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                            : 'bg-slate-100 text-slate-600'
                        }`}>
                          {user.cert_status === 'ACTIVE' && <CheckCircle className="w-3 h-3" />}
                          {user.cert_status || 'NO CERT'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          {user.cert_status === 'ACTIVE' ? (
                            <button 
                              onClick={() => {
                                const cert = certs.find(c => c.user_id === user.id && c.status === 'ACTIVE');
                                if (cert) openRevokeModal(cert.id);
                              }}
                              className="px-2.5 py-1 text-rose-700 bg-rose-50 hover:bg-rose-100 rounded-md border border-rose-200 font-medium transition-colors cursor-pointer"
                              title="Unieważnij certyfikat (CRL)"
                            >
                              Revoke
                            </button>
                          ) : (
                            <button 
                              onClick={() => handleIssueCert(user.id)}
                              className="px-2.5 py-1 text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-md border border-emerald-200 font-medium transition-colors cursor-pointer"
                              title="Wystaw certyfikat X.509"
                            >
                              Issue Cert
                            </button>
                          )}
                          <button 
                            onClick={() => handleDeleteUser(user.id)}
                            className="p-1 text-slate-400 hover:text-rose-600 rounded-md hover:bg-rose-50 transition-colors cursor-pointer"
                            title="Usuń węzeł"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {filteredUsers.length === 0 && (
                    <tr>
                      <td colSpan="4" className="text-center py-8 text-slate-400 text-xs">
                        No users or edge nodes found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
        ) : (
          /* Certificate Registry Tab */
          <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
            <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
              <h3 className="text-sm font-semibold text-slate-900">Certificate Registry & Revocation List (CRL)</h3>
              <span className="text-xs text-slate-400 font-medium">Total: {filteredCerts.length}</span>
            </div>
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-100 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-slate-50/50">
                  <th className="py-3 px-4">Subject</th>
                  <th className="py-3 px-4">Serial Number</th>
                  <th className="py-3 px-4">Fingerprint (SHA-256)</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Issued At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {filteredCerts.map((cert) => (
                  <tr key={cert.id} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-900">{cert.username}</div>
                      <div className="text-slate-400 text-[11px]">{cert.email}</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-[11px] text-slate-700">
                      {cert.serial_number}
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] text-slate-500 max-w-[160px] truncate" title={cert.fingerprint}>
                      {cert.fingerprint || '—'}
                    </td>
                    <td className="py-3 px-4">
                      <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ${
                        cert.status === 'ACTIVE' 
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200' 
                          : 'bg-rose-50 text-rose-700 border border-rose-200'
                      }`}>
                        {cert.status === 'ACTIVE' ? <CheckCircle className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                        {cert.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500 text-[11px]">
                      {new Date(cert.issued_at).toLocaleDateString('pl-PL')}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {cert.certificate_pem && (
                          <button
                            onClick={() => setDetailsCert(cert)}
                            className="p-1 text-slate-500 hover:text-indigo-600 rounded-md hover:bg-indigo-50 transition-colors cursor-pointer"
                            title="Rozszerzenia X.509 (AKI, SKI, KeyUsage)"
                          >
                            <Info className="w-4 h-4" />
                          </button>
                        )}
                        {cert.certificate_pem && (
                          <button
                            onClick={() => downloadFile(`${cert.username}_cert.pem`, cert.certificate_pem)}
                            className="p-1 text-slate-500 hover:text-indigo-600 rounded-md hover:bg-indigo-50 transition-colors cursor-pointer"
                            title="Pobierz certyfikat PEM"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        )}
                        {cert.status === 'ACTIVE' && (
                          <button 
                            onClick={() => openRevokeModal(cert.id)}
                            className="px-2 py-0.5 text-rose-700 bg-rose-50 hover:bg-rose-100 rounded-md border border-rose-200 font-medium transition-colors cursor-pointer"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
                {filteredCerts.length === 0 && (
                  <tr>
                    <td colSpan="6" className="text-center py-10 text-slate-400 text-xs">
                      No records found in certificate registry.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </main>

      {detailsCert && (
        <CertDetailsModal apiUrl={API_URL} cert={detailsCert} onClose={() => setDetailsCert(null)} />
      )}

      {/* Revocation Modal */}
      {showRevokeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="w-full max-w-md bg-white border border-slate-200 rounded-xl p-6 shadow-xl">
            <h3 className="text-base font-semibold text-slate-900 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-600" />
              Revoke Certificate
            </h3>
            <p className="text-xs text-slate-500 mb-4">
              This action cannot be undone. The selected key will be permanently added to the Certificate Revocation List (CRL).
            </p>
            <div className="mb-4">
              <label className="block text-xs font-semibold text-slate-500 mb-1">Revocation Reason</label>
              <input 
                type="text" 
                value={revocationReason} 
                onChange={(e) => setRevocationReason(e.target.value)}
                placeholder="e.g. Key compromise, Employee departure"
                className="w-full border border-slate-200 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 rounded-lg px-3 py-2 text-xs text-slate-900 placeholder-slate-400 outline-none transition-all"
                required
              />
            </div>
            <div className="flex justify-end gap-2 border-t border-slate-100 pt-4">
              <button 
                onClick={() => setShowRevokeModal(false)}
                className="px-3 py-2 rounded-lg text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-slate-200 transition-colors cursor-pointer"
              >
                Cancel
              </button>
              <button 
                onClick={handleRevokeCert}
                className="px-3 py-2 rounded-lg text-xs font-medium text-white bg-rose-600 hover:bg-rose-700 transition-colors shadow-xs cursor-pointer"
              >
                Confirm Revocation
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Newly Issued Credentials Modal */}
      {newlyIssuedCert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="w-full max-w-lg bg-white border border-slate-200 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-start justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-emerald-100 text-emerald-700 rounded-lg">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    Wydano poświadczenia węzła brzegowego
                  </h3>
                  <p className="text-xs text-slate-500">
                    Węzeł: <span className="font-semibold text-slate-800">{newlyIssuedCert.targetUsername}</span> &bull; SN: <span className="font-mono">{newlyIssuedCert.serial_number}</span>
                  </p>
                </div>
              </div>
            </div>

            <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold">Klucz prywatny jest zwracany jednorazowo!</span>
                <p className="mt-0.5 text-amber-700">
                  Zgodnie z zasadami PKI, serwer nie przechowuje klucza prywatnego węzła. Pobierz go teraz i skopiuj na maszynę wirtualną / do stacji polowej, aby umożliwić podpisywanie transmisji radiowej.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-semibold text-slate-600 uppercase tracking-wider">
                Pobierz pakiet tożsamości do maszyny wirtualnej (offline):
              </p>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                <button
                  onClick={() => downloadFile(`${newlyIssuedCert.targetUsername}_cert.pem`, newlyIssuedCert.certificate_pem)}
                  className="flex items-center gap-2 p-2.5 rounded-lg border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 text-indigo-700 text-xs font-semibold transition-colors cursor-pointer text-left"
                >
                  <Download className="w-4 h-4 shrink-0" />
                  <div>
                    <p className="font-bold">Certyfikat węzła</p>
                    <p className="text-[10px] text-indigo-500 font-normal">{newlyIssuedCert.targetUsername}_cert.pem</p>
                  </div>
                </button>

                <button
                  onClick={() => downloadFile(`${newlyIssuedCert.targetUsername}_private.key`, newlyIssuedCert.private_key, 'application/x-pem-file')}
                  className="flex items-center gap-2 p-2.5 rounded-lg border border-rose-200 bg-rose-50 hover:bg-rose-100 text-rose-700 text-xs font-semibold transition-colors cursor-pointer text-left"
                >
                  <Key className="w-4 h-4 shrink-0" />
                  <div>
                    <p className="font-bold">Klucz prywatny węzła</p>
                    <p className="text-[10px] text-rose-500 font-normal">{newlyIssuedCert.targetUsername}_private.key</p>
                  </div>
                </button>

                <button
                  onClick={handleDownloadCaCert}
                  className="flex items-center gap-2 p-2.5 rounded-lg border border-emerald-200 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 text-xs font-semibold transition-colors cursor-pointer text-left"
                >
                  <ShieldCheck className="w-4 h-4 shrink-0" />
                  <div>
                    <p className="font-bold">Certyfikat Root CA</p>
                    <p className="text-[10px] text-emerald-500 font-normal">ca_certificate.pem</p>
                  </div>
                </button>

                <button
                  onClick={handleDownloadCrl}
                  className="flex items-center gap-2 p-2.5 rounded-lg border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-semibold transition-colors cursor-pointer text-left"
                >
                  <ShieldAlert className="w-4 h-4 shrink-0" />
                  <div>
                    <p className="font-bold">Lista odwołań CRL</p>
                    <p className="text-[10px] text-slate-500 font-normal">crl.pem</p>
                  </div>
                </button>
              </div>
            </div>

            <div className="border-t border-slate-100 pt-3 flex justify-end">
              <button
                onClick={() => setNewlyIssuedCert(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold text-white bg-slate-800 hover:bg-slate-900 transition-colors cursor-pointer"
              >
                Zamknij okno
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
