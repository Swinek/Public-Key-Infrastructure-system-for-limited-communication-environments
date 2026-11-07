import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Trash2,
  CheckCircle,
  AlertTriangle,
  Key
} from 'lucide-react';
import PkiPanel from './PkiPanel';
import CsrPanel from './CsrPanel';

const API_URL = 'http://localhost:5000/api';

function App() {
  const [users, setUsers] = useState([]);
  const [certs, setCerts] = useState([]);
  const [activeTab, setActiveTab] = useState('users');

  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState(null);
  const [revocationReason, setRevocationReason] = useState('');

  const [crlNotice, setCrlNotice] = useState(null);
  const [pkiRefreshKey, setPkiRefreshKey] = useState(0);

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

  const filteredUsers = users;

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans">
      
      {/* Top Navbar */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
        <div className="max-w-5xl mx-auto px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-indigo-600 text-white rounded-xl shadow-xs">
              <Key className="w-5 h-5" />
            </div>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200">
              Panel Administratora
            </span>
          </div>
        </div>
      </nav>

      {/* Main Admin Dashboard Content */}
      <main className="max-w-5xl mx-auto px-6 py-8">

        {/* Action Bar and Navigation Tabs */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
          <div className="flex bg-slate-200/70 p-1 rounded-lg">
            <button 
              onClick={() => setActiveTab('users')}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'users' 
                  ? 'bg-white text-slate-900 shadow-xs' 
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Users & Edge Nodes
            </button>
            <button
              onClick={() => setActiveTab('pki')}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'pki'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              PKI / CRL
            </button>
            <button
              onClick={() => setActiveTab('csr')}
              className={`px-4 py-2 text-xs font-semibold rounded-md transition-all cursor-pointer ${
                activeTab === 'csr'
                  ? 'bg-white text-slate-900 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Wnioski CSR
            </button>
          </div>
        </div>

        {crlNotice && (
          <div className="mb-6 flex justify-between items-center bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-medium rounded-lg px-4 py-3">
            <span>{crlNotice}</span>
            <button onClick={() => setCrlNotice(null)} className="text-emerald-600 hover:text-emerald-900 cursor-pointer">✕</button>
          </div>
        )}

        {activeTab === 'csr' ? (
          <CsrPanel apiUrl={API_URL} onChanged={() => { setPkiRefreshKey((k) => k + 1); fetchUsers(); fetchCerts(); }} />
        ) : activeTab === 'pki' ? (
          <PkiPanel apiUrl={API_URL} refreshKey={pkiRefreshKey} />
        ) : (
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
                          {/* Certyfikat wystawia tylko zatwierdzenie wniosku CSR (zakładka „Wnioski CSR”). */}
                          {user.cert_status === 'ACTIVE' && (
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
        )}
      </main>

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
    </div>
  );
}

export default App;
