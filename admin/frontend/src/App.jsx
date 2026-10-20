import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  Users, 
  ShieldCheck, 
  ShieldAlert, 
  UserPlus, 
  Trash2, 
  RefreshCw, 
  Search, 
  CheckCircle, 
  AlertTriangle, 
  Mail, 
  User, 
  Calendar, 
  Download,
  Key,
  ExternalLink
} from 'lucide-react';

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
  
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newRole, setNewRole] = useState('user');

  const [showRevokeModal, setShowRevokeModal] = useState(false);
  const [selectedCertId, setSelectedCertId] = useState(null);
  const [revocationReason, setRevocationReason] = useState('');

  const [searchQuery, setSearchQuery] = useState('');
  const [newlyIssuedCert, setNewlyIssuedCert] = useState(null);
  const [loading, setLoading] = useState(false);

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
      setLoading(true);
      const res = await axios.get(`${API_URL}/users`);
      setUsers(res.data);
    } catch (err) {
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
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

  const handleAddUser = async (e) => {
    e.preventDefault();
    if (!newUsername || !newEmail) return;

    try {
      await axios.post(`${API_URL}/users`, {
        username: newUsername.trim(),
        email: newEmail.trim(),
        role: newRole
      });
      setNewUsername('');
      setNewEmail('');
      setNewRole('user');
      fetchUsers();
    } catch (err) {
      alert('Error adding user. Username or email may already be taken.');
    }
  };

  const handleDeleteUser = async (id) => {
    if (!window.confirm('Are you sure you want to delete this user? All associated certificates will be permanently deleted.')) return;
    try {
      await axios.delete(`${API_URL}/users/${id}`);
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
      await axios.post(`${API_URL}/certificates/revoke`, {
        certId: selectedCertId,
        reason: revocationReason
      });
      setShowRevokeModal(false);
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
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-slate-900 leading-tight">
                  PKI Root CA Administration
                </h1>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200">
                  Panel Administratora
                </span>
              </div>
              <p className="text-xs text-slate-500 font-medium">
                Główny Urząd Certyfikacji (Zarządzanie Tożsamościami i CRL)
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button 
              onClick={() => { fetchUsers(); fetchCerts(); }} 
              className="p-2 text-slate-500 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 rounded-lg border border-slate-200 shadow-2xs transition-colors cursor-pointer"
              title="Odśwież dane"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>

            <a
              href="http://localhost:3001"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-emerald-800 bg-emerald-50 hover:bg-emerald-100 rounded-lg border border-emerald-200 transition-colors shadow-2xs"
              title="Przejdź do Portalu Klienta (port 3001)"
            >
              <span>Portal Klienta (3001)</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </nav>

      {/* Main Admin Dashboard Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        
        {/* Metric Cards */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-xs flex items-center gap-4">
            <div className="p-3 bg-blue-50 text-blue-600 rounded-lg border border-blue-100">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Users</p>
              <h3 className="text-2xl font-bold text-slate-900 mt-0.5">{users.length}</h3>
            </div>
          </div>

          <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-xs flex items-center gap-4">
            <div className="p-3 bg-emerald-50 text-emerald-600 rounded-lg border border-emerald-100">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Active Certificates</p>
              <h3 className="text-2xl font-bold text-emerald-600 mt-0.5">
                {certs.filter(c => c.status === 'ACTIVE').length}
              </h3>
            </div>
          </div>

          <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-xs flex items-center gap-4">
            <div className="p-3 bg-rose-50 text-rose-600 rounded-lg border border-rose-100">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Revoked (CRL)</p>
              <h3 className="text-2xl font-bold text-rose-600 mt-0.5">
                {certs.filter(c => c.status === 'REVOKED').length}
              </h3>
            </div>
          </div>
        </section>

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
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={handleDownloadCaCert}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-emerald-700 bg-emerald-50 hover:bg-emerald-100 rounded-lg border border-emerald-200 transition-colors shadow-2xs cursor-pointer"
              title="Pobierz certyfikat Root CA w formacie PEM"
            >
              <Download className="w-3.5 h-3.5" />
              Download Root CA (PEM)
            </button>

            <button
              onClick={handleDownloadCrl}
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-300 transition-colors shadow-2xs cursor-pointer"
              title="Pobierz listę odwołań CRL w formacie PEM"
            >
              <Download className="w-3.5 h-3.5" />
              Download CRL (PEM)
            </button>

            <div className="relative min-w-[240px]">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input 
                type="text"
                placeholder={activeTab === 'users' ? 'Search by username or email...' : 'Search by name or serial number...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 hover:border-slate-300 focus:bg-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-4 py-2 text-xs outline-none transition-all text-slate-900"
              />
            </div>
          </div>
        </div>

        {activeTab === 'users' ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Add User Form */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs h-fit">
              <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2 border-b border-slate-100 pb-3">
                <UserPlus className="w-4 h-4 text-slate-500" />
                Add New User / Edge Node
              </h3>
              <form onSubmit={handleAddUser} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Username / Node ID</label>
                  <div className="relative">
                    <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input 
                      type="text" 
                      required
                      placeholder="e.g. ship_alpha_1" 
                      value={newUsername}
                      onChange={(e) => setNewUsername(e.target.value)}
                      className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-900 outline-none transition-all"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Email Address</label>
                  <div className="relative">
                    <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input 
                      type="email" 
                      required
                      placeholder="e.g. alpha@radio.local" 
                      value={newEmail}
                      onChange={(e) => setNewEmail(e.target.value)}
                      className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-900 outline-none transition-all"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-500 mb-1">Role</label>
                  <select 
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value)}
                    className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg px-3 py-2 text-xs text-slate-700 outline-none transition-all bg-white"
                  >
                    <option value="user">User / Edge Station</option>
                    <option value="admin">Administrator</option>
                  </select>
                </div>

                <button 
                  type="submit" 
                  className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-2 px-4 rounded-lg text-xs transition-colors shadow-xs flex items-center justify-center gap-2 cursor-pointer mt-2"
                >
                  <UserPlus className="w-4 h-4" />
                  Register Node
                </button>
              </form>
            </div>

            {/* Users Table */}
            <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl overflow-hidden shadow-xs">
              <div className="px-6 py-4 border-b border-slate-100 flex justify-between items-center bg-slate-50/50">
                <h3 className="text-sm font-semibold text-slate-900">Registered Users & Edge Nodes</h3>
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
