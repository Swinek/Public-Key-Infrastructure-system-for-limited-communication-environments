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
  LogOut, 
  Download 
} from 'lucide-react';

const API_URL = 'http://localhost:5000/api';

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

  const [currentRoleView, setCurrentRoleView] = useState('admin');
  const [loggedInUser, setLoggedInUser] = useState(null);

  useEffect(() => {
    fetchUsers();
    fetchCerts();
  }, []);

  const fetchUsers = async () => {
    try {
      const res = await axios.get(`${API_URL}/users`);
      setUsers(res.data);
      if (currentRoleView !== 'admin') {
        const updatedUser = res.data.find(u => u.id === Number(currentRoleView));
        if (updatedUser) setLoggedInUser(updatedUser);
      }
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

  const handleRoleViewChange = (val) => {
    setCurrentRoleView(val);
    
    if (val === 'admin') {
      setLoggedInUser(null);
    } else {
      const u = users.find(usr => usr.id === Number(val));
      setLoggedInUser(u || null);
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
      await axios.post(`${API_URL}/certificates`, { userId });
      fetchUsers();
      fetchCerts();
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

  const getLoggedInUserCertDetails = () => {
    if (!loggedInUser) return null;
    return certs.find(c => c.user_id === loggedInUser.id);
  };

  const userCert = getLoggedInUserCertDetails();

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
      
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-sm">
        <div className="max-w-7xl mx-auto px-6 py-4 flex justify-end items-center">
          <div className="flex items-center gap-3">
            <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider hidden md:block">Logged in as:</label>
            <select
              value={currentRoleView}
              onChange={(e) => handleRoleViewChange(e.target.value)}
              className="bg-slate-50 border border-slate-200 hover:border-slate-300 rounded-lg px-3 py-2 text-xs font-medium text-slate-700 outline-none cursor-pointer focus:ring-1 focus:ring-indigo-500"
            >
              <option value="admin">Administrator (Full Dashboard)</option>
              {users.map(u => (
                <option key={u.id} value={u.id}>
                  User: {u.username} ({u.role})
                </option>
              ))}
            </select>
            
            <button 
              onClick={() => { fetchUsers(); fetchCerts(); }} 
              className="p-2 text-slate-500 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 rounded-lg border border-slate-200 shadow-sm transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>
      </nav>

      {currentRoleView === 'admin' ? (
        <main className="max-w-7xl mx-auto px-6 py-8">
          
          <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-sm flex items-center gap-4">
              <div className="p-3 bg-blue-50 text-blue-600 rounded-lg border border-blue-100">
                <Users className="w-5 h-5" />
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Users</p>
                <h3 className="text-2xl font-bold text-slate-900 mt-0.5">{users.length}</h3>
              </div>
            </div>

            <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-sm flex items-center gap-4">
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

            <div className="bg-white border border-slate-200 p-6 rounded-xl shadow-sm flex items-center gap-4">
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

          <div className="bg-white border border-slate-200 rounded-xl p-4 mb-8 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex bg-slate-100 p-1 rounded-lg w-fit border border-slate-200">
              <button 
                onClick={() => { setActiveTab('users'); setSearchQuery(''); }}
                className={`px-4 py-2 text-xs font-medium rounded-md transition-all ${
                  activeTab === 'users' 
                    ? 'bg-white text-slate-900 shadow-sm' 
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Users
              </button>
              <button 
                onClick={() => { setActiveTab('certs'); setSearchQuery(''); }}
                className={`px-4 py-2 text-xs font-medium rounded-md transition-all ${
                  activeTab === 'certs' 
                    ? 'bg-white text-slate-900 shadow-sm' 
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Certificate Registry
              </button>
            </div>

            <div className="relative w-full md:w-80">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input 
                type="text" 
                placeholder={activeTab === 'users' ? 'Search by username or email...' : 'Search by name or serial number...'}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-50 border border-slate-200 hover:border-slate-300 focus:bg-white focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-4 py-2 text-sm outline-none transition-all text-slate-900"
              />
            </div>
          </div>

          {activeTab === 'users' ? (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm h-fit">
                <h3 className="text-sm font-semibold text-slate-900 mb-4 flex items-center gap-2 border-b border-slate-100 pb-3">
                  <UserPlus className="w-4 h-4 text-slate-500" />
                  Add New User
                </h3>
                <form onSubmit={handleAddUser} className="space-y-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-500 mb-1">Username</label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input 
                        type="text" 
                        placeholder="e.g. j_smith" 
                        value={newUsername}
                        onChange={(e) => setNewUsername(e.target.value)}
                        className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-4 py-2 text-sm outline-none transition-all text-slate-900"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-500 mb-1">Email Address</label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input 
                        type="email" 
                        placeholder="e.g. john@pki.local" 
                        value={newEmail}
                        onChange={(e) => setNewEmail(e.target.value)}
                        className="w-full border border-slate-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 rounded-lg pl-9 pr-4 py-2 text-sm outline-none transition-all text-slate-900"
                        required
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-500 mb-1">Role</label>
                    <select 
                      value={newRole} 
                      onChange={(e) => setNewRole(e.target.value)}
                      className="w-full border border-slate-200 focus:border-indigo-500 rounded-lg px-3 py-2 text-sm outline-none text-slate-900 bg-white"
                    >
                      <option value="user">Standard User</option>
                      <option value="admin">Administrator</option>
                    </select>
                  </div>

                  <button 
                    type="submit" 
                    className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg text-sm shadow-sm transition-all active:scale-[0.98]"
                  >
                    Add User
                  </button>
                </form>
              </div>

              <div className="lg:col-span-2 bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-slate-50/70 border-b border-slate-200 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                      <th className="px-6 py-4">Name / Email</th>
                      <th className="px-6 py-4">Role</th>
                      <th className="px-6 py-4">Certificate Status</th>
                      <th className="px-6 py-4 text-right">Key Management</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {filteredUsers.map(user => (
                      <tr key={user.id} className="hover:bg-slate-50/40 transition-colors">
                        <td className="px-6 py-4">
                          <div className="font-medium text-slate-900">{user.username}</div>
                          <div className="text-xs text-slate-500 mt-0.5">{user.email}</div>
                        </td>
                        <td className="px-6 py-4">
                          <span className={`inline-flex px-2 py-0.5 rounded text-[11px] font-medium border ${
                            user.role === 'admin' 
                              ? 'bg-amber-50 text-amber-800 border-amber-200' 
                              : 'bg-slate-50 text-slate-600 border-slate-200'
                          }`}>
                            {user.role === 'admin' ? 'Admin' : 'User'}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          {user.cert_status === 'ACTIVE' ? (
                            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200">
                              <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
                              Active Certificate
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 bg-slate-50 px-2.5 py-1 rounded-full border border-slate-200">
                              No Certificate
                            </span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {user.cert_status === 'ACTIVE' ? (
                              <button 
                                onClick={() => openRevokeModal(user.cert_id)}
                                className="text-xs font-medium text-rose-700 bg-rose-50 hover:bg-rose-100 px-3 py-1.5 rounded-lg border border-rose-200 transition-colors"
                              >
                                Revoke
                              </button>
                            ) : (
                              <button 
                                onClick={() => handleIssueCert(user.id)}
                                className="text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200 shadow-sm transition-colors"
                              >
                                Issue Certificate
                              </button>
                            )}
                            <button 
                              onClick={() => handleDeleteUser(user.id)}
                              className="p-1.5 text-slate-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-all"
                              title="Delete user"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                    {filteredUsers.length === 0 && (
                      <tr>
                        <td colSpan="4" className="text-center py-10 text-slate-400 text-sm">
                          No matching users found.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50/70 border-b border-slate-200 text-slate-500 text-xs font-semibold uppercase tracking-wider">
                    <th className="px-6 py-4">User</th>
                    <th className="px-6 py-4">Key (Serial Number)</th>
                    <th className="px-6 py-4">Certificate Status</th>
                    <th className="px-6 py-4">Validity Dates</th>
                    <th className="px-6 py-4">Revocation Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredCerts.map(cert => (
                    <tr key={cert.id} className="hover:bg-slate-50/40 transition-colors">
                      <td className="px-6 py-4">
                        <div className="font-medium text-slate-900">{cert.username}</div>
                        <div className="text-xs text-slate-500">{cert.email}</div>
                      </td>
                      <td className="px-6 py-4 font-mono text-xs text-slate-600">
                        {cert.serial_number}
                      </td>
                      <td className="px-6 py-4">
                        {cert.status === 'ACTIVE' ? (
                          <span className="inline-flex px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200">
                            Issued / Valid
                          </span>
                        ) : (
                          <span className="inline-flex px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-50 text-rose-800 border border-rose-200">
                            Revoked (CRL)
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-xs text-slate-500">
                        <div className="flex items-center gap-1">
                          <Calendar className="w-3.5 h-3.5 text-slate-400" />
                          <span>Issued: {new Date(cert.issued_at).toLocaleString('en-US')}</span>
                        </div>
                        {cert.revoked_at && (
                          <div className="text-rose-600 mt-1 font-medium">
                            Revoked: {new Date(cert.revoked_at).toLocaleString('en-US')}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 text-xs italic text-slate-500">
                        {cert.revocation_reason ? (
                          <span className="inline-flex items-center gap-1 text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-100">
                            <AlertTriangle className="w-3 h-3 text-rose-500" />
                            {cert.revocation_reason}
                          </span>
                        ) : '-'}
                      </td>
                    </tr>
                  ))}
                  {filteredCerts.length === 0 && (
                    <tr>
                      <td colSpan="5" className="text-center py-10 text-slate-400 text-sm">
                        No records found in certificate registry.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </main>
      ) : (
        <main className="max-w-4xl mx-auto px-6 py-8">
          {loggedInUser && (
            <div className="space-y-6">
              
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div className="flex items-center gap-4">
                  <div className="p-3 bg-slate-100 text-slate-700 rounded-full border border-slate-200">
                    <User className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-lg font-bold text-slate-900">User Dashboard: {loggedInUser.username}</h2>
                    <p className="text-xs text-slate-500">Email: {loggedInUser.email} &bull; Role: {loggedInUser.role}</p>
                  </div>
                </div>
                
                <button
                  onClick={() => handleRoleViewChange('admin')}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors self-start md:self-auto"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  Switch to Admin
                </button>
              </div>

              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
                <h3 className="text-sm font-semibold text-slate-900 mb-4 pb-3 border-b border-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-slate-500" />
                  Your Digital Certificate
                </h3>
                
                {loggedInUser.cert_status === 'ACTIVE' && userCert ? (
                  <div className="space-y-4">
                    <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl flex items-start gap-3">
                      <CheckCircle className="w-5 h-5 text-emerald-600 mt-0.5" />
                      <div>
                        <h4 className="text-sm font-semibold text-emerald-800">You have active digital certificate credentials</h4>
                        <p className="text-xs text-emerald-700 mt-0.5">Your X.509 certificate is installed and active. You are authorized to use it for authentication and signatures.</p>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Certificate Serial Number</p>
                        <p className="text-sm font-mono font-medium text-slate-900 mt-0.5">{userCert.serial_number}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Issue Date</p>
                        <p className="text-sm text-slate-700 mt-0.5">{new Date(userCert.issued_at).toLocaleString('en-US')}</p>
                      </div>
                    </div>

                    <div className="pt-2">
                      <button 
                        onClick={() => alert(`--- MOCK CERTIFICATE PEM ---\nSerialNumber: ${userCert.serial_number}\nSubject: CN=${loggedInUser.username}\nIssuer: CN=Mock-Local-CA\n--- END CERTIFICATE ---`)}
                        className="inline-flex items-center gap-2 px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Download Certificate (PEM)
                      </button>
                    </div>
                  </div>
                ) : userCert && userCert.status === 'REVOKED' ? (
                  <div className="space-y-4">
                    <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-start gap-3">
                      <AlertTriangle className="w-5 h-5 text-rose-600 mt-0.5" />
                      <div>
                        <h4 className="text-sm font-semibold text-rose-800">Your certificate has been revoked! (CRL)</h4>
                        <p className="text-xs text-rose-700 mt-0.5">An administrator has revoked your digital certificate credentials.</p>
                      </div>
                    </div>

                    <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-2">
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Revoked Key Serial Number</p>
                        <p className="text-sm font-mono text-slate-500 mt-0.5">{userCert.serial_number}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Revocation Reason</p>
                        <p className="text-sm font-medium text-rose-700 mt-0.5">{userCert.revocation_reason || 'No specific reason provided'}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Revocation Date</p>
                        <p className="text-sm text-slate-600 mt-0.5">{new Date(userCert.revoked_at).toLocaleString('en-US')}</p>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="p-4 bg-slate-100 border border-slate-200 rounded-xl flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-slate-500 mt-0.5" />
                    <div>
                      <h4 className="text-sm font-semibold text-slate-800">No Digital Certificate</h4>
                      <p className="text-xs text-slate-500 mt-0.5">No key has been issued for your account in this system. Please request a certificate from an administrator in the Admin Panel.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      )}

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
                className="w-full border border-slate-200 focus:border-rose-500 focus:ring-1 focus:ring-rose-500 rounded-lg px-3 py-2 text-sm text-slate-900 placeholder-slate-400 outline-none transition-all"
                required
              />
            </div>
            <div className="flex justify-end gap-2 border-t border-slate-100 pt-4">
              <button 
                onClick={() => setShowRevokeModal(false)}
                className="px-3 py-2 rounded-lg text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button 
                onClick={handleRevokeCert}
                className="px-3 py-2 rounded-lg text-xs font-medium text-white bg-rose-600 hover:bg-rose-700 transition-colors shadow-sm"
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
