import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  User, 
  Download,
  Radio,
  ExternalLink,
  RefreshCw,
  CheckCircle,
  FileText,
  Key,
  WifiOff
} from 'lucide-react';

const API_URL = 'http://localhost:5001/api';

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

export default function App() {
  const [users, setUsers] = useState([]);
  const [selectedUserId, setSelectedUserId] = useState(null);
  const [userCert, setUserCert] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    if (selectedUserId) {
      fetchUserCert(selectedUserId);
    } else {
      setUserCert(null);
    }
  }, [selectedUserId]);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const res = await axios.get(`${API_URL}/users`);
      setUsers(res.data);
      if (res.data.length > 0 && !selectedUserId) {
        setSelectedUserId(res.data[0].id);
      }
    } catch (err) {
      console.error('Błąd pobierania listy węzłów/użytkowników:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchUserCert = async (userId) => {
    try {
      const res = await axios.get(`${API_URL}/certificates/user/${userId}`);
      setUserCert(res.data);
    } catch (err) {
      setUserCert(null);
    }
  };

  const selectedUser = users.find(u => u.id === Number(selectedUserId));

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
      alert('Nie udało się pobrać certyfikatu Root CA z portalu klienta.');
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

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 antialiased font-sans">
      {/* Top Navbar */}
      <nav className="bg-white border-b border-slate-200 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto px-6 py-4 flex flex-col md:flex-row justify-between items-center gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-emerald-600 text-white rounded-xl shadow-xs">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-base font-bold text-slate-900 leading-tight">
                PKI Edge Portal
              </h1>
              <p className="text-xs text-slate-500 font-medium">
                Panel Samoobsługowy Węzła Polowego / Klienta
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 w-full md:w-auto justify-end">
            <div className="flex items-center gap-2">
              <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider hidden sm:block">
                Tożsamość:
              </label>
              <select
                value={selectedUserId || ''}
                onChange={(e) => setSelectedUserId(Number(e.target.value))}
                className="bg-slate-50 border border-slate-200 hover:border-slate-300 rounded-lg px-3 py-2 text-xs font-medium text-slate-700 outline-none cursor-pointer focus:ring-1 focus:ring-emerald-500"
              >
                {users.map(u => (
                  <option key={u.id} value={u.id}>
                    Węzeł: {u.username} ({u.role})
                  </option>
                ))}
              </select>
            </div>

            <button 
              onClick={() => { fetchUsers(); if (selectedUserId) fetchUserCert(selectedUserId); }} 
              className="p-2 text-slate-500 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 rounded-lg border border-slate-200 shadow-2xs transition-colors cursor-pointer"
              title="Odśwież dane"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>

            <a
              href="http://localhost:3000"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition-colors shadow-2xs"
              title="Przejdź do Panelu Administratora CA (port 3000)"
            >
              <span>Panel Admina (3000)</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-4xl mx-auto px-6 py-8">
        {selectedUser ? (
          <div className="space-y-6">
            
            {/* Identity Banner */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-emerald-50 text-emerald-700 rounded-full border border-emerald-100">
                  <User className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-slate-900">{selectedUser.username}</h2>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-slate-100 text-slate-600 border border-slate-200">
                      {selectedUser.role}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-0.5">
                    Email: <span className="font-mono text-slate-700">{selectedUser.email}</span> &bull; ID: #{selectedUser.id}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 self-start md:self-auto">
                <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${
                  userCert && userCert.status === 'ACTIVE'
                    ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                    : userCert && userCert.status === 'REVOKED'
                    ? 'bg-rose-100 text-rose-800 border border-rose-200'
                    : 'bg-amber-100 text-amber-800 border border-amber-200'
                }`}>
                  {userCert && userCert.status === 'ACTIVE' && <CheckCircle className="w-3.5 h-3.5" />}
                  {userCert && userCert.status === 'REVOKED' && <AlertTriangle className="w-3.5 h-3.5" />}
                  {userCert ? userCert.status : 'NO CERT'}
                </span>
              </div>
            </div>

            {/* Certificate Details Card */}
            <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs">
              <h3 className="text-sm font-semibold text-slate-900 mb-4 pb-3 border-b border-slate-100 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                Stan Poświadczeń Cyfrowych X.509
              </h3>

              {userCert && userCert.status === 'ACTIVE' ? (
                <div className="space-y-5">
                  <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-xl flex items-start gap-3">
                    <CheckCircle className="w-5 h-5 text-emerald-600 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="text-sm font-semibold text-emerald-900">
                        Twój certyfikat cyfrowy X.509 jest aktywny i zaufany
                      </h4>
                      <p className="text-xs text-emerald-700 mt-0.5">
                        Posiadasz ważny podpis Root CA. Możesz pobrać certyfikat do weryfikacji tożsamości oraz łączności szyfrowanej.
                      </p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-200">
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Numer Seryjny (Serial Number)</p>
                      <p className="text-sm font-mono font-medium text-slate-900 mt-0.5 break-all">{userCert.serial_number}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Data Wystawienia</p>
                      <p className="text-sm text-slate-700 mt-0.5">{new Date(userCert.issued_at).toLocaleString('pl-PL')}</p>
                    </div>
                    {userCert.fingerprint && (
                      <div className="md:col-span-2 pt-2 border-t border-slate-200">
                        <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Odcisk Palca (SHA-256 Fingerprint)</p>
                        <p className="text-xs font-mono text-slate-600 mt-0.5 break-all">{userCert.fingerprint}</p>
                      </div>
                    )}
                  </div>

                  <div className="pt-3 border-t border-slate-100">
                    <div className="flex items-center gap-2 mb-2">
                      <Radio className="w-4 h-4 text-emerald-600" />
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
                        Pobieranie Poświadczeń do Pracy Offline / P2P
                      </h4>
                    </div>
                    <p className="text-xs text-slate-500 mb-4">
                      W środowisku o ograniczonej łączności (np. radio morskie, stacja polowa) węzeł weryfikuje inne jednostki za pomocą certyfikatu Root CA oraz listy CRL.
                    </p>

                    <div className="flex flex-wrap gap-3">
                      <button 
                        onClick={() => downloadFile(`${selectedUser.username}_cert.pem`, userCert.certificate_pem)}
                        className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-semibold text-emerald-800 bg-emerald-50 hover:bg-emerald-100 rounded-lg border border-emerald-200 transition-colors shadow-2xs cursor-pointer"
                        title="Pobierz plik certyfikatu X.509 węzła"
                      >
                        <Download className="w-3.5 h-3.5" />
                        Pobierz Certyfikat Węzła (PEM)
                      </button>

                      <button 
                        onClick={handleDownloadCaCert}
                        className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-semibold text-indigo-800 bg-indigo-50 hover:bg-indigo-100 rounded-lg border border-indigo-200 transition-colors shadow-2xs cursor-pointer"
                        title="Pobierz certyfikat Root CA zaufanego urzędu"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        Pobierz Root CA (PEM)
                      </button>

                      <button 
                        onClick={handleDownloadCrl}
                        className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-semibold text-slate-700 bg-slate-50 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors shadow-2xs cursor-pointer"
                        title="Pobierz najnowszą listę unieważnień CRL"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        Pobierz Listę CRL (PEM)
                      </button>
                    </div>
                  </div>
                </div>
              ) : userCert && userCert.status === 'REVOKED' ? (
                <div className="space-y-5">
                  <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl flex items-start gap-3">
                    <AlertTriangle className="w-5 h-5 text-rose-600 mt-0.5 shrink-0" />
                    <div>
                      <h4 className="text-sm font-semibold text-rose-900">
                        Certyfikat tego węzła został UNIEWAŻNIONY (CRL)
                      </h4>
                      <p className="text-xs text-rose-700 mt-0.5">
                        Administrator wycofał poświadczenia dla tego węzła. Inne jednostki posiadające aktualną listę CRL odrzucą komunikację.
                      </p>
                    </div>
                  </div>

                  <div className="bg-slate-50 p-4 rounded-xl border border-slate-200 space-y-3">
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Unieważniony Numer Seryjny</p>
                      <p className="text-sm font-mono text-slate-600 mt-0.5">{userCert.serial_number}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Powód Wycofania (Revocation Reason)</p>
                      <p className="text-sm font-medium text-rose-700 mt-0.5">{userCert.revocation_reason || 'Administrative revocation'}</p>
                    </div>
                    <div>
                      <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Data Wycofania</p>
                      <p className="text-sm text-slate-600 mt-0.5">{new Date(userCert.revoked_at).toLocaleString('pl-PL')}</p>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-100">
                    <p className="text-xs text-slate-500 mb-3">
                      Pobierz najnowszą listę odwołań CRL, aby sprawdzić wpis o unieważnieniu:
                    </p>
                    <button 
                      onClick={handleDownloadCrl}
                      className="inline-flex items-center gap-2 px-3.5 py-2.5 text-xs font-semibold text-rose-800 bg-rose-50 hover:bg-rose-100 rounded-lg border border-rose-200 transition-colors cursor-pointer"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Pobierz Aktualną Listę CRL (PEM)
                    </button>
                  </div>
                </div>
              ) : (
                <div className="p-6 bg-slate-50 border border-slate-200 rounded-xl text-center space-y-3">
                  <div className="p-3 bg-amber-50 text-amber-600 rounded-full w-fit mx-auto">
                    <WifiOff className="w-6 h-6" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-800">Brak Wydanego Certyfikatu</h4>
                    <p className="text-xs text-slate-500 max-w-md mx-auto mt-1">
                      Dla węzła <span className="font-semibold text-slate-700">{selectedUser.username}</span> nie wygenerowano jeszcze certyfikatu cyfrowego.
                      Skontaktuj się z administratorem urzędu Root CA w celu wystawienia tożsamości.
                    </p>
                  </div>
                  <div className="pt-2">
                    <a
                      href="http://localhost:3000"
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-indigo-700 bg-white hover:bg-slate-100 rounded-lg border border-slate-300 transition-colors"
                    >
                      <span>Otwórz Panel Administratora</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </div>
                </div>
              )}
            </div>

            {/* Tactical Explanatory Card */}
            <div className="bg-indigo-900 text-white rounded-xl p-6 shadow-md">
              <div className="flex items-center gap-2 mb-2">
                <Radio className="w-5 h-5 text-indigo-300" />
                <h4 className="text-sm font-bold uppercase tracking-wider text-indigo-200">
                  Model Weryfikacji X.509 w Środowisku Rozproszonym (Data Mule / Radio)
                </h4>
              </div>
              <p className="text-xs text-indigo-100 leading-relaxed">
                W architekturze PKI z ograniczoną łącznością stacja polowa nie łączy się z bazą danych na lądzie podczas spotkania z inną jednostką.
                Wystarczy certyfikat <code className="bg-indigo-800 px-1.5 py-0.5 rounded text-indigo-200">ca_certificate.pem</code> oraz lista unieważnień <code className="bg-indigo-800 px-1.5 py-0.5 rounded text-indigo-200">crl.pem</code>, aby w 100% offline potwierdzić ważność certyfikatu innego statku za pomocą kryptografii asymetrycznej (RSA + SHA-256).
              </p>
            </div>

          </div>
        ) : (
          <div className="text-center py-12 text-slate-400">
            Wybierz tożsamość węzła z listy powyżej.
          </div>
        )}
      </main>
    </div>
  );
}
