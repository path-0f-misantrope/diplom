import { useState, useEffect } from 'react';
import { api, removeAuthToken } from '../services/api';
import { useNavigate, Link } from 'react-router-dom';
import { LogOut, FileText, UploadCloud, Trash2, Shield, Download } from 'lucide-react';

export default function Dashboard() {
  const [secrets, setSecrets] = useState([]);
  const [media, setMedia] = useState([]);
  const [newTitle, setNewTitle] = useState('');
  const [newContent, setNewContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      const [secretsRes, mediaRes] = await Promise.all([
        api.getSecrets().catch(() => []), 
        api.getMedia().catch(() => [])
      ]);
      setSecrets(secretsRes || []);
      setMedia(mediaRes || []);
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    try {
      await api.logout();
    } catch (e) {
      console.error('Logout error UI');
    }
    removeAuthToken();
    navigate('/login');
  };

  const handleCreateSecret = async (e) => {
    e.preventDefault();
    try {
      await api.createSecret({ title: newTitle, content: newContent });
      setNewTitle('');
      setNewContent('');
      loadData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleDeleteSecret = async (id) => {
    if (!window.confirm('Are you sure?')) return;
    try {
      await api.deleteSecret(id);
      loadData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    try {
      await api.uploadMedia(file);
      loadData();
    } catch (err) {
      alert(err.message);
    } finally {
      setUploading(false);
      e.target.value = null; // reset input
    }
  };

  // Простейший механизм для скачивания файла
  const handleDownloadMedia = async (id, filename) => {
    try {
      const blob = await api.downloadMedia(id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download');
    }
  };

  const handleDeleteMedia = async (id) => {
    if (!window.confirm('Delete media?')) return;
    try {
      await api.deleteMedia(id);
      loadData();
    } catch (err) {
      alert(err.message);
    }
  };

  if (loading) {
    return <div className="container" style={{ display: 'flex', justifyContent: 'center', marginTop: '100px' }}><span className="spinner" style={{width: '40px', height: '40px'}}></span></div>;
  }

  return (
    <>
      <nav>
        <Link to="/dashboard" className="logo">
          <Shield size={24} /> Secure Storage
        </Link>
        <div className="user-info">
          <button onClick={handleLogout} className="btn btn-ghost" style={{ padding: '8px 16px' }}>
            <LogOut size={16} /> Logout
          </button>
        </div>
      </nav>

      <div className="container">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
          
          {/* ----- Секреты ----- */}
          <div className="glass-panel">
            <h3><FileText size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }}/> Your Secrets</h3>
            
            <form onSubmit={handleCreateSecret} style={{ marginBottom: '24px' }}>
              <input 
                type="text" 
                className="input-field" 
                placeholder="Secret Title" 
                value={newTitle} 
                onChange={e => setNewTitle(e.target.value)} 
                required 
              />
              <textarea 
                className="input-field" 
                placeholder="Top Secret Content..." 
                rows="3" 
                value={newContent} 
                onChange={e => setNewContent(e.target.value)} 
                style={{ resize: 'vertical' }}
                required 
              />
              <button type="submit" className="btn mb-4">Save Secret</button>
            </form>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {secrets.length === 0 ? (
                <p style={{ color: 'var(--text-secondary)' }}>No secrets found.</p>
              ) : (
                secrets.map(secret => (
                  <div key={secret.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h4 style={{ margin: 0, color: 'var(--accent)' }}>{secret.title}</h4>
                      <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>id: {secret.id}</div>
                    </div>
                    <button onClick={() => handleDeleteSecret(secret.id)} className="btn btn-danger" style={{ width: 'auto', padding: '8px' }}>
                      <Trash2 size={16} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* ----- Медиа ----- */}
          <div className="glass-panel">
            <h3><UploadCloud size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }}/> Secure Media</h3>
            
            <div style={{ marginBottom: '24px', position: 'relative' }}>
              <input 
                type="file" 
                onChange={handleFileUpload} 
                style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', opacity: 0, cursor: 'pointer' }}
                disabled={uploading}
              />
              <div style={{ padding: '32px', textAlign: 'center', border: '2px dashed var(--panel-border)', borderRadius: '8px', background: 'rgba(255,255,255,0.02)' }}>
                 {uploading ? <span className="spinner"></span> : <><UploadCloud size={32} color="var(--text-secondary)" /><br/><span>Click or drag file to upload</span></>}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {media.length === 0 ? (
                <p style={{ color: 'var(--text-secondary)' }}>No files uploaded.</p>
              ) : (
                media.map(m => (
                  <div key={m.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginRight: '16px' }}>
                      <h4 style={{ margin: 0 }}>{m.filename}</h4>
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{(m.size / 1024).toFixed(1)} KB</span>
                    </div>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button onClick={() => handleDownloadMedia(m.id, m.filename)} className="btn btn-ghost" style={{ width: 'auto', padding: '8px', border: 'none' }} title="Download">
                        <Download size={16} />
                      </button>
                      <button onClick={() => handleDeleteMedia(m.id)} className="btn btn-danger" style={{ width: 'auto', padding: '8px' }} title="Delete">
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </>
  );
}

