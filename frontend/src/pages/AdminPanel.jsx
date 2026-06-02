import { useState, useEffect } from 'react';
import { api, removeAuthToken } from '../services/api';
import { useNavigate, Link } from 'react-router-dom';
import { LogOut, FileText, UploadCloud, Trash2, Shield, Eye, Download, Users, Activity } from 'lucide-react';

export default function AdminPanel() {
  const [secrets, setSecrets] = useState([]);
  const [media, setMedia] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [revealedSecrets, setRevealedSecrets] = useState({}); // id -> payload
  const [previewedMedia, setPreviewedMedia] = useState({});   // id -> { url, contentType }
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setLoading(true);
      // Admin gets all secrets, media, and audit logs automatically from the backend
      const [secretsRes, mediaRes, auditRes] = await Promise.all([
        api.getSecrets().catch(() => ({ data: [] })),
        api.getMedia().catch(() => ({ data: [] })),
        api.getAuditLogs().catch(() => ({ data: [] }))
      ]);
      setSecrets(secretsRes?.data || []);
      setMedia(mediaRes?.data || []);
      setAuditLogs(auditRes?.data || []);
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

  const handleDeleteSecret = async (id) => {
    if (!window.confirm('Are you sure you want to delete this secret?')) return;
    try {
      await api.deleteSecret(id);
      setRevealedSecrets(prev => { const n = {...prev}; delete n[id]; return n; });
      loadData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handleRevealSecret = async (id) => {
    if (revealedSecrets[id] !== undefined) {
      setRevealedSecrets(prev => { const n = {...prev}; delete n[id]; return n; });
      return;
    }
    try {
      const data = await api.getSecret(id);
      setRevealedSecrets(prev => ({ ...prev, [id]: data.payload }));
    } catch (err) {
      alert(err.message);
    }
  };

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
      if (previewedMedia[id]) {
        window.URL.revokeObjectURL(previewedMedia[id].url);
        setPreviewedMedia(prev => { const n = {...prev}; delete n[id]; return n; });
      }
      loadData();
    } catch (err) {
      alert(err.message);
    }
  };

  const handlePreviewMedia = async (id, contentType) => {
    if (previewedMedia[id]) {
      window.URL.revokeObjectURL(previewedMedia[id].url);
      setPreviewedMedia(prev => { const n = {...prev}; delete n[id]; return n; });
      return;
    }
    try {
      const blob = await api.downloadMedia(id);
      const url = window.URL.createObjectURL(blob);
      setPreviewedMedia(prev => ({ ...prev, [id]: { url, contentType } }));
    } catch (err) {
      alert('Failed to load preview');
    }
  };

  if (loading) {
    return <div className="container" style={{ display: 'flex', justifyContent: 'center', marginTop: '100px' }}><span className="spinner" style={{width: '40px', height: '40px'}}></span></div>;
  }

  return (
    <>
      <nav>
        <Link to="/dashboard" className="logo">
          <Shield size={24} /> Secure Storage (Admin)
        </Link>
        <div className="user-info" style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <Link to="/dashboard" className="btn btn-ghost" style={{ padding: '8px 16px', textDecoration: 'none' }}>
            To Dashboard
          </Link>
          <button onClick={handleLogout} className="btn btn-ghost" style={{ padding: '8px 16px' }}>
            <LogOut size={16} /> Logout
          </button>
        </div>
      </nav>

      <div className="container">
        <div style={{ marginBottom: '24px', padding: '16px', background: 'rgba(255,50,50,0.1)', border: '1px solid rgba(255,50,50,0.3)', borderRadius: '8px', color: '#ffaaaa' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '8px' }}><Users size={24} /> Admin Panel Overview</h2>
          <p style={{ margin: 0 }}>You are viewing all users' secrets and media objects across the platform.</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '24px' }}>
          
          {/* ----- Секреты ----- */}
          <div className="glass-panel">
            <h3><FileText size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }}/> All Platform Secrets</h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {secrets.length === 0 ? (
                <p style={{ color: 'var(--text-secondary)' }}>No secrets found in the system.</p>
              ) : (
                secrets.map(secret => (
                  <div key={secret.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', borderLeft: '3px solid var(--accent)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div>
                        <h4 style={{ margin: 0, color: 'var(--accent)' }}>{secret.title}</h4>
                        <div style={{ fontSize: '0.8rem', color: '#aaa', marginTop: '4px' }}>
                          Owner ID: {secret.owner_id}
                        </div>
                        <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                          {new Date(secret.created_at).toLocaleString()}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px' }}>
                        <button
                          onClick={() => handleRevealSecret(secret.id)}
                          className="btn btn-ghost"
                          style={{ width: 'auto', padding: '8px', border: 'none' }}
                          title={revealedSecrets[secret.id] !== undefined ? 'Hide' : 'Reveal'}
                        >
                          <Eye size={16} />
                        </button>
                        <button onClick={() => handleDeleteSecret(secret.id)} className="btn btn-danger" style={{ width: 'auto', padding: '8px' }}>
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>
                    {revealedSecrets[secret.id] !== undefined && (
                      <div style={{
                        marginTop: '12px',
                        padding: '10px',
                        background: 'rgba(255,255,255,0.05)',
                        borderRadius: '6px',
                        fontFamily: 'monospace',
                        fontSize: '0.9rem',
                        color: 'var(--text-primary)',
                        wordBreak: 'break-all',
                        whiteSpace: 'pre-wrap',
                      }}>
                        {revealedSecrets[secret.id]}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* ----- Медиа ----- */}
          <div className="glass-panel">
            <h3><UploadCloud size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }}/> All Platform Media</h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {media.length === 0 ? (
                <p style={{ color: 'var(--text-secondary)' }}>No files uploaded in the system.</p>
              ) : (
                media.map(m => (
                  <div key={m.id} style={{ background: 'rgba(0,0,0,0.2)', padding: '16px', borderRadius: '8px', borderLeft: '3px solid #8e44ad' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                      <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginRight: '16px' }}>
                        <h4 style={{ margin: 0 }}>{m.filename}</h4>
                        <div style={{ fontSize: '0.8rem', color: '#aaa', marginTop: '4px' }}>
                          Owner ID: {m.owner_id}
                        </div>
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                          {(m.size_bytes / 1024).toFixed(1)} KB &nbsp;·&nbsp; {m.content_type}
                        </span>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                          {new Date(m.created_at).toLocaleString()}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
                        {(m.content_type?.startsWith('image/') || m.content_type?.startsWith('video/')) && (
                          <button
                            onClick={() => handlePreviewMedia(m.id, m.content_type)}
                            className="btn btn-ghost"
                            style={{ width: 'auto', padding: '8px', border: 'none' }}
                            title={previewedMedia[m.id] ? 'Hide' : 'Preview'}
                          >
                            <Eye size={16} />
                          </button>
                        )}
                        <button onClick={() => handleDownloadMedia(m.id, m.filename)} className="btn btn-ghost" style={{ width: 'auto', padding: '8px', border: 'none' }} title="Download">
                          <Download size={16} />
                        </button>
                        <button onClick={() => handleDeleteMedia(m.id)} className="btn btn-danger" style={{ width: 'auto', padding: '8px' }} title="Delete">
                          <Trash2 size={16} />
                        </button>
                      </div>
                    </div>

                    {/* Inline preview */}
                    {previewedMedia[m.id] && (
                      <div style={{ marginTop: '12px', borderRadius: '8px', overflow: 'hidden', background: 'rgba(0,0,0,0.3)' }}>
                        {previewedMedia[m.id].contentType.startsWith('image/') ? (
                          <img
                            src={previewedMedia[m.id].url}
                            alt={m.filename}
                            style={{ width: '100%', maxHeight: '400px', objectFit: 'contain', display: 'block' }}
                          />
                        ) : (
                          <video
                            src={previewedMedia[m.id].url}
                            controls
                            style={{ width: '100%', maxHeight: '400px', display: 'block' }}
                          />
                        )}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

        </div>

        {/* ----- Аудит-логи ----- */}
        <div className="glass-panel" style={{ marginTop: '24px' }}>
          <h3><Activity size={20} style={{ verticalAlign: 'middle', marginRight: '8px' }}/> System Audit Logs</h3>
          <div style={{ overflowX: 'auto', marginTop: '16px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.2)' }}>
                  <th style={{ padding: '12px' }}>Time</th>
                  <th style={{ padding: '12px' }}>User ID</th>
                  <th style={{ padding: '12px' }}>Action</th>
                  <th style={{ padding: '12px' }}>Resource</th>
                  <th style={{ padding: '12px' }}>Status</th>
                  <th style={{ padding: '12px' }}>IP / Agent</th>
                </tr>
              </thead>
              <tbody>
                {auditLogs.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ padding: '12px', textAlign: 'center', color: 'var(--text-secondary)' }}>No audit logs found.</td>
                  </tr>
                ) : (
                  auditLogs.map(log => (
                    <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '12px', whiteSpace: 'nowrap' }}>{new Date(log.created_at).toLocaleString()}</td>
                      <td style={{ padding: '12px', fontFamily: 'monospace' }} title={log.user_id}>{log.user_id ? log.user_id.substring(0, 8) + '...' : '-'}</td>
                      <td style={{ padding: '12px' }}>
                        <span style={{ 
                          background: 'rgba(255,255,255,0.1)', 
                          padding: '4px 8px', 
                          borderRadius: '4px',
                          textTransform: 'uppercase',
                          fontSize: '0.75rem'
                        }}>{log.action}</span>
                      </td>
                      <td style={{ padding: '12px' }}>
                        {log.resource || '-'}
                        {log.resource_id && <div style={{ fontSize: '0.7rem', color: '#aaa', fontFamily: 'monospace' }}>{log.resource_id.substring(0, 8) + '...'}</div>}
                      </td>
                      <td style={{ padding: '12px' }}>
                        <span style={{ color: log.status === 'success' ? '#2ecc71' : '#e74c3c' }}>
                          {log.status}
                        </span>
                        {log.details && <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{log.details}</div>}
                      </td>
                      <td style={{ padding: '12px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        <div>{log.ip_address}</div>
                        <div style={{ maxWidth: '150px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={log.user_agent}>{log.user_agent}</div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </>
  );
}
