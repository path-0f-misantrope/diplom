import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../services/api';
import { ShieldCheck } from 'lucide-react';

export default function Register() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await api.register({ username, password });
      setSuccess(true);
      setTimeout(() => navigate('/login'), 2000);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flex: 1 }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '400px' }}>
        <div className="text-center" style={{ marginBottom: '24px' }}>
          <ShieldCheck size={48} color="var(--success)" style={{ marginBottom: '16px' }} />
          <h2>Create Account</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Get started with secure storage</p>
        </div>

        {error && <div className="error-message">{error}</div>}
        {success && <div className="success-message">Account created! Redirecting to login...</div>}

        {!success && (
          <form onSubmit={handleRegister}>
            <input
              type="text"
              className="input-field"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
            <input
              type="password"
              className="input-field"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
            />
            <button type="submit" className="btn" disabled={loading} style={{ background: 'var(--success)' }}>
              {loading ? <span className="spinner"></span> : 'Sign Up'}
            </button>
          </form>
        )}

        <p className="text-center mt-4" style={{ fontSize: '0.875rem' }}>
          Already have an account? <Link to="/login" style={{ color: 'var(--accent)' }}>Sign in</Link>
        </p>
      </div>
    </div>
  );
}
