import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { api } from '../services/api';
import { ShieldCheck } from 'lucide-react';

export default function Register() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
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
      await api.register({ username, email, password });
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
          <h2>Создать аккаунт</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Начните работу с защищённым хранилищем</p>
        </div>

        {error && <div className="error-message">{error}</div>}
        {success && <div className="success-message">Аккаунт создан! Перенаправление на страницу входа...</div>}

        {!success && (
          <form onSubmit={handleRegister}>
            <input
              type="text"
              className="input-field"
              placeholder="Имя пользователя"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              minLength={3}
              maxLength={64}
            />
            <input
              type="email"
              className="input-field"
              placeholder="Эл. почта"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <input
              type="password"
              className="input-field"
              placeholder="Пароль"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
            />
            <button type="submit" className="btn" disabled={loading} style={{ background: 'var(--success)' }}>
              {loading ? <span className="spinner"></span> : 'Зарегистрироваться'}
            </button>
          </form>
        )}

        <p className="text-center mt-4" style={{ fontSize: '0.875rem' }}>
          Уже есть аккаунт? <Link to="/login" style={{ color: 'var(--accent)' }}>Войти</Link>
        </p>
      </div>
    </div>
  );
}
