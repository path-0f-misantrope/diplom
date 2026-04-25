const API_URL = 'http://localhost:8080/api/v1';

export const getAuthToken = () => localStorage.getItem('token');
export const setAuthToken = (token) => localStorage.setItem('token', token);
export const removeAuthToken = () => localStorage.removeItem('token');

// Базовая функция обертка для fetch
async function fetchWithAuth(endpoint, options = {}) {
  const token = getAuthToken();
  const headers = {
    ...options.headers,
    ...(token && { Authorization: `Bearer ${token}` }),
  };

  const config = {
    ...options,
    headers,
  };

  const response = await fetch(`${API_URL}${endpoint}`, config);

  if (!response.ok) {
    if (response.status === 401) {
      removeAuthToken();
      window.location.href = '/login'; // Простейший редирект, если токен протух
    }
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.error || response.statusText);
  }

  return response.json();
}

export const api = {
  // Auth
  register: (data) =>
    fetch(`${API_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).then(async (res) => {
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Ошибка регистрации');
      }
      return res.json();
    }),

  login: (data) =>
    fetch(`${API_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }).then(async (res) => {
      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Ошибка входа');
      }
      return res.json();
    }),

  getMe: () => fetchWithAuth('/auth/me', { method: 'GET' }),
  logout: () => fetchWithAuth('/auth/logout', { method: 'POST' }),

  // Secrets
  getSecrets: () => fetchWithAuth('/secrets', { method: 'GET' }),
  createSecret: (data) =>
    fetchWithAuth('/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }),
  deleteSecret: (id) => fetchWithAuth(`/secrets/${id}`, { method: 'DELETE' }),
  getSecret: (id) => fetchWithAuth(`/secrets/${id}`, { method: 'GET' }),

  // Media
  getMedia: () => fetchWithAuth('/media', { method: 'GET' }),
  uploadMedia: async (file) => {
    const token = getAuthToken();
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(`${API_URL}/media/upload`, {
      method: 'POST',
      headers: {
        ...(token && { Authorization: `Bearer ${token}` }),
        // Content-Type устанавливается автоматически браузером для FormData
      },
      body: formData,
    });

    if (!res.ok) {
        const error = await res.json();
        throw new Error(error.error || 'Upload error');
    }
    return res.json();
  },
  downloadMedia: async (id) => {
    const token = getAuthToken();
    const response = await fetch(`${API_URL}/media/${id}/download`, {
        headers: {
            ...(token && { Authorization: `Bearer ${token}` }),
        }
    });
    if (!response.ok) throw new Error('Download failed');
    return response.blob();
  },
  deleteMedia: (id) => fetchWithAuth(`/media/${id}`, { method: 'DELETE' }),
};
