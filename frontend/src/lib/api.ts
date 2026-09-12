import axios from 'axios';
import toast from 'react-hot-toast';
import { clearTokens } from '@/lib/utils';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  headers: { 'Content-Type': 'application/json' },
  // Required so the browser sends the HttpOnly refresh_token cookie on /api/auth/* requests.
  // The backend sets Allow-Credentials: true with explicit allow_origins (not wildcard).
  withCredentials: true,
});

// Attach access token to every request
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('access_token');
    if (token) config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-refresh on 401
// The browser automatically sends the HttpOnly refresh_token cookie to /api/auth/refresh.
// No need to read the refresh token from localStorage.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      try {
        // Cookie is sent automatically — no body required for browser clients.
        // The server still returns the new access token in the JSON body.
        const res = await axios.post(
          `${API_URL}/api/auth/refresh`,
          {},
          { withCredentials: true },
        );
        const { access_token } = res.data;
        localStorage.setItem('access_token', access_token);
        original.headers.Authorization = `Bearer ${access_token}`;
        return api(original);
      } catch {
        clearTokens();
        if (typeof window !== 'undefined') {
          const isAdmin = window.location.pathname.startsWith('/admin');
          const loginPath = isAdmin
            ? '/admin/login?error=session_expired'
            : '/login';
          if (window.location.pathname !== loginPath) {
            window.location.href = loginPath;
          }
        }
        return Promise.reject(error);
      }
    }
    let msg = error.response?.data?.detail;
    if (!msg && error.response?.data instanceof Blob) {
      try {
        const text = await error.response.data.text();
        const parsed = JSON.parse(text);
        msg = parsed.detail || parsed.message;
      } catch {
        msg = 'An error occurred while processing the request.';
      }
    }
    if (!msg) {
      msg = error.message || 'Something went wrong';
    }

    const config = error.config || {};
    if (
      !config.skipGlobalToast &&
      !config.silent &&
      error.response?.status !== 401 &&
      error.response?.status !== 403
    ) {
      toast.error(msg);
    }
    return Promise.reject(error);
  }
);

export default api;
