import { create } from 'zustand';
import { api, setToken, setUnauthorizedHandler } from '../api/client';

interface AuthState {
  /** null = 未探测 */
  required: boolean | null;
  authed: boolean;
  init: () => Promise<void>;
  login: (password: string) => Promise<void>;
  logout: () => void;
}

export const useAuth = create<AuthState>()((set) => ({
  required: null,
  authed: !!localStorage.getItem('sd.token'),

  init: async () => {
    setUnauthorizedHandler(() => {
      setToken(null);
      set({ authed: false });
    });
    const health = await api.health();
    set({ required: health.auth });
    if (!health.auth) set({ authed: true });
  },

  login: async (password: string) => {
    const { token } = await api.login(password);
    setToken(token);
    set({ authed: true });
  },

  logout: () => {
    setToken(null);
    set({ authed: false });
  },
}));
