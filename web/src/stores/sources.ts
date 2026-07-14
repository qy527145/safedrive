import { create } from 'zustand';
import { api, type DsRecord } from '../api/client';

interface SourcesState {
  list: DsRecord[];
  loaded: boolean;
  refresh: () => Promise<void>;
}

export const useSources = create<SourcesState>()((set) => ({
  list: [],
  loaded: false,
  refresh: async () => {
    const list = await api.listDs();
    set({ list, loaded: true });
  },
}));
