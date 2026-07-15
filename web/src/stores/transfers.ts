import { create } from 'zustand';
import { api, type TransferSnapshot } from '../api/client';

const EMPTY: TransferSnapshot = { uploadSpeed: 0, downloadSpeed: 0, fileDownloadSpeeds: {} };
const HISTORY = 36;

interface TransferState {
  snapshot: TransferSnapshot;
  uploadHistory: number[];
  downloadHistory: number[];
}

export const useTransfers = create<TransferState>()(() => ({
  snapshot: EMPTY,
  uploadHistory: [],
  downloadHistory: [],
}));

let running = false;
let timer: number | undefined;

export function startTransferPolling() {
  if (running) return () => undefined;
  running = true;
  const poll = async () => {
    if (!running) return;
    try {
      const snapshot = await api.transferStatus();
      useTransfers.setState((state) => ({
        snapshot,
        uploadHistory: [...state.uploadHistory, snapshot.uploadSpeed].slice(-HISTORY),
        downloadHistory: [...state.downloadHistory, snapshot.downloadSpeed].slice(-HISTORY),
      }));
    } catch { /* 短暂断线保留最后一次读数，下一轮自动恢复 */ }
    if (running) timer = window.setTimeout(poll, document.hidden ? 1000 : 250);
  };
  void poll();
  return () => {
    running = false;
    if (timer !== undefined) window.clearTimeout(timer);
  };
}
