import { create } from 'zustand';

export interface TransferTask {
  id: string;
  kind: 'upload' | 'download';
  name: string;
  dsName: string;
  totalBytes: number;
  /** 本地维度：上传 = 已加密/分卷的字节；下载 = 已接收字节 */
  doneBytes: number;
  /** 远端维度（仅上传）：存储端已确认接收的字节 */
  uploadedBytes: number;
  status: 'queued' | 'running' | 'done' | 'error' | 'canceled';
  error?: string;
}

type Runner = (task: TransferTask, signal: AbortSignal) => Promise<void>;

const CONCURRENCY = 3;
const controllers = new Map<string, AbortController>();
const runners = new Map<string, Runner>();

interface TasksState {
  tasks: TransferTask[];
  enqueue: (task: Omit<TransferTask, 'status' | 'doneBytes' | 'uploadedBytes'>, run: Runner) => void;
  cancel: (id: string) => void;
  /** 失败任务重新排队（从头重传，runner 会被再次执行）。 */
  retry: (id: string) => void;
  clearFinished: () => void;
  /** 内部：更新进度 */
  _patch: (id: string, patch: Partial<TransferTask>) => void;
}

export const useTasks = create<TasksState>()((set, getState) => ({
  tasks: [],

  enqueue: (task, run) => {
    runners.set(task.id, run);
    set((s) => ({
      tasks: [...s.tasks, { ...task, status: 'queued', doneBytes: 0, uploadedBytes: 0 }],
    }));
    pump(set, getState);
  },

  cancel: (id) => {
    controllers.get(id)?.abort();
    set((s) => ({
      tasks: s.tasks.map((t) =>
        t.id === id && (t.status === 'queued' || t.status === 'running')
          ? { ...t, status: 'canceled' }
          : t,
      ),
    }));
    runners.delete(id);
    pump(set, getState);
  },

  retry: (id) => {
    const task = getState().tasks.find((t) => t.id === id);
    if (!task || task.status !== 'error' || !runners.has(id)) return;
    set((s) => ({
      tasks: s.tasks.map((t) =>
        t.id === id
          ? { ...t, status: 'queued', doneBytes: 0, uploadedBytes: 0, error: undefined }
          : t,
      ),
    }));
    pump(set, getState);
  },

  clearFinished: () =>
    set((s) => {
      for (const t of s.tasks) {
        if (t.status !== 'queued' && t.status !== 'running') runners.delete(t.id);
      }
      return {
        tasks: s.tasks.filter((t) => t.status === 'queued' || t.status === 'running'),
      };
    }),

  _patch: (id, patch) =>
    set((s) => ({ tasks: s.tasks.map((t) => (t.id === id ? { ...t, ...patch } : t)) })),
}));

function pump(
  set: (fn: (s: TasksState) => Partial<TasksState>) => void,
  getState: () => TasksState,
) {
  const { tasks, _patch } = getState();
  const running = tasks.filter((t) => t.status === 'running').length;
  if (running >= CONCURRENCY) return;
  const next = tasks.find((t) => t.status === 'queued' && runners.has(t.id));
  if (!next) return;

  const run = runners.get(next.id)!;
  const ctrl = new AbortController();
  controllers.set(next.id, ctrl);
  _patch(next.id, { status: 'running' });

  void run({ ...next }, ctrl.signal)
    .then(() => {
      const cur = getState().tasks.find((t) => t.id === next.id);
      if (cur?.status === 'running') {
        _patch(next.id, {
          status: 'done',
          doneBytes: cur.totalBytes,
          uploadedBytes: cur.totalBytes,
        });
      }
      runners.delete(next.id);
    })
    .catch((e: unknown) => {
      const cur = getState().tasks.find((t) => t.id === next.id);
      if (cur?.status !== 'canceled') {
        // 保留 runner —— 失败任务可通过 retry() 重新排队执行
        _patch(next.id, { status: 'error', error: e instanceof Error ? e.message : String(e) });
      }
    })
    .finally(() => {
      controllers.delete(next.id);
      pump(set, getState);
    });

  // 尝试并行填满
  pump(set, getState);
}

export function taskProgress(id: string, done: number) {
  useTasks.getState()._patch(id, { doneBytes: done });
}

/** 上传远端维度：存储端已确认接收的字节（轮询服务端得来）。 */
export function taskUploaded(id: string, uploaded: number) {
  useTasks.getState()._patch(id, { uploadedBytes: uploaded });
}
