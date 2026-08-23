import React, { useState, useEffect, useRef } from 'react';
import {
  Terminal,
  Trash2,
  Pause,
  Play,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Cpu,
  ArrowDownCircle,
} from 'lucide-react';

export default function LiveLogTerminal() {
  const [logs, setLogs] = useState([]);
  const [filter, setFilter] = useState('ALL');
  const [isPaused, setIsPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const logContainerRef = useRef(null);

  // Initial synthetic logs
  useEffect(() => {
    const initialLogs = [
      {
        id: '1',
        time: new Date().toLocaleTimeString(),
        source: 'AST_ENGINE',
        level: 'INFO',
        message: 'Tree-sitter multi-language AST parser initialized (Python & JS grammars ready).',
      },
      {
        id: '2',
        time: new Date().toLocaleTimeString(),
        source: 'SANDBOX',
        level: 'INFO',
        message: 'Docker ephemeral container security profile loaded (ReadOnly, CapDrop:ALL, NoNet).',
      },
      {
        id: '3',
        time: new Date().toLocaleTimeString(),
        source: 'OLLAMA_LLM',
        level: 'INFO',
        message: 'Model discovered: qwen2.5-coder:1.5b (Delimiters active, JSON schema enforced).',
      },
      {
        id: '4',
        time: new Date().toLocaleTimeString(),
        source: 'CELERY_WORKER',
        level: 'INFO',
        message: 'Celery worker connected to Redis broker (3 queues: scans, verification, remediation).',
      },
    ];
    setLogs(initialLogs);
  }, []);

  // Connect to SSE stream
  useEffect(() => {
    let eventSource = null;
    try {
      eventSource = new EventSource('/api/v1/stream/live');
      eventSource.onmessage = (event) => {
        if (isPaused) return;
        try {
          const parsed = JSON.parse(event.data);
          const newLog = {
            id: String(Date.now() + Math.random()),
            time: new Date().toLocaleTimeString(),
            source: parsed.data?.source || 'PIPELINE',
            level: parsed.data?.level || 'INFO',
            message: parsed.data?.message || JSON.stringify(parsed.data),
          };
          setLogs((prev) => [...prev.slice(-200), newLog]);
        } catch {
          // ignore parsing error
        }
      };
    } catch {
      // SSE not available
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, [isPaused]);

  // Autoscroll
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const filteredLogs = logs.filter((log) => {
    if (filter === 'ALL') return true;
    return log.source.toUpperCase().includes(filter.toUpperCase());
  });

  const getSourceColor = (source) => {
    switch (source?.toUpperCase()) {
      case 'AST_ENGINE':
        return 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20';
      case 'SANDBOX':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20';
      case 'OLLAMA_LLM':
        return 'text-purple-400 bg-purple-500/10 border-purple-500/20';
      case 'CELERY_WORKER':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20';
      case 'GITHUB':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/20';
      default:
        return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
    }
  };

  return (
    <div className="glass-panel overflow-hidden border border-indigo-500/30 shadow-2xl flex flex-col h-[520px]">
      {/* Terminal Toolbar */}
      <div className="p-3.5 border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)]/80 flex items-center justify-between gap-3">
        {/* Terminal Title & Window Dots */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-amber-500/80 inline-block" />
            <span className="w-3 h-3 rounded-full bg-emerald-500/80 inline-block" />
          </div>

          <div className="flex items-center gap-2 pl-2 border-l border-[var(--border-subtle)]">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <span className="font-heading font-bold text-xs text-white">
              Live Pipeline Stream
            </span>
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span>{isPaused ? 'PAUSED' : 'STREAMING'}</span>
            </div>
          </div>
        </div>

        {/* Filter Buttons */}
        <div className="hidden md:flex items-center gap-1.5">
          {['ALL', 'AST', 'SANDBOX', 'OLLAMA', 'CELERY'].map((cat) => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-2.5 py-1 rounded-md text-[10px] font-mono font-bold transition-all ${
                filter === cat
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'bg-[var(--bg-primary)]/80 text-[var(--text-subtle)] hover:text-white border border-[var(--border-subtle)]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setIsPaused(!isPaused)}
            className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-white hover:bg-white/5 transition-colors"
            title={isPaused ? 'Resume Stream' : 'Pause Stream'}
          >
            {isPaused ? <Play className="w-4 h-4 text-emerald-400" /> : <Pause className="w-4 h-4" />}
          </button>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded-lg transition-colors ${
              autoScroll ? 'text-cyan-400 bg-cyan-500/10' : 'text-[var(--text-muted)] hover:bg-white/5'
            }`}
            title="Toggle Autoscroll"
          >
            <ArrowDownCircle className="w-4 h-4" />
          </button>

          <button
            onClick={() => setLogs([])}
            className="p-1.5 rounded-lg text-[var(--text-muted)] hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
            title="Clear Logs"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Log Output Window */}
      <div
        ref={logContainerRef}
        className="flex-1 bg-[#05070c] p-4 overflow-y-auto font-mono text-xs space-y-1.5 select-text"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-[var(--text-subtle)] py-12 text-center">
            No pipeline log events to display.
          </div>
        ) : (
          filteredLogs.map((log) => (
            <div
              key={log.id}
              className="flex items-start gap-3 py-1 px-2 rounded hover:bg-white/[0.03] transition-colors leading-relaxed"
            >
              <span className="text-[var(--text-subtle)] select-none text-[11px] shrink-0">
                [{log.time}]
              </span>

              <span
                className={`px-1.5 py-0.5 rounded text-[10px] font-bold border uppercase shrink-0 ${getSourceColor(
                  log.source
                )}`}
              >
                {log.source}
              </span>

              <span className="text-slate-200 flex-1 break-all">{log.message}</span>
            </div>
          ))
        )}
      </div>

      {/* Terminal Footer */}
      <div className="p-2 border-t border-[var(--border-subtle)] bg-[var(--bg-secondary)]/50 text-[10px] font-mono text-[var(--text-subtle)] flex items-center justify-between px-4">
        <span>SSE Stream Endpoint: /api/v1/stream/live</span>
        <span>Events buffered: {filteredLogs.length}</span>
      </div>
    </div>
  );
}
