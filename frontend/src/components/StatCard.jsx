import React from 'react';

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'indigo', badge }) {
  const colorMap = {
    indigo: {
      border: 'hover:border-indigo-500/50',
      glow: 'group-hover:shadow-[0_0_25px_-5px_rgba(99,102,241,0.3)]',
      iconBg: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20',
      badgeBg: 'bg-indigo-500/20 text-indigo-300',
    },
    cyan: {
      border: 'hover:border-cyan-500/50',
      glow: 'group-hover:shadow-[0_0_25px_-5px_rgba(56,189,248,0.3)]',
      iconBg: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      badgeBg: 'bg-cyan-500/20 text-cyan-300',
    },
    emerald: {
      border: 'hover:border-emerald-500/50',
      glow: 'group-hover:shadow-[0_0_25px_-5px_rgba(16,185,129,0.3)]',
      iconBg: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
      badgeBg: 'bg-emerald-500/20 text-emerald-300',
    },
    rose: {
      border: 'hover:border-rose-500/50',
      glow: 'group-hover:shadow-[0_0_25px_-5px_rgba(244,63,94,0.3)]',
      iconBg: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
      badgeBg: 'bg-rose-500/20 text-rose-300',
    },
    amber: {
      border: 'hover:border-amber-500/50',
      glow: 'group-hover:shadow-[0_0_25px_-5px_rgba(245,158,11,0.3)]',
      iconBg: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      badgeBg: 'bg-amber-500/20 text-amber-300',
    },
  };

  const scheme = colorMap[color] || colorMap.indigo;

  return (
    <div
      className={`glass-panel p-5 relative overflow-hidden group cursor-pointer transition-all duration-300 ${scheme.border} ${scheme.glow}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-[var(--text-subtle)]">
            {title}
          </p>
          <h3 className="text-3xl font-extrabold font-heading text-white mt-1.5 tracking-tight">
            {value}
          </h3>
          {subtitle && (
            <p className="text-xs text-[var(--text-muted)] mt-1 flex items-center gap-1.5">
              {subtitle}
            </p>
          )}
        </div>
        <div className={`p-3 rounded-xl border ${scheme.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {badge && (
        <div className="mt-4 pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-md ${scheme.badgeBg}`}>
            {badge}
          </span>
          <span className="text-[11px] text-[var(--text-subtle)] font-mono">Live telemetry</span>
        </div>
      )}
    </div>
  );
}
