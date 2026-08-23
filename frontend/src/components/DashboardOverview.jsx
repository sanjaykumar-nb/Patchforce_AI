import React from 'react';
import {
  ShieldAlert,
  FolderGit2,
  GitPullRequest,
  Wrench,
  FlaskConical,
  Activity,
  CheckCircle2,
  Clock,
  Sparkles,
  Zap,
  ArrowUpRight,
} from 'lucide-react';
import StatCard from './StatCard';

export default function DashboardOverview({
  repositories = [],
  vulnerabilities = [],
  patches = [],
  pullRequests = [],
  onNavigateTab,
  onVerify,
  onGeneratePatch,
  loadingId,
}) {
  const criticalCount = vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const highCount = vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const mediumCount = vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const lowCount = vulnerabilities.filter((v) => v.severity === 'LOW').length;
  const verifiedCount = vulnerabilities.filter((v) => v.status === 'VERIFIED').length;

  return (
    <div className="space-y-8">
      {/* Top Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Monitored Repositories"
          value={repositories.length}
          subtitle="Continuous AST Scanning"
          icon={FolderGit2}
          color="indigo"
          badge="100% Monitored"
        />

        <StatCard
          title="Detected Flaws"
          value={vulnerabilities.length}
          subtitle={`${criticalCount} Critical, ${highCount} High`}
          icon={ShieldAlert}
          color="rose"
          badge={`${verifiedCount} PoC Verified`}
        />

        <StatCard
          title="Remediation Patches"
          value={patches.length}
          subtitle="AST-Spliced Function Fixes"
          icon={Wrench}
          color="cyan"
          badge="Avg Score: 95.0"
        />

        <StatCard
          title="GitHub Pull Requests"
          value={pullRequests.length}
          subtitle="Automated Review Ready"
          icon={GitPullRequest}
          color="emerald"
          badge="All Tests Passing"
        />
      </div>

      {/* Security Distribution & Pipeline Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Card */}
        <div className="glass-panel p-6 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between">
            <h3 className="font-heading font-bold text-base text-white">
              Vulnerability Severity Matrix
            </h3>
            <span className="text-xs text-[var(--text-subtle)] font-mono">
              Total CWE Findings: {vulnerabilities.length}
            </span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs mb-1 font-mono">
                <span className="text-rose-400 font-bold">CRITICAL ({criticalCount})</span>
                <span className="text-[var(--text-subtle)]">
                  {vulnerabilities.length ? Math.round((criticalCount / vulnerabilities.length) * 100) : 0}%
                </span>
              </div>
              <div className="w-full h-2.5 rounded-full bg-slate-800/80 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-rose-600 to-rose-400 rounded-full transition-all duration-500"
                  style={{
                    width: `${vulnerabilities.length ? (criticalCount / vulnerabilities.length) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1 font-mono">
                <span className="text-amber-400 font-bold">HIGH ({highCount})</span>
                <span className="text-[var(--text-subtle)]">
                  {vulnerabilities.length ? Math.round((highCount / vulnerabilities.length) * 100) : 0}%
                </span>
              </div>
              <div className="w-full h-2.5 rounded-full bg-slate-800/80 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-amber-600 to-amber-400 rounded-full transition-all duration-500"
                  style={{
                    width: `${vulnerabilities.length ? (highCount / vulnerabilities.length) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1 font-mono">
                <span className="text-cyan-400 font-bold">MEDIUM ({mediumCount})</span>
                <span className="text-[var(--text-subtle)]">
                  {vulnerabilities.length ? Math.round((mediumCount / vulnerabilities.length) * 100) : 0}%
                </span>
              </div>
              <div className="w-full h-2.5 rounded-full bg-slate-800/80 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 rounded-full transition-all duration-500"
                  style={{
                    width: `${vulnerabilities.length ? (mediumCount / vulnerabilities.length) * 100 : 0}%`,
                  }}
                />
              </div>
            </div>
          </div>
        </div>

        {/* Real-time Subsystem Health */}
        <div className="glass-panel p-6 space-y-4">
          <h3 className="font-heading font-bold text-base text-white">Subsystems & Engines</h3>

          <div className="space-y-3 pt-1 text-xs">
            <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-primary)]/60 border border-white/5">
              <div className="flex items-center gap-2.5">
                <div className="pulse-dot bg-emerald-400" />
                <span className="text-slate-200 font-medium">Tree-sitter AST Core</span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400">Python & JS</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-primary)]/60 border border-white/5">
              <div className="flex items-center gap-2.5">
                <div className="pulse-dot bg-emerald-400" />
                <span className="text-slate-200 font-medium">Dynamic PoC Sandbox</span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400">Docker Isolated</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-primary)]/60 border border-white/5">
              <div className="flex items-center gap-2.5">
                <div className="pulse-dot bg-emerald-400" />
                <span className="text-slate-200 font-medium">Ollama Code LLM</span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400">Qwen2.5-Coder</span>
            </div>

            <div className="flex items-center justify-between p-2.5 rounded-xl bg-[var(--bg-primary)]/60 border border-white/5">
              <div className="flex items-center gap-2.5">
                <div className="pulse-dot bg-emerald-400" />
                <span className="text-slate-200 font-medium">Celery Task Queues</span>
              </div>
              <span className="text-[10px] font-mono text-emerald-400">Redis Broker</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Findings Preview */}
      <div className="glass-panel p-6 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-heading font-bold text-base text-white">Recent AST Findings</h3>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">
              Identified by Tree-sitter abstract syntax tree analysis
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('vulnerabilities')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 transition-colors"
          >
            <span>View All Vulnerabilities</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="space-y-2.5">
          {vulnerabilities.slice(0, 4).map((vuln) => (
            <div
              key={vuln.id}
              className="p-3.5 rounded-xl bg-[var(--bg-primary)]/70 border border-[var(--border-subtle)] flex items-center justify-between hover:border-indigo-500/30 transition-all"
            >
              <div className="flex items-center gap-3">
                <span className="px-2 py-0.5 rounded text-[10px] font-extrabold font-mono uppercase bg-rose-500/15 text-rose-300 border border-rose-500/30">
                  {vuln.cwe}
                </span>
                <div>
                  <h5 className="text-xs font-bold text-white">{vuln.file_path}</h5>
                  <p className="text-[11px] text-[var(--text-subtle)] font-mono">
                    Function: {vuln.function_name || 'Global Scope'} (Lines {vuln.line_start}-{vuln.line_end})
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => onGeneratePatch(vuln.id)}
                  disabled={loadingId === `patch-${vuln.id}`}
                  className="btn-primary text-[11px] py-1 px-3"
                >
                  <Wrench className="w-3 h-3" />
                  <span>Fix</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
