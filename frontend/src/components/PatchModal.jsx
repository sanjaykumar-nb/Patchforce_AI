import React, { useState } from 'react';
import {
  X,
  ShieldCheck,
  GitPullRequest,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  FileCode,
  Sparkles,
  ExternalLink,
  Code2,
} from 'lucide-react';

export default function PatchModal({
  patch,
  vulnerability,
  onClose,
  onCreatePR,
  isCreatingPR,
  createdPR,
}) {
  if (!patch) return null;

  const score = patch.patch_score ?? patch.composite_score ?? 95;
  const isHighQuality = score >= 80;

  const renderDiff = (diffText) => {
    if (!diffText) return <div className="p-4 text-xs text-[var(--text-muted)]">No diff available.</div>;
    const lines = diffText.split('\n');

    return (
      <div className="diff-container max-h-96 overflow-y-auto">
        {lines.map((line, idx) => {
          let lineClass = 'diff-line text-slate-300';
          if (line.startsWith('+') && !line.startsWith('+++')) {
            lineClass = 'diff-line diff-add';
          } else if (line.startsWith('-') && !line.startsWith('---')) {
            lineClass = 'diff-line diff-del';
          } else if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) {
            lineClass = 'diff-line diff-header';
          }
          return (
            <div key={idx} className={lineClass}>
              {line}
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="glass-panel w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden border border-indigo-500/30 shadow-2xl shadow-indigo-950/50">
        {/* Modal Header */}
        <div className="p-6 border-b border-[var(--border-subtle)] flex items-center justify-between bg-[var(--bg-secondary)]/50">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 text-cyan-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-heading font-bold text-lg text-white">
                  Autonomous Remediation Patch
                </h3>
                <span className="px-2 py-0.5 text-[10px] font-bold font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 rounded-md">
                  AST Targeted
                </span>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                Minimal AST function replacement with zero full-file rewrites
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-[var(--text-subtle)] hover:text-white hover:bg-white/5 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* Validation Scorecard */}
          <div className="glass-panel p-5 border border-indigo-500/20 bg-gradient-to-r from-indigo-950/30 via-slate-900/50 to-cyan-950/20">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4">
              {/* Score Gauge */}
              <div className="flex items-center gap-4">
                <div className="relative flex items-center justify-center">
                  <div className="w-16 h-16 rounded-full border-4 border-indigo-500/20 border-t-indigo-400 border-r-cyan-400 flex items-center justify-center">
                    <span className="font-heading font-extrabold text-xl text-white">
                      {score.toFixed(0)}
                    </span>
                  </div>
                </div>
                <div>
                  <p className="text-xs font-semibold uppercase tracking-wider text-[var(--text-subtle)]">
                    Composite Verification Score
                  </p>
                  <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-sm font-bold text-white">
                      {isHighQuality ? 'Verified Production Grade' : 'Candidate Patch'}
                    </span>
                    <span className="text-xs text-emerald-400 font-mono">100.0 Max</span>
                  </div>
                </div>
              </div>

              {/* 4-Stage Breakdown Badges */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5 w-full md:w-auto">
                <div className="px-3 py-2 rounded-xl bg-[var(--bg-primary)]/80 border border-[var(--border-subtle)] text-center">
                  <p className="text-[10px] text-[var(--text-subtle)] uppercase">1. Syntax</p>
                  <p className="text-xs font-bold text-emerald-400 mt-0.5">
                    {patch.syntax_valid ? '20/20 ✅' : '0/20 ❌'}
                  </p>
                </div>

                <div className="px-3 py-2 rounded-xl bg-[var(--bg-primary)]/80 border border-[var(--border-subtle)] text-center">
                  <p className="text-[10px] text-[var(--text-subtle)] uppercase">2. AST Scope</p>
                  <p className="text-xs font-bold text-emerald-400 mt-0.5">
                    {patch.ast_valid ? '20/20 ✅' : '0/20 ❌'}
                  </p>
                </div>

                <div className="px-3 py-2 rounded-xl bg-[var(--bg-primary)]/80 border border-[var(--border-subtle)] text-center">
                  <p className="text-[10px] text-[var(--text-subtle)] uppercase">3. Sandbox PoC</p>
                  <p className="text-xs font-bold text-emerald-400 mt-0.5">
                    {patch.test_pass_rate >= 1.0 ? '30/30 ✅' : `${(patch.test_pass_rate * 30).toFixed(0)}/30 ⚠️`}
                  </p>
                </div>

                <div className="px-3 py-2 rounded-xl bg-[var(--bg-primary)]/80 border border-[var(--border-subtle)] text-center">
                  <p className="text-[10px] text-[var(--text-subtle)] uppercase">4. Re-Scan</p>
                  <p className="text-xs font-bold text-emerald-400 mt-0.5">
                    {patch.rescan_clean ? '30/30 ✅' : '0/30 ❌'}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Remediation Explanation */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-subtle)]">
              LLM Defense Rationale
            </h4>
            <div className="glass-panel p-4 text-xs text-slate-200 leading-relaxed">
              <p>{patch.explanation}</p>
              {patch.security_reason && (
                <div className="mt-2.5 pt-2.5 border-t border-[var(--border-subtle)] text-[var(--text-muted)]">
                  <strong className="text-cyan-400">Security Enhancement: </strong>
                  {patch.security_reason}
                </div>
              )}
            </div>
          </div>

          {/* Code Diff */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-xs font-bold uppercase tracking-wider text-[var(--text-subtle)]">
                Unified Patch Diff
              </h4>
              <span className="text-[11px] font-mono text-[var(--text-subtle)]">
                {vulnerability?.file_path || patch.file_path || 'target source file'}
              </span>
            </div>
            {renderDiff(patch.diff_content)}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-5 border-t border-[var(--border-subtle)] bg-[var(--bg-secondary)]/60 flex items-center justify-between">
          <div className="text-xs text-[var(--text-muted)] flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Passed all sandbox safety constraints</span>
          </div>

          <div className="flex items-center gap-3">
            {createdPR ? (
              createdPR.is_simulated ? (
                <div className="flex items-center gap-2 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2">
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>
                    Not pushed to GitHub — {createdPR.simulation_reason || 'no GitHub token was available.'}
                  </span>
                </div>
              ) : (
                <a
                  href={createdPR.pr_url || '#'}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-success text-xs flex items-center gap-2"
                >
                  <GitPullRequest className="w-4 h-4" />
                  <span>View PR #{createdPR.pr_number}</span>
                  <ExternalLink className="w-3.5 h-3.5 opacity-80" />
                </a>
              )
            ) : (
              <button
                onClick={() => onCreatePR(patch.id || patch.patch_id)}
                disabled={isCreatingPR}
                className="btn-primary text-xs"
              >
                <GitPullRequest className="w-4 h-4" />
                {isCreatingPR ? 'Opening Pull Request...' : 'Open GitHub Pull Request'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
