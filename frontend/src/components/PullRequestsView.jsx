import React from 'react';
import { GitPullRequest, GitBranch, ExternalLink, Clock, CheckCircle2, AlertTriangle } from 'lucide-react';

export default function PullRequestsView({ pullRequests = [] }) {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-heading font-bold text-xl text-white">Automated Pull Requests</h2>
        <p className="text-xs text-[var(--text-muted)] mt-1">
          Review and audit automated remediation PRs opened on GitHub with complete verification scorecards.
        </p>
      </div>

      <div className="space-y-3">
        {pullRequests.length === 0 ? (
          <div className="glass-panel p-12 text-center text-[var(--text-muted)]">
            <GitPullRequest className="w-10 h-10 text-[var(--text-subtle)] mx-auto mb-3 opacity-50" />
            <p className="text-sm font-medium">No pull requests opened yet.</p>
            <p className="text-xs text-[var(--text-subtle)] mt-1">
              Generate and validate patches from the Vulnerabilities tab to open pull requests.
            </p>
          </div>
        ) : (
          pullRequests.map((pr) => (
            <div
              key={pr.id}
              className={`glass-panel p-5 flex flex-col gap-3 transition-all ${
                pr.is_simulated
                  ? 'border-amber-500/30 hover:border-amber-500/50'
                  : 'hover:border-indigo-500/40'
              }`}
            >
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div className="flex items-start gap-3.5">
                  <div
                    className={`p-3 rounded-xl border mt-0.5 ${
                      pr.is_simulated
                        ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                        : 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                    }`}
                  >
                    {pr.is_simulated ? <AlertTriangle className="w-5 h-5" /> : <GitPullRequest className="w-5 h-5" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`font-mono font-bold ${pr.is_simulated ? 'text-amber-400' : 'text-emerald-400'}`}>
                        #{pr.pr_number || '1'}
                      </span>
                      <h4 className="font-bold text-sm text-white">{pr.title}</h4>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono border ${
                          pr.is_simulated
                            ? 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        }`}
                      >
                        {pr.is_simulated ? 'NOT PUSHED TO GITHUB' : pr.status}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 mt-2 text-[11px] text-[var(--text-subtle)] font-mono">
                      <div className="flex items-center gap-1 text-slate-300">
                        <GitBranch className="w-3.5 h-3.5 text-indigo-400" />
                        <span>{pr.branch_name}</span>
                      </div>
                      <span>•</span>
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        <span>{new Date(pr.created_at).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {pr.is_simulated ? (
                  <span className="text-xs text-amber-300/80 shrink-0 italic">No real PR exists</span>
                ) : (
                  <a
                    href={pr.pr_url}
                    target="_blank"
                    rel="noreferrer"
                    className="btn-primary text-xs shrink-0"
                  >
                    <span>Review on GitHub</span>
                    <ExternalLink className="w-3.5 h-3.5 opacity-80" />
                  </a>
                )}
              </div>

              {pr.is_simulated && (
                <div className="flex items-start gap-2 text-xs text-amber-200/90 bg-amber-500/5 border border-amber-500/20 rounded-lg px-3 py-2.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                  <span>
                    <strong>Simulated only.</strong> This diff was generated and validated, but was never pushed
                    to GitHub.{' '}
                    {pr.simulation_reason || 'No GitHub token was available to push it.'}
                  </span>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
