import React from 'react';
import { GitPullRequest, GitBranch, ExternalLink, Clock, CheckCircle2 } from 'lucide-react';

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
              className="glass-panel p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 hover:border-indigo-500/40 transition-all"
            >
              <div className="flex items-start gap-3.5">
                <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 mt-0.5">
                  <GitPullRequest className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-emerald-400">
                      #{pr.pr_number || '1'}
                    </span>
                    <h4 className="font-bold text-sm text-white">{pr.title}</h4>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-bold font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      {pr.status}
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

              <a
                href={pr.pr_url}
                target="_blank"
                rel="noreferrer"
                className="btn-primary text-xs shrink-0"
              >
                <span>Review on GitHub</span>
                <ExternalLink className="w-3.5 h-3.5 opacity-80" />
              </a>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
