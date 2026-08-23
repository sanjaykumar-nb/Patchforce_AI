import React from 'react';
import {
  ShieldAlert,
  Activity,
  GitPullRequest,
  FolderGit2,
  Cpu,
  CheckCircle2,
  Github,
  KeyRound,
  LogOut,
  User as UserIcon,
} from 'lucide-react';

export default function Navbar({
  activeTab,
  setActiveTab,
  currentUser,
  onOpenAuthModal,
  onLogout,
}) {
  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Activity },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'repositories', label: 'Repositories', icon: FolderGit2 },
    { id: 'pull_requests', label: 'Pull Requests', icon: GitPullRequest },
    { id: 'logs', label: 'Live Logs', icon: Cpu },
  ];

  return (
    <header className="border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)]/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-indigo-500 to-cyan-400 p-0.5 shadow-lg shadow-indigo-500/20">
            <div className="w-full h-full bg-[var(--bg-primary)] rounded-[10px] flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-heading font-extrabold text-xl tracking-tight text-white">
                PatchForge<span className="text-cyan-400">.AI</span>
              </span>
              <span className="px-2 py-0.5 text-[10px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 rounded-full font-mono">
                v1.0
              </span>
            </div>
            <p className="text-[11px] text-[var(--text-subtle)] -mt-0.5">AST Autonomous Remediation</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 bg-[var(--bg-primary)]/60 p-1 rounded-xl border border-[var(--border-subtle)]">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all duration-200 ${
                  isActive
                    ? 'bg-indigo-600/90 text-white shadow-md shadow-indigo-600/30 border border-indigo-400/30'
                    : 'text-[var(--text-muted)] hover:text-white hover:bg-white/5'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Right Section: Auth & Engine Status */}
        <div className="flex items-center gap-3">
          {currentUser ? (
            <div className="flex items-center gap-3 bg-slate-900/80 px-3 py-1.5 rounded-xl border border-white/10">
              {currentUser.github_avatar_url ? (
                <img
                  src={currentUser.github_avatar_url}
                  alt={currentUser.github_username || 'User'}
                  className="w-7 h-7 rounded-full border border-cyan-400/40"
                />
              ) : (
                <div className="w-7 h-7 rounded-full bg-indigo-600/40 border border-indigo-400/30 flex items-center justify-center text-cyan-300">
                  <UserIcon className="w-3.5 h-3.5" />
                </div>
              )}

              <div className="text-left">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-bold text-white font-mono">
                    {currentUser.github_username || currentUser.full_name || currentUser.email.split('@')[0]}
                  </span>
                  {currentUser.github_username && (
                    <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono">
                      GitHub
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1.5">
                  <p className="text-[10px] text-slate-400 font-mono capitalize">{currentUser.role || 'Developer'}</p>
                  {currentUser.organization?.name && (
                    <>
                      <span className="text-[9px] text-slate-600">·</span>
                      <span className="text-[10px] text-indigo-300 font-mono truncate max-w-[110px]" title={currentUser.organization.name}>
                        {currentUser.organization.name}
                      </span>
                    </>
                  )}
                </div>
              </div>

              <button
                onClick={onLogout}
                title="Log Out"
                className="p-1 text-slate-400 hover:text-rose-400 transition-colors ml-1"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={onOpenAuthModal}
              className="btn-primary text-xs py-2 px-3.5 font-bold shadow-lg shadow-indigo-600/20"
            >
              <Github className="w-3.5 h-3.5" />
              <span>Connect GitHub</span>
            </button>
          )}

          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
            <span>Ready</span>
          </div>
        </div>
      </div>
    </header>
  );
}
