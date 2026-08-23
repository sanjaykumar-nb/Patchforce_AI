import React, { useState } from 'react';
import {
  FolderGit2,
  Plus,
  Play,
  CheckCircle2,
  Clock,
  Code2,
  Copy,
  ExternalLink,
  Radio,
  Webhook,
  Trash2,
} from 'lucide-react';

export default function RepositoriesView({
  repositories = [],
  onTriggerScan,
  onCreateRepository,
  onDeleteRepository,
  isScanningRepo,
}) {
  const [showAddModal, setShowAddModal] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    full_name: '',
    url: '',
    clone_url: '',
    language: 'python',
  });
  const [copiedWebhook, setCopiedWebhook] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!formData.full_name) return;
    onCreateRepository({
      ...formData,
      name: formData.name || formData.full_name.split('/')[1] || formData.full_name,
      url: formData.url || `https://github.com/${formData.full_name}`,
      clone_url: formData.clone_url || `https://github.com/${formData.full_name}.git`,
    });
    setShowAddModal(false);
    setFormData({ name: '', full_name: '', url: '', clone_url: '', language: 'python' });
  };

  const copyWebhookUrl = () => {
    navigator.clipboard.writeText('http://localhost:8000/api/v1/webhooks/github');
    setCopiedWebhook(true);
    setTimeout(() => setCopiedWebhook(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header & Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="font-heading font-bold text-xl text-white">Connected Repositories</h2>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            Target codebases monitored by PatchForge AI for continuous AST static analysis.
          </p>
        </div>

        <button onClick={() => setShowAddModal(true)} className="btn-primary text-xs">
          <Plus className="w-4 h-4" />
          <span>Connect Repository</span>
        </button>
      </div>

      {/* Webhook Configuration Info Banner */}
      <div className="glass-panel p-5 border border-indigo-500/20 bg-gradient-to-r from-indigo-950/40 to-slate-900/60 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="p-3 rounded-xl bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
            <Webhook className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-white">Cryptographic Push Webhook</h4>
            <p className="text-xs text-[var(--text-muted)] mt-0.5 font-mono">
              http://localhost:8000/api/v1/webhooks/github
            </p>
          </div>
        </div>

        <button onClick={copyWebhookUrl} className="btn-secondary text-xs">
          <Copy className="w-3.5 h-3.5" />
          <span>{copiedWebhook ? 'Copied!' : 'Copy Webhook URL'}</span>
        </button>
      </div>

      {/* Repositories List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {repositories.length === 0 ? (
          <div className="glass-panel p-12 text-center text-[var(--text-muted)] col-span-2">
            <FolderGit2 className="w-10 h-10 text-[var(--text-subtle)] mx-auto mb-3 opacity-50" />
            <p className="text-sm font-medium">No repositories registered yet.</p>
            <p className="text-xs text-[var(--text-subtle)] mt-1">
              Click "Connect Repository" above to add your first project.
            </p>
          </div>
        ) : (
          repositories.map((repo) => {
            const isScanning = isScanningRepo === repo.id;

            return (
              <div
                key={repo.id}
                className="glass-panel p-5 space-y-4 hover:border-indigo-500/40 transition-all group"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-slate-800/80 border border-white/5 text-cyan-400">
                      <FolderGit2 className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="font-heading font-bold text-sm text-white group-hover:text-cyan-400 transition-colors">
                        {repo.full_name}
                      </h4>
                      <div className="flex items-center gap-2 mt-1 text-[11px] text-[var(--text-subtle)] font-mono">
                        <span className="capitalize">{repo.language}</span>
                        <span>•</span>
                        <span>Branch: {repo.default_branch || 'main'}</span>
                      </div>
                    </div>
                  </div>

                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    Active
                  </span>
                </div>

                <div className="pt-3 border-t border-[var(--border-subtle)] flex items-center justify-between">
                  <a
                    href={repo.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-xs text-[var(--text-muted)] hover:text-cyan-400 flex items-center gap-1.5 transition-colors font-mono"
                  >
                    <span>GitHub Repo</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>

                  <div className="flex items-center gap-2">
                    {onDeleteRepository && (
                      <button
                        onClick={() => onDeleteRepository(repo.id)}
                        className="p-1.5 rounded-lg border border-red-500/20 text-red-400 hover:bg-red-500/10 transition-colors"
                        title="Delete Repository"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                    <button
                      onClick={() => onTriggerScan(repo.id)}
                      disabled={isScanning}
                      className="btn-primary text-xs py-1.5 px-3"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>{isScanning ? 'Scanning AST...' : 'Scan Now'}</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Add Repository Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="glass-panel w-full max-w-md p-6 space-y-5 border border-indigo-500/30">
            <h3 className="font-heading font-bold text-lg text-white">Connect Git Repository</h3>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-[var(--text-subtle)] uppercase mb-1.5">
                  Full Repository Name
                </label>
                <input
                  type="text"
                  placeholder="e.g. acme-corp/payment-service"
                  value={formData.full_name}
                  onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
                  required
                  className="w-full bg-[var(--bg-primary)] border border-[var(--border-subtle)] rounded-xl px-3.5 py-2 text-xs text-white placeholder-[var(--text-subtle)] focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-[var(--text-subtle)] uppercase mb-1.5">
                  Primary Language
                </label>
                <select
                  value={formData.language}
                  onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                  className="w-full bg-[var(--bg-primary)] border border-[var(--border-subtle)] rounded-xl px-3.5 py-2 text-xs text-white focus:outline-none focus:border-indigo-500"
                >
                  <option value="python">Python (Tree-sitter AST)</option>
                  <option value="javascript">JavaScript (Tree-sitter AST)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-3 pt-3 border-t border-[var(--border-subtle)]">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="btn-secondary text-xs"
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary text-xs">
                  Save Repository
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
