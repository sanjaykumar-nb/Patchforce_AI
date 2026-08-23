import React, { useState } from 'react';
import {
  X,
  Github,
  KeyRound,
  Mail,
  ShieldCheck,
  Sparkles,
  Lock,
  ArrowRight,
  CheckCircle2,
  AlertCircle,
  HelpCircle,
  ExternalLink,
} from 'lucide-react';
import { loginWithGitHub, sendOTP, verifyOTP, loginWithPassword, registerWithPassword } from '../api';

export default function AuthModal({ isOpen, onClose, onAuthSuccess }) {
  if (!isOpen) return null;

  const [activeTab, setActiveTab] = useState('github'); // 'github' | 'otp' | 'password'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // GitHub Token State
  const [githubToken, setGithubToken] = useState('');
  const [githubOrgName, setGithubOrgName] = useState('');

  // OTP State
  const [otpEmail, setOtpEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpSent, setOtpSent] = useState(false);
  const [demoOtp, setDemoOtp] = useState(null);
  const [otpOrgName, setOtpOrgName] = useState('');

  // Password State
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [orgName, setOrgName] = useState('');

  // 1. GitHub Token Handler
  const handleGitHubLogin = async (e) => {
    e.preventDefault();
    if (!githubToken.trim()) {
      setError('Please paste your GitHub Personal Access Token.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await loginWithGitHub(githubToken.trim(), githubOrgName.trim());
      localStorage.setItem('patchforge_token', res.data.access_token);
      localStorage.setItem('patchforge_user', JSON.stringify(res.data.user));
      onAuthSuccess(res.data.user, res.data.access_token);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to authenticate GitHub token.');
    } finally {
      setLoading(false);
    }
  };

  // 2. OTP Send Handler
  const handleSendOTP = async (e) => {
    e.preventDefault();
    if (!otpEmail.trim()) {
      setError('Please enter a valid email address.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await sendOTP(otpEmail.trim(), otpOrgName.trim());
      setOtpSent(true);
      setDemoOtp(res.data.demo_otp);
      setSuccessMsg(`6-Digit OTP code sent to ${otpEmail}!`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to send OTP code.');
    } finally {
      setLoading(false);
    }
  };

  // 3. OTP Verify Handler
  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    if (!otpCode.trim() || otpCode.length !== 6) {
      setError('Please enter the 6-digit verification OTP code.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await verifyOTP(otpEmail.trim(), otpCode.trim());
      localStorage.setItem('patchforge_token', res.data.access_token);
      localStorage.setItem('patchforge_user', JSON.stringify(res.data.user));
      onAuthSuccess(res.data.user, res.data.access_token);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Invalid or expired OTP code.');
    } finally {
      setLoading(false);
    }
  };

  // 4. Password Login / Register Handler
  const handlePasswordAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      if (isRegister) {
        await registerWithPassword(email.trim(), password, fullName, orgName.trim());
      }
      const res = await loginWithPassword(email.trim(), password);
      localStorage.setItem('patchforge_token', res.data.access_token);
      localStorage.setItem('patchforge_user', JSON.stringify(res.data.user));
      onAuthSuccess(res.data.user, res.data.access_token);
      onClose();
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
      <div className="glass-panel w-full max-w-md p-6 space-y-5 border border-indigo-500/30 shadow-2xl shadow-indigo-950/50">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-[var(--border-subtle)]">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-heading font-bold text-lg text-white">PatchForge AI Access</h3>
              <p className="text-xs text-[var(--text-muted)]">Secure Identity & GitHub PR Authorization</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-[var(--text-subtle)] hover:text-white hover:bg-white/5 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="grid grid-cols-3 gap-1 p-1 bg-slate-900/80 rounded-xl border border-white/5 text-xs font-semibold">
          <button
            onClick={() => {
              setActiveTab('github');
              setError(null);
            }}
            className={`py-2 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'github'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                : 'text-[var(--text-muted)] hover:text-white'
            }`}
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub PAT</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('otp');
              setError(null);
            }}
            className={`py-2 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'otp'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                : 'text-[var(--text-muted)] hover:text-white'
            }`}
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>OTP Code</span>
          </button>

          <button
            onClick={() => {
              setActiveTab('password');
              setError(null);
            }}
            className={`py-2 px-2 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'password'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-600/30'
                : 'text-[var(--text-muted)] hover:text-white'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Password</span>
          </button>
        </div>

        {/* Notifications */}
        {error && (
          <div className="p-3 rounded-xl bg-rose-950/80 border border-rose-500/40 text-rose-200 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="p-3 rounded-xl bg-emerald-950/80 border border-emerald-500/40 text-emerald-200 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* TAB 1: GitHub Access Token Login */}
        {activeTab === 'github' && (
          <form onSubmit={handleGitHubLogin} className="space-y-4">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold text-slate-300">GitHub Personal Access Token</label>
                <a
                  href="https://github.com/settings/tokens"
                  target="_blank"
                  rel="noreferrer"
                  className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1"
                >
                  <span>Generate Token</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <div className="relative">
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                  className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
                  required
                />
              </div>
              <p className="text-[11px] text-[var(--text-subtle)] leading-relaxed">
                Requires <code className="text-cyan-400">repo</code> scope. Used to authenticate your identity and automatically dispatch remediation pull requests to your GitHub repositories.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Workspace Name (optional, first sign-in only)</label>
              <input
                type="text"
                value={githubOrgName}
                onChange={(e) => setGithubOrgName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary justify-center py-2.5 text-xs font-bold"
            >
              <Github className="w-4 h-4" />
              <span>{loading ? 'Verifying with GitHub...' : 'Authorize & Sign In with GitHub'}</span>
            </button>
          </form>
        )}

        {/* TAB 2: 2FA OTP Email Verification */}
        {activeTab === 'otp' && (
          <div className="space-y-4">
            {!otpSent ? (
              <form onSubmit={handleSendOTP} className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-300">Work Email Address</label>
                  <input
                    type="email"
                    value={otpEmail}
                    onChange={(e) => setOtpEmail(e.target.value)}
                    placeholder="developer@yourcompany.com"
                    className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-slate-300">Workspace Name (optional)</label>
                  <input
                    type="text"
                    value={otpOrgName}
                    onChange={(e) => setOtpOrgName(e.target.value)}
                    placeholder="Acme Corp"
                    className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                  />
                  <p className="text-[11px] text-[var(--text-subtle)] leading-relaxed">
                    Join an existing team workspace by its exact name, or leave blank for your own private workspace.
                  </p>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full btn-primary justify-center py-2.5 text-xs font-bold"
                >
                  <Mail className="w-4 h-4" />
                  <span>{loading ? 'Sending Security OTP...' : 'Send 6-Digit OTP Code'}</span>
                </button>
              </form>
            ) : (
              <form onSubmit={handleVerifyOTP} className="space-y-4">
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-slate-300">Enter 6-Digit OTP</label>
                    <button
                      type="button"
                      onClick={() => setOtpSent(false)}
                      className="text-[11px] text-cyan-400 hover:underline"
                    >
                      Change Email
                    </button>
                  </div>
                  <input
                    type="text"
                    maxLength={6}
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    placeholder="123456"
                    className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2.5 text-center text-lg font-mono tracking-widest text-cyan-400 focus:outline-none focus:border-cyan-400"
                    required
                  />
                  {demoOtp && (
                    <div className="p-2 bg-indigo-950/40 rounded-lg border border-indigo-500/20 text-[11px] text-indigo-300 flex items-center justify-between font-mono">
                      <span>Generated Code: <strong>{demoOtp}</strong></span>
                      <button
                        type="button"
                        onClick={() => setOtpCode(demoOtp)}
                        className="text-cyan-400 hover:underline text-[10px]"
                      >
                        Auto-fill
                      </button>
                    </div>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  className="w-full btn-success justify-center py-2.5 text-xs font-bold"
                >
                  <ShieldCheck className="w-4 h-4" />
                  <span>{loading ? 'Verifying...' : 'Verify OTP & Log In'}</span>
                </button>
              </form>
            )}
          </div>
        )}

        {/* TAB 3: Email + Password */}
        {activeTab === 'password' && (
          <form onSubmit={handlePasswordAuth} className="space-y-3.5">
            {isRegister && (
              <>
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Full Name</label>
                  <input
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Gurumurthy"
                    className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                    required
                  />
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300">Workspace Name (optional)</label>
                  <input
                    type="text"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    placeholder="Acme Corp"
                    className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                  />
                  <p className="text-[11px] text-[var(--text-subtle)] leading-relaxed">
                    Join an existing team workspace by its exact name, or leave blank to create your own.
                  </p>
                </div>
              </>
            )}

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300">Email Address</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="secops@patchforge.ai"
                className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400"
                required
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-slate-950/80 border border-white/10 rounded-xl px-3.5 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary justify-center py-2.5 text-xs font-bold mt-2"
            >
              <span>{loading ? 'Processing...' : isRegister ? 'Create Account' : 'Sign In'}</span>
            </button>

            <div className="text-center pt-2">
              <button
                type="button"
                onClick={() => setIsRegister(!isRegister)}
                className="text-xs text-cyan-400 hover:underline"
              >
                {isRegister ? 'Already have an account? Sign in' : 'Need an account? Register'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
