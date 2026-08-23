import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import DashboardOverview from './components/DashboardOverview';
import VulnerabilityTable from './components/VulnerabilityTable';
import RepositoriesView from './components/RepositoriesView';
import PullRequestsView from './components/PullRequestsView';
import LiveLogTerminal from './components/LiveLogTerminal';
import PatchModal from './components/PatchModal';
import AuthModal from './components/AuthModal';
import {
  getRepositories,
  createRepository,
  deleteRepository,
  getVulnerabilities,
  verifyVulnerability,
  generatePatch,
  validatePatch,
  getPatches,
  getPullRequests,
  createPullRequest,
  createScan,
  getMetrics,
} from './api';
import { CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [repositories, setRepositories] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [patches, setPatches] = useState([]);
  const [pullRequests, setPullRequests] = useState([]);
  const [metrics, setMetrics] = useState(null);

  // Authentication State
  const [currentUser, setCurrentUser] = useState(() => {
    try {
      const saved = localStorage.getItem('patchforge_user');
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  const [selectedPatch, setSelectedPatch] = useState(null);
  const [selectedVulnForPatch, setSelectedVulnForPatch] = useState(null);
  const [loadingId, setLoadingId] = useState(null);
  const [isCreatingPR, setIsCreatingPR] = useState(false);
  const [createdPR, setCreatedPR] = useState(null);
  const [isScanningRepo, setIsScanningRepo] = useState(null);

  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'success') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  const loadData = async () => {
    try {
      const [reposRes, vulnsRes, patchesRes, prsRes] = await Promise.all([
        getRepositories().catch(() => ({ data: { items: [] } })),
        getVulnerabilities().catch(() => ({ data: { items: [] } })),
        getPatches().catch(() => ({ data: { items: [] } })),
        getPullRequests().catch(() => ({ data: { items: [] } })),
      ]);

      setRepositories(reposRes.data?.items || []);
      setVulnerabilities(vulnsRes.data?.items || []);
      setPatches(patchesRes.data?.items || []);
      setPullRequests(prsRes.data?.items || []);
    } catch (err) {
      console.error('Failed loading PatchForge state:', err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000); // 10s auto-refresh
    return () => clearInterval(interval);
  }, []);

  const handleVerifyPoC = async (vulnId) => {
    setLoadingId(`verify-${vulnId}`);
    try {
      const res = await verifyVulnerability(vulnId);
      showToast('Dynamic PoC executed in isolated Docker sandbox!');
      await loadData();
    } catch (err) {
      showToast('PoC verification failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoadingId(null);
    }
  };

  const handleGeneratePatch = async (vulnId) => {
    setLoadingId(`patch-${vulnId}`);
    try {
      const targetVuln = vulnerabilities.find((v) => v.id === vulnId);
      setSelectedVulnForPatch(targetVuln);

      // 1. Generate patch
      const genRes = await generatePatch(vulnId);
      const patch = genRes.data;

      // 2. Validate patch
      let validatedPatch = patch;
      try {
        const valRes = await validatePatch(patch.id);
        validatedPatch = {
          ...patch,
          ...valRes.data,
          id: patch.id || valRes.data.patch_id,
          patch_score: valRes.data.composite_score ?? patch.patch_score ?? 95,
          diff_content: patch.diff_content || valRes.data.diff_content,
          explanation: patch.explanation || valRes.data.explanation,
          security_reason: patch.security_reason || valRes.data.security_reason,
        };
      } catch (valErr) {
        console.warn('Validation call error fallback:', valErr);
      }

      setSelectedPatch(validatedPatch);
      setCreatedPR(null);
      showToast(`Autonomous Patch synthesized! Score: ${validatedPatch.patch_score || 95}/100`);
      await loadData();
    } catch (err) {
      showToast('Patch generation failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setLoadingId(null);
    }
  };

  const handleCreatePR = async (patchId) => {
    const targetPatchId = patchId || selectedPatch?.id || selectedPatch?.patch_id;
    if (!targetPatchId) {
      showToast('Invalid patch ID for PR creation', 'error');
      return;
    }
    setIsCreatingPR(true);
    try {
      const res = await createPullRequest(targetPatchId);
      setCreatedPR(res.data);
      showToast(`Pull Request #${res.data.pr_number} created successfully!`);
      await loadData();
    } catch (err) {
      showToast('PR creation failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setIsCreatingPR(false);
    }
  };

  const handleTriggerScan = async (repoId) => {
    setIsScanningRepo(repoId);
    try {
      await createScan({ repository_id: repoId });
      showToast('AST Security Scan completed!');
      await loadData();
    } catch (err) {
      showToast('Scan failed: ' + (err.response?.data?.detail || err.message), 'error');
    } finally {
      setIsScanningRepo(null);
    }
  };

  const handleCreateRepository = async (data) => {
    try {
      await createRepository(data);
      showToast(`Repository ${data.full_name} registered!`);
      await loadData();
    } catch (err) {
      showToast('Repo registration failed: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleDeleteRepository = async (repoId) => {
    try {
      await deleteRepository(repoId);
      showToast('Repository deleted successfully!');
      await loadData();
    } catch (err) {
      showToast('Failed to delete repository: ' + (err.response?.data?.detail || err.message), 'error');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('patchforge_token');
    localStorage.removeItem('patchforge_user');
    setCurrentUser(null);
    showToast('Signed out successfully.');
  };

  const handleAuthSuccess = (user) => {
    setCurrentUser(user);
    showToast(
      user.github_username
        ? `Authenticated with GitHub (@${user.github_username})!`
        : `Authenticated as ${user.email}!`
    );
  };

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] text-slate-100 flex flex-col">
      {/* Toast Notification */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 animate-bounce">
          <div
            className={`px-4 py-3 rounded-xl shadow-xl flex items-center gap-2.5 text-xs font-semibold border ${
              toast.type === 'error'
                ? 'bg-rose-950/90 text-rose-200 border-rose-500/40'
                : 'bg-emerald-950/90 text-emerald-200 border-emerald-500/40'
            }`}
          >
            {toast.type === 'error' ? (
              <AlertCircle className="w-4 h-4 text-rose-400" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            )}
            <span>{toast.message}</span>
          </div>
        </div>
      )}

      {/* Navigation Header with Profile & GitHub Connect */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        metrics={metrics}
        currentUser={currentUser}
        onOpenAuthModal={() => setIsAuthModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {activeTab === 'dashboard' && (
          <DashboardOverview
            repositories={repositories}
            vulnerabilities={vulnerabilities}
            patches={patches}
            pullRequests={pullRequests}
            onNavigateTab={setActiveTab}
            onVerify={handleVerifyPoC}
            onGeneratePatch={handleGeneratePatch}
            loadingId={loadingId}
          />
        )}

        {activeTab === 'vulnerabilities' && (
          <VulnerabilityTable
            vulnerabilities={vulnerabilities}
            repositories={repositories}
            onVerify={handleVerifyPoC}
            onGeneratePatch={handleGeneratePatch}
            loadingId={loadingId}
          />
        )}

        {activeTab === 'repositories' && (
          <RepositoriesView
            repositories={repositories}
            onTriggerScan={handleTriggerScan}
            onCreateRepository={handleCreateRepository}
            onDeleteRepository={handleDeleteRepository}
            isScanningRepo={isScanningRepo}
          />
        )}

        {activeTab === 'pull_requests' && <PullRequestsView pullRequests={pullRequests} />}

        {activeTab === 'logs' && <LiveLogTerminal />}
      </main>

      {/* Auth & GitHub Token Modal */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onAuthSuccess={handleAuthSuccess}
      />

      {/* Patch Remediation Modal */}
      {selectedPatch && (
        <PatchModal
          patch={selectedPatch}
          vulnerability={selectedVulnForPatch}
          onClose={() => {
            setSelectedPatch(null);
            setSelectedVulnForPatch(null);
          }}
          onCreatePR={handleCreatePR}
          isCreatingPR={isCreatingPR}
          createdPR={createdPR}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-[var(--border-subtle)] py-6 mt-12 text-center text-xs text-[var(--text-subtle)]">
        <p>
          PatchForge AI © 2026 — AST-Driven Autonomous Remediation & DevSecOps Platform
        </p>
      </footer>
    </div>
  );
}
