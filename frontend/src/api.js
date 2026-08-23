/**
 * PatchForge AI - Frontend API Service Client
 * ===========================================
 * Connects React UI to FastAPI backend endpoints.
 */

import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach the stored JWT to every request. Most endpoints now require
// authentication - without this, every call would 401 once logged in,
// since login only ever wrote the token to localStorage without anything
// reading it back out on subsequent requests.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('patchforge_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// System & Health
export const getHealth = () => api.get('/health');
export const getMetrics = () => api.get('/metrics');

// Authentication & GitHub Token / OTP Verification
export const loginWithGitHub = (token) => api.post('/auth/github', { token });
export const sendOTP = (email) => api.post('/auth/otp/send', { email });
export const verifyOTP = (email, otp) => api.post('/auth/otp/verify', { email, otp });
export const loginWithPassword = (email, password) => api.post('/auth/login', { email, password });
export const registerWithPassword = (email, password, fullName) =>
  api.post('/auth/register', { email, password, full_name: fullName });
export const getMyProfile = () => api.get('/auth/me');

// Repositories
export const getRepositories = () => api.get('/repositories');
export const createRepository = (data) => api.post('/repositories', data);
export const deleteRepository = (id) => api.delete(`/repositories/${id}`);

// Scans
export const getScans = (repoId) =>
  api.get('/scans', { params: repoId ? { repository_id: repoId } : {} });
export const createScan = (data) => api.post('/scans', data);

// Vulnerabilities
export const getVulnerabilities = (scanId, status) =>
  api.get('/vulnerabilities', {
    params: {
      ...(scanId ? { scan_id: scanId } : {}),
      ...(status ? { status } : {}),
    },
  });
export const getVulnerability = (id) => api.get(`/vulnerabilities/${id}`);
export const verifyVulnerability = (id) => api.post(`/vulnerabilities/${id}/verify`);

// Remediation Patches
export const getPatches = () => api.get('/patches');
export const getPatch = (id) => api.get(`/patches/${id}`);
export const generatePatch = (vulnerabilityId) =>
  api.post('/patches/generate', { vulnerability_id: vulnerabilityId });
export const validatePatch = (patchId) => api.post(`/patches/${patchId}/validate`);

// Pull Requests
export const getPullRequests = (repoId) =>
  api.get('/pull-requests', { params: repoId ? { repository_id: repoId } : {} });
export const createPullRequest = (patchId, baseBranch = 'main') =>
  api.post('/pull-requests/create', { patch_id: patchId, base_branch: baseBranch });

export default api;
