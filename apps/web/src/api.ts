import type { Assessment, CheckId, CheckResults } from '@ip-assess/core';

export interface HistorySummary {
  total: number;
  last24h: number;
  last7d: number;
  last30d: number;
  first: string | null;
  recent: { id: string; createdAt: string; priority: string; threatLevel: string }[];
}

export interface AiEvaluation {
  verdict: 'likely_malicious' | 'suspicious' | 'likely_benign' | 'inconclusive';
  confidence: 'low' | 'medium' | 'high';
  summary: string;
  key_points: string[];
  recommended_actions: string[];
  caveats: string[];
}

export interface AiState {
  status: 'none' | 'queued' | 'deferred' | 'done' | 'failed';
  model?: string | null;
  result?: AiEvaluation | null;
  completedAt?: string | null;
}

export interface AssessmentResponse {
  id: string;
  assessment: Assessment;
  history: HistorySummary;
  ai: AiState;
}

export interface StoredAssessmentResponse extends AssessmentResponse {
  checks: CheckResults;
}

export class ApiError extends Error {
  constructor(public code: string, public status: number) {
    super(code);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch {
    throw new ApiError('network', 0);
  }
  const body = (await res.json().catch(() => ({}))) as { error?: string };
  if (!res.ok) throw new ApiError(body.error ?? 'generic', res.status);
  return body as T;
}

export const fetchCheck = <K extends CheckId>(id: K, ip: string) =>
  request<CheckResults[K]>(`/api/checks/${id}?ip=${encodeURIComponent(ip)}`);

export const createAssessment = (ip: string) =>
  request<AssessmentResponse>('/api/assessments', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ip }),
  });

export const fetchAssessment = (id: string) => request<StoredAssessmentResponse>(`/api/assessments/${encodeURIComponent(id)}`);

export const fetchAi = (id: string) => request<AiState>(`/api/assessments/${encodeURIComponent(id)}/ai`);
