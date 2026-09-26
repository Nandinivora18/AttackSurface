import api from '@/lib/api';
import { AIChatRequest, AIChatResponse, AIExplainFindingResponse, VisualAIRequest, VisualAIResponse } from '@/types/ai';

export interface AIStatusResponse {
  configured: boolean;
  provider: string | null;
  model: string | null;
}

export async function getAIStatus(): Promise<AIStatusResponse> {
  const res = await api.get<AIStatusResponse>('/api/ai/status', {
    skipGlobalToast: true,
  } as any);
  return res.data;
}

export async function chatWithSentinel(req: AIChatRequest): Promise<AIChatResponse> {
  const res = await api.post<AIChatResponse>('/api/ai/chat', req, {
    // Don't show global toast for AI errors — the panel handles them gracefully
    skipGlobalToast: true,
  } as any);
  return res.data;
}

export async function explainFinding(findingId: string): Promise<AIExplainFindingResponse> {
  const res = await api.post<AIExplainFindingResponse>(
    '/api/ai/explain-finding',
    { finding_id: findingId },
    { skipGlobalToast: true } as any,
  );
  return res.data;
}

/**
 * Circle to Sentinel — send a visual region to the AI.
 * The image (base64 JPEG, no data: prefix) plus extracted DOM text are sent
 * to the backend's /api/ai/visual-chat endpoint, which constructs a Gemini
 * vision request server-side. The API key never touches the browser.
 */
export async function visualChatWithSentinel(req: VisualAIRequest): Promise<VisualAIResponse> {
  const res = await api.post<VisualAIResponse>('/api/ai/visual-chat', req, {
    skipGlobalToast: true,
  } as any);
  return res.data;
}
