'use client';
import { create } from 'zustand';
import { AIMessage, VisualContext } from '@/types/ai';
import { chatWithSentinel, visualChatWithSentinel } from '@/lib/aiApi';

// Conversation history format for backend (no id/timestamp — only role+content)
function toBackendHistory(messages: AIMessage[]): Array<{ role: string; content: string }> {
  return messages
    .filter((m) => !m.isError)
    .map((m) => ({ role: m.role, content: m.content }));
}

function generateId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export type AIContextType = 'general' | 'scan' | 'finding';

interface AIStore {
  isOpen: boolean;
  contextType: AIContextType;
  scanId: string | null;
  findingId: string | null;
  findingTitle: string | null;
  scanUrl: string | null;
  messages: AIMessage[];
  isLoading: boolean;
  error: string | null;
  conversationId: string;

  // ── Circle to Sentinel visual state ──────────────────────────────────────
  /** True while the selection overlay is active (before confirm) */
  circleToSentinelActive: boolean;
  /** Visual context captured from selection, waiting to be sent with a question */
  pendingVisualContext: VisualContext | null;
  /** True while analyzing a visual selection */
  isAnalyzingVisual: boolean;

  openAssistant: (opts?: {
    scanId?: string;
    findingId?: string;
    findingTitle?: string;
    scanUrl?: string;
    contextType?: AIContextType;
    visualContext?: VisualContext;
  }) => void;
  closeAssistant: () => void;
  sendMessage: (message: string) => Promise<void>;
  sendVisualMessage: (message: string, visualContext: VisualContext) => Promise<void>;
  explainVisualSelection: (visualContext: VisualContext) => Promise<void>;
  clearConversation: () => void;
  regenerateLastResponse: () => Promise<void>;
  setError: (error: string | null) => void;
  setCircleToSentinelActive: (active: boolean) => void;
  setPendingVisualContext: (ctx: VisualContext | null) => void;
  clearVisualContext: () => void;
}

let _isSubmitting = false;

export const useAIStore = create<AIStore>((set, get) => ({
  isOpen: false,
  contextType: 'general',
  scanId: null,
  findingId: null,
  findingTitle: null,
  scanUrl: null,
  messages: [],
  isLoading: false,
  isAnalyzingVisual: false,
  error: null,
  conversationId: generateId(),
  circleToSentinelActive: false,
  pendingVisualContext: null,

  openAssistant: (opts = {}) => {
    const { scanId, findingId, findingTitle, scanUrl, contextType, visualContext } = opts;
    const newType: AIContextType = contextType ?? (findingId ? 'finding' : scanId ? 'scan' : 'general');

    // Clear conversation if context changes significantly
    const state = get();
    const contextChanged =
      state.findingId !== (findingId ?? null) ||
      state.scanId !== (scanId ?? null);

    set({
      isOpen: true,
      contextType: newType,
      scanId: scanId ?? null,
      findingId: findingId ?? null,
      findingTitle: findingTitle ?? null,
      scanUrl: scanUrl ?? null,
      messages: contextChanged ? [] : state.messages,
      error: null,
      conversationId: contextChanged ? generateId() : state.conversationId,
      // Store incoming visual context as pending
      pendingVisualContext: visualContext ?? state.pendingVisualContext,
    });
  },

  closeAssistant: () => set({ isOpen: false }),

  sendMessage: async (message: string) => {
    const state = get();
    if (_isSubmitting || state.isLoading) return;
    _isSubmitting = true;

    const userMsg: AIMessage = {
      id: generateId(),
      role: 'user',
      content: message,
      timestamp: new Date().toISOString(),
    };

    set((s) => ({
      messages: [...s.messages, userMsg],
      isLoading: true,
      error: null,
    }));

    try {
      const currentState = get();
      const history = toBackendHistory(currentState.messages.slice(0, -1)); // exclude the just-added user message

      const response = await chatWithSentinel({
        message,
        scan_id: currentState.scanId ?? undefined,
        finding_id: currentState.findingId ?? undefined,
        conversation_id: currentState.conversationId,
        conversation_history: history,
      });

      const assistantMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: response.answer,
        sources: response.sources,
        timestamp: new Date().toISOString(),
        model: response.model,
      };

      set((s) => ({
        messages: [...s.messages, assistantMsg],
        isLoading: false,
      }));
    } catch (err: any) {
      let errorDetail =
        err?.response?.data?.detail ||
        err?.message ||
        'Sentinel AI is temporarily unavailable. Your SentinelScan results are still accessible.';

      // Friendly timeout message
      if (
        err?.code === 'ECONNABORTED' ||
        err?.response?.status === 504 ||
        errorDetail.toLowerCase().includes('took too long') ||
        errorDetail.toLowerCase().includes('timeout')
      ) {
        errorDetail = 'Gemini took too long to respond. Please try again.';
      }

      const errorMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: `⚠️ ${errorDetail}`,
        timestamp: new Date().toISOString(),
        isError: true,
      };

      set((s) => ({
        messages: [...s.messages, errorMsg],
        isLoading: false,
        error: errorDetail,
      }));
    } finally {
      _isSubmitting = false;
    }
  },

  /**
   * Circle to Sentinel — send a message with visual context.
   * Calls POST /api/ai/visual-chat. The visual context is stored on the
   * user message so the panel can render a preview thumbnail.
   */
  sendVisualMessage: async (message: string, visualContext: VisualContext) => {
    const state = get();
    if (_isSubmitting || state.isLoading) return;
    _isSubmitting = true;

    const userMsg: AIMessage = {
      id: generateId(),
      role: 'user',
      content: message,
      timestamp: new Date().toISOString(),
      visualContext,
    };

    set((s) => ({
      messages: [...s.messages, userMsg],
      isLoading: true,
      isAnalyzingVisual: true,
      error: null,
      pendingVisualContext: visualContext,
    }));

    try {
      const currentState = get();
      const history = toBackendHistory(currentState.messages.slice(0, -1));

      const response = await visualChatWithSentinel({
        message,
        image_data: visualContext.image_data,
        selected_text: visualContext.selected_text,
        region: visualContext.region,
        scan_id: currentState.scanId ?? undefined,
        finding_id: currentState.findingId ?? undefined,
        conversation_id: currentState.conversationId,
        conversation_history: history,
      });

      const assistantMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: response.answer,
        sources: response.sources,
        timestamp: new Date().toISOString(),
        model: response.model,
        visualContext,
      };

      set((s) => ({
        messages: [...s.messages, assistantMsg],
        isLoading: false,
        isAnalyzingVisual: false,
        pendingVisualContext: visualContext,
      }));
    } catch (err: any) {
      let errorDetail =
        err?.response?.data?.detail ||
        err?.message ||
        'Sentinel AI could not analyze the selected area. Please try again.';

      if (
        err?.code === 'ECONNABORTED' ||
        err?.response?.status === 504 ||
        errorDetail.toLowerCase().includes('took too long') ||
        errorDetail.toLowerCase().includes('timeout')
      ) {
        errorDetail = 'The visual analysis took too long to respond. Please try again.';
      }

      const errorMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: `⚠️ ${errorDetail}`,
        timestamp: new Date().toISOString(),
        isError: true,
        visualContext,
      };

      set((s) => ({
        messages: [...s.messages, errorMsg],
        isLoading: false,
        isAnalyzingVisual: false,
        error: errorDetail,
        pendingVisualContext: visualContext,
      }));
    } finally {
      _isSubmitting = false;
    }
  },

  /**
   * Circle to Sentinel — automatic explanation of selected region.
   * Calls POST /api/ai/visual-chat with empty message so the backend applies
   * DEFAULT_VISUAL_EXPLANATION_PROMPT. No fake user message is added to messages.
   * The assistant's answer appears naturally as the first response.
   */
  explainVisualSelection: async (visualContext: VisualContext) => {
    const state = get();
    if (_isSubmitting || state.isLoading) return;
    _isSubmitting = true;

    set((s) => ({
      messages: s.messages.filter((m) => !m.isError),
      isLoading: true,
      isAnalyzingVisual: true,
      error: null,
      pendingVisualContext: visualContext,
    }));

    try {
      const currentState = get();
      const history = toBackendHistory(currentState.messages);

      const response = await visualChatWithSentinel({
        message: '',
        image_data: visualContext.image_data,
        selected_text: visualContext.selected_text,
        region: visualContext.region,
        scan_id: currentState.scanId ?? undefined,
        finding_id: currentState.findingId ?? undefined,
        conversation_id: currentState.conversationId,
        conversation_history: history,
      });

      const assistantMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: response.answer,
        sources: response.sources,
        timestamp: new Date().toISOString(),
        model: response.model,
        visualContext,
      };

      set((s) => ({
        messages: [...s.messages, assistantMsg],
        isLoading: false,
        isAnalyzingVisual: false,
        pendingVisualContext: visualContext,
      }));
    } catch (err: any) {
      let errorDetail =
        err?.response?.data?.detail ||
        err?.message ||
        "Sentinel Intelligence couldn't analyze this selection.";

      if (
        err?.code === 'ECONNABORTED' ||
        err?.response?.status === 504 ||
        errorDetail.toLowerCase().includes('took too long') ||
        errorDetail.toLowerCase().includes('timeout')
      ) {
        errorDetail = 'The visual analysis took too long to respond. Please try again.';
      }

      const errorMsg: AIMessage = {
        id: generateId(),
        role: 'assistant',
        content: `⚠️ Sentinel Intelligence couldn't analyze this selection.`,
        timestamp: new Date().toISOString(),
        isError: true,
        visualContext,
      };

      set((s) => ({
        messages: [...s.messages, errorMsg],
        isLoading: false,
        isAnalyzingVisual: false,
        error: errorDetail,
        pendingVisualContext: visualContext,
      }));
    } finally {
      _isSubmitting = false;
    }
  },

  clearConversation: () =>
    set({
      messages: [],
      error: null,
      conversationId: generateId(),
      pendingVisualContext: null,
      isAnalyzingVisual: false,
    }),

  regenerateLastResponse: async () => {
    const state = get();
    if (state.isLoading) return;

    // Check if the conversation has an error message with visualContext
    const lastMsg = state.messages[state.messages.length - 1];
    if (lastMsg && lastMsg.isError && lastMsg.visualContext && !state.messages.some((m) => m.role === 'user')) {
      await get().explainVisualSelection(lastMsg.visualContext);
      return;
    }

    // Find the last user message
    const lastUserIdx = [...state.messages].reverse().findIndex((m) => m.role === 'user');
    if (lastUserIdx === -1) {
      if (state.pendingVisualContext) {
        await get().explainVisualSelection(state.pendingVisualContext);
      }
      return;
    }

    const lastUserMessage = [...state.messages].reverse()[lastUserIdx];

    // Remove last assistant message(s) after the last user message
    const realIdx = state.messages.length - 1 - lastUserIdx;
    const trimmedMessages = state.messages.slice(0, realIdx + 1);

    // Remove the last user message from the trimmed list too (sendMessage will re-add it)
    const historyMessages = trimmedMessages.slice(0, -1);

    set({ messages: historyMessages, error: null });

    // If the last user message had visual context, re-send visually
    if (lastUserMessage.visualContext) {
      await get().sendVisualMessage(lastUserMessage.content, lastUserMessage.visualContext);
    } else {
      await get().sendMessage(lastUserMessage.content);
    }
  },

  setError: (error) => set({ error }),

  setCircleToSentinelActive: (active) => set({ circleToSentinelActive: active }),

  setPendingVisualContext: (ctx) => set({ pendingVisualContext: ctx }),

  clearVisualContext: () => set({ pendingVisualContext: null }),
}));


