// AI types for Ask Sentinel
export interface AIMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sources?: string[];
  timestamp: string;
  model?: string;
  isError?: boolean;
  /** Optional: visual context when message was sent from Circle to Sentinel */
  visualContext?: VisualContext;
}

export interface AIChatRequest {
  message: string;
  scan_id?: string;
  finding_id?: string;
  conversation_id?: string;
  conversation_history: Array<{ role: string; content: string }>;
}

export interface AIChatResponse {
  answer: string;
  sources: string[];
  context_type: 'scan' | 'finding' | 'general';
  finding_id?: string;
  scan_id?: string;
  model: string;
  provider: string;
}

export interface AIExplainFindingResponse {
  summary: string;
  why_it_matters: string;
  evidence_explanation: string;
  technical_explanation: string;
  severity_explanation: string;
  owasp_context: string;
  remediation: string;
  limitations: string;
  sources: string[];
  model: string;
  provider: string;
}

// ── Circle to Sentinel visual context types ──────────────────────────────────

export interface SelectionRegion {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface VisualContext {
  /** Base64-encoded JPEG of the cropped region (no data: prefix) */
  image_data: string;
  /** Visible text extracted from DOM nodes within the selection */
  selected_text: string;
  /** Pixel coordinates of the selected rectangle in the viewport */
  region: SelectionRegion;
  /** Thumbnail data URI for in-panel preview only — never sent to backend */
  thumbnailDataUrl?: string;
}

export interface VisualAIRequest {
  message?: string;
  image_data: string;
  selected_text: string;
  region: SelectionRegion;
  scan_id?: string;
  finding_id?: string;
  conversation_id?: string;
  conversation_history: Array<{ role: string; content: string }>;
}

export interface VisualAIResponse {
  answer: string;
  sources: string[];
  context_type: string;
  finding_id?: string;
  scan_id?: string;
  model: string;
  provider: string;
}
