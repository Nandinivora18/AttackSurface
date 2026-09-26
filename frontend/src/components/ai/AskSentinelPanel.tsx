'use client';
import { useEffect, useRef, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Trash2,
  Globe,
  FileText,
  Loader2,
  AlertTriangle,
  Shield,
  Terminal,
  Lock,
  Wrench,
  ArrowUp,
} from 'lucide-react';
import { useAIStore } from '@/store/aiStore';
import MessageBubble from './MessageBubble';
import QuickActions from './QuickActions';
import { cn } from '@/lib/utils';
import { getAIStatus } from '@/lib/aiApi';

// ─── Shared Sentinel mark (small, for panel header) ───────────────────────────
function SentinelMark({ size = 18, spin = false }: { size?: number; spin?: boolean }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
      style={{ display: 'block', animation: spin ? 'siMarkSpin 3s linear infinite' : undefined }}
    >
      <circle cx="12" cy="12" r="10.5" stroke="currentColor" strokeWidth="0.5" strokeDasharray="1.5 4" opacity="0.25" className="si-orbit" />
      <circle cx="12" cy="12" r="6" stroke="currentColor" strokeWidth="0.35" opacity="0.12" />
      <path d="M12 1.5 L12.9 9.5 L12 10.5 L11.1 9.5 Z" fill="currentColor" />
      <path d="M12 22.5 L12.9 14.5 L12 13.5 L11.1 14.5 Z" fill="currentColor" />
      <path d="M1.5 12 L9.5 12.9 L10.5 12 L9.5 11.1 Z" fill="currentColor" />
      <path d="M22.5 12 L14.5 12.9 L13.5 12 L14.5 11.1 Z" fill="currentColor" />
      <path d="M12 9.8 L14.2 12 L12 14.2 L9.8 12 Z" fill="currentColor" opacity="0.9" />
    </svg>
  );
}

// ─── Loading animation ─────────────────────────────────────────────────────────
function AnalyzingIndicator({ isVisual = false }: { isVisual?: boolean }) {
  return (
    <div className="flex gap-3 items-start">
      {/* Animated icon */}
      <div
        className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5"
        style={{
          background: 'linear-gradient(145deg, #1C1808, #0D0B06)',
          border: '1px solid rgba(212,175,55,0.35)',
          boxShadow: '0 0 14px rgba(212,175,55,0.12)',
          animation: 'siGlowPulse 2s ease-in-out infinite',
        }}
      >
        <span className="text-[#D4AF37]" style={{ animation: 'siMarkSpin 4s linear infinite' }}>
          <SentinelMark size={15} />
        </span>
      </div>
      {/* Text */}
      <div
        className="flex-1 rounded-2xl rounded-tl-sm px-4 py-3"
        style={{ background: '#0F0F0F', border: '1px solid #1C1C1C' }}
      >
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1 flex-shrink-0">
            {[0, 1, 2].map((i) => (
              <motion.span
                key={i}
                className="block w-1 h-1 rounded-full"
                style={{ background: '#D4AF37' }}
                animate={{ opacity: [0.2, 1, 0.2], scale: [0.7, 1.3, 0.7] }}
                transition={{ duration: 1.3, repeat: Infinity, delay: i * 0.23 }}
              />
            ))}
          </div>
          <span className="text-[11px] font-mono text-[#C8C5BD]" id="si-loading-text">
            {isVisual ? 'Analyzing selected area…' : 'Sentinel Intelligence is analyzing...'}
          </span>
        </div>
      </div>
    </div>
  );
}

export default function AskSentinelPanel() {
  const {
    isOpen, contextType, scanId, findingId, findingTitle, scanUrl,
    messages, isLoading, isAnalyzingVisual, error, closeAssistant, sendMessage, sendVisualMessage,
    clearConversation, regenerateLastResponse,
    pendingVisualContext, clearVisualContext,
  } = useAIStore();

  const [inputValue, setInputValue] = useState('');
  const [aiConfigured, setAiConfigured] = useState<boolean | null>(null);
  const [loadingSeconds, setLoadingSeconds] = useState(0);
  const [inputFocused, setInputFocused] = useState(false);
  const statusChecked = useRef(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const messagesRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let timer: ReturnType<typeof setInterval> | null = null;
    if (isLoading) {
      setLoadingSeconds(0);
      timer = setInterval(() => setLoadingSeconds((s) => s + 1), 1000);
    } else {
      setLoadingSeconds(0);
    }
    return () => { if (timer) clearInterval(timer); };
  }, [isLoading]);

  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading]);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 350);
      if (!statusChecked.current) {
        statusChecked.current = true;
        getAIStatus()
          .then((s) => setAiConfigured(s.configured))
          .catch(() => setAiConfigured(null));
      }
    }
  }, [isOpen]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) closeAssistant();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [isOpen, closeAssistant]);

  const handleSend = useCallback(async () => {
    if (isLoading) return;
    const msg = inputValue.trim();
    if (!msg) return;
    setInputValue('');
    if (inputRef.current) inputRef.current.style.height = 'auto';
    // Route through visual path if pending visual context exists
    if (pendingVisualContext) {
      await sendVisualMessage(msg, pendingVisualContext);
    } else {
      await sendMessage(msg);
    }
  }, [inputValue, isLoading, sendMessage, sendVisualMessage, pendingVisualContext]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (!isLoading) handleSend();
    }
  };

  const handleQuickAction = useCallback(async (message: string) => {
    if (isLoading) return;
    await sendMessage(message);
  }, [isLoading, sendMessage]);

  const contextLabel = (): string => {
    if (contextType === 'finding' && findingTitle) return findingTitle;
    if (contextType === 'scan' && scanUrl) {
      try { return new URL(scanUrl).hostname; } catch { return scanUrl; }
    }
    return '';
  };

  const hasMessages = messages.length > 0;

  const loadingStageText =
    isAnalyzingVisual
      ? (loadingSeconds < 3 ? 'Analyzing visual context & visible elements...' :
         loadingSeconds < 7 ? 'Synthesizing security explanation...' :
         'Grounding explanation in SentinelScan telemetry...')
      : (loadingSeconds < 3 ? 'Analyzing telemetry & context...' :
         loadingSeconds < 7 ? 'Synthesizing security guidance...' :
         'Grounding recommendations in evidence...');

  const inputPlaceholder =
    pendingVisualContext
      ? 'Ask about the selected area...'
      : contextType === 'finding' ? 'Ask about this finding...'
      : contextType === 'scan'    ? 'Ask about this scan...'
      : 'Ask Sentinel Intelligence about your attack surface...';

  const capabilityCards = [
    {
      title: 'Analyze Findings',
      category: 'Analysis',
      desc: 'Understand detected vulnerabilities, severity & OWASP 2025 mappings.',
      Icon: Shield,
      prompt: contextType === 'finding'
        ? 'Explain this finding in detail, including why it matters and how its severity was evaluated.'
        : 'What security findings does SentinelScan detect and how are they prioritized?',
    },
    {
      title: 'Inspect Evidence',
      category: 'Evidence',
      desc: 'Understand the passive evidence behind a security finding.',
      Icon: Terminal,
      prompt: contextType === 'finding'
        ? 'Show and break down the specific passive evidence observed for this finding.'
        : 'How does SentinelScan collect and verify passive evidence without active exploitation?',
    },
    {
      title: 'Security Intelligence',
      category: 'Intelligence',
      desc: 'Understand TLS, headers, DNS, and technology security posture.',
      Icon: Lock,
      prompt: contextType === 'scan'
        ? 'Evaluate the SSL/TLS configuration, headers, and DNS records from this scan.'
        : 'What are the essential HTTP security headers and TLS standards for modern web applications?',
    },
    {
      title: 'Remediation',
      category: 'Remediation',
      desc: 'Get actionable guidance and configuration examples.',
      Icon: Wrench,
      prompt: contextType === 'finding'
        ? 'Provide step-by-step remediation instructions and configuration snippets for this finding.'
        : 'What are the best practices for remediating web application attack surface findings?',
    },
  ];

  const canSend = inputValue.trim().length > 0 && !isLoading;

  return (
    <>
      {/* ── Global CSS: keyframes + custom scrollbar ────────────────────────── */}
      <style>{`
        @keyframes siOrbit {
          to { transform: rotate(360deg); }
        }
        .si-orbit {
          transform-origin: 12px 12px;
          animation: siOrbit 18s linear infinite;
        }
        @keyframes siMarkSpin {
          to { transform: rotate(360deg); }
        }
        @keyframes siGlowPulse {
          0%, 100% { box-shadow: 0 0 10px rgba(212,175,55,0.10); }
          50%       { box-shadow: 0 0 20px rgba(212,175,55,0.22); }
        }
        .si-panel-scroll {
          scrollbar-width: thin;
          scrollbar-color: #1E1E1E transparent;
        }
        .si-panel-scroll::-webkit-scrollbar { width: 3px; }
        .si-panel-scroll::-webkit-scrollbar-track { background: transparent; }
        .si-panel-scroll::-webkit-scrollbar-thumb {
          background: #1E1E1E;
          border-radius: 2px;
        }
        .si-panel-scroll::-webkit-scrollbar-thumb:hover {
          background: #3D3020;
        }
        .si-cap-card {
          background: #0C0C0C;
          border: 1px solid #1A1A1A;
          border-radius: 14px;
          padding: 14px;
          cursor: pointer;
          transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
          text-align: left;
          width: 100%;
        }
        .si-cap-card:hover {
          background: #111008;
          border-color: #3D3020;
          box-shadow: 0 4px 20px rgba(212,175,55,0.07);
          transform: translateY(-2px);
        }
        .si-cap-card:hover .si-cap-icon {
          border-color: rgba(212,175,55,0.35);
          box-shadow: 0 0 12px rgba(212,175,55,0.12);
        }
        .si-cap-card:hover .si-cap-icon-svg {
          color: #D4AF37;
        }
        .si-cap-card:hover .si-cap-arrow {
          opacity: 0.5;
          transform: translateX(2px);
        }
        .si-cap-icon {
          width: 28px; height: 28px;
          border-radius: 8px;
          background: #161614;
          border: 1px solid #202020;
          display: flex; align-items: center; justify-content: center;
          transition: border-color 0.2s ease, box-shadow 0.2s ease;
          flex-shrink: 0;
        }
        .si-cap-icon-svg {
          color: rgba(212,175,55,0.5);
          transition: color 0.2s ease;
        }
        .si-cap-arrow {
          opacity: 0;
          transform: translateX(-2px);
          transition: opacity 0.2s ease, transform 0.2s ease;
          color: #D4AF37;
          font-size: 12px;
          line-height: 1;
        }
        .si-chip {
          display: inline-flex; align-items: center; gap: 6px;
          padding: 6px 12px;
          background: #0C0C0C;
          border: 1px solid #1E1E1E;
          border-radius: 10px;
          font-size: 11px;
          color: #7A7670;
          cursor: pointer;
          white-space: nowrap;
          transition: border-color 0.15s ease, color 0.15s ease, transform 0.15s ease;
          font-family: inherit;
        }
        .si-chip:hover {
          border-color: #3D3020;
          color: #D8D5CD;
          transform: translateY(-1px);
        }
        .si-chip:disabled {
          opacity: 0.35;
          cursor: not-allowed;
          transform: none;
        }
        @media (prefers-reduced-motion: reduce) {
          .si-orbit, [style*="siMarkSpin"], [style*="siGlowPulse"] { animation: none !important; }
          .si-cap-card { transition: none; }
          .si-cap-card:hover { transform: none; }
        }
      `}</style>

      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              key="si-backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.22 }}
              onClick={closeAssistant}
              className="fixed inset-0 z-[450]"
              style={{ background: 'rgba(0,0,0,0.48)', backdropFilter: 'blur(2px)' }}
            />

            {/* ── Panel ───────────────────────────────────────────────────── */}
            <motion.div
              key="si-panel"
              data-ai-panel="true"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 30, stiffness: 280, mass: 0.85 }}
              className="fixed right-0 top-0 bottom-0 z-[460] flex flex-col w-full sm:w-[488px] max-w-[100vw]"
              style={{
                background: 'linear-gradient(180deg, #0B0B0B 0%, #080808 100%)',
                borderLeft: '1px solid #191919',
                boxShadow: '-16px 0 60px rgba(0,0,0,0.85)',
              }}
            >

              {/* ── Header ──────────────────────────────────────────────── */}
              <div
                className="flex-shrink-0 px-5 py-4 relative overflow-hidden"
                style={{ borderBottom: '1px solid #181818', background: '#0D0D0D' }}
              >
                {/* Subtle left glow behind icon */}
                <div
                  className="absolute left-0 top-0 bottom-0 w-24 pointer-events-none"
                  style={{ background: 'radial-gradient(ellipse at left center, rgba(212,175,55,0.06) 0%, transparent 70%)' }}
                />

                <div className="relative flex items-center justify-between">
                  {/* Left: identity */}
                  <div className="flex items-center gap-3">
                    {/* Icon */}
                    <div className="relative flex-shrink-0">
                      <div
                        className="w-[38px] h-[38px] rounded-xl flex items-center justify-center"
                        style={{
                          background: 'linear-gradient(145deg, #1C1808, #0C0A05)',
                          border: '1px solid rgba(212,175,55,0.30)',
                          boxShadow: '0 0 16px rgba(212,175,55,0.12)',
                        }}
                      >
                        <span className="text-[#D4AF37]">
                          <SentinelMark size={17} />
                        </span>
                      </div>
                      {/* Status dot */}
                      <span
                        className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full border-2"
                        style={{
                          background: aiConfigured === false ? '#EF4444' : '#4FAF72',
                          borderColor: '#0D0D0D',
                          boxShadow: aiConfigured === false
                            ? '0 0 6px rgba(239,68,68,0.5)'
                            : '0 0 7px rgba(79,175,114,0.55)',
                        }}
                        title={aiConfigured === false ? 'Intelligence Offline' : 'Intelligence Online'}
                      />
                    </div>

                    {/* Name */}
                    <div>
                      <h2
                        className="font-black font-mono uppercase leading-none"
                        style={{ fontSize: '11px', letterSpacing: '0.10em', color: '#F0EDE6' }}
                      >
                        Sentinel Intelligence
                      </h2>
                      <p
                        className="mt-1 font-medium leading-none"
                        style={{ fontSize: '10.5px', color: '#4A4640' }}
                      >
                        Security Intelligence Assistant
                      </p>
                    </div>
                  </div>

                  {/* Right: controls */}
                  <div className="flex items-center gap-1">
                    {hasMessages && (
                      <button
                        onClick={clearConversation}
                        title="Clear conversation"
                        className="group flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-mono transition-all duration-150"
                        style={{ color: '#4A4640', border: '1px solid transparent' }}
                        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.cssText += 'color:#D4AF37;border-color:#272520;background:#111111'; }}
                        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.cssText += 'color:#4A4640;border-color:transparent;background:transparent'; }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span className="hidden sm:inline">Clear</span>
                      </button>
                    )}
                    <button
                      onClick={closeAssistant}
                      aria-label="Close Sentinel Intelligence"
                      className="p-2 rounded-lg transition-all duration-150"
                      style={{ color: '#4A4640', border: '1px solid transparent' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.cssText += 'color:#E6E4DD;border-color:#222222;background:#141414'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.cssText += 'color:#4A4640;border-color:transparent;background:transparent'; }}
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>

              {/* ── Context indicator ──────────────────────────────────── */}
              <div className="flex-shrink-0 px-4 pt-3 pb-1">
                {/* Visual context preview strip */}
                {pendingVisualContext && (
                  <div
                    className="mb-2 flex items-center gap-2.5 rounded-xl px-3 py-2"
                    style={{
                      background: 'rgba(212,175,55,0.05)',
                      border: '1px solid rgba(212,175,55,0.22)',
                      borderLeft: '3px solid rgba(212,175,55,0.55)',
                    }}
                  >
                    {/* Thumbnail */}
                    {pendingVisualContext.thumbnailDataUrl && (
                      <img
                        src={pendingVisualContext.thumbnailDataUrl}
                        alt="Selected region preview"
                        className="flex-shrink-0 rounded object-cover"
                        style={{ width: 40, height: 28, border: '1px solid rgba(212,175,55,0.2)' }}
                      />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className="text-[9px] font-mono font-bold uppercase" style={{ color: '#D4AF37', letterSpacing: '0.1em' }}>
                        Visual Context
                      </div>
                      <div className="text-[10px] font-medium mt-0.5 truncate" style={{ color: '#6E6A62' }}>
                        {Math.round(pendingVisualContext.region.width)} × {Math.round(pendingVisualContext.region.height)}px selected
                        {pendingVisualContext.selected_text && ` · ${pendingVisualContext.selected_text.slice(0, 30)}…`}
                      </div>
                    </div>
                    <button
                      onClick={clearVisualContext}
                      title="Remove visual context"
                      className="flex-shrink-0 w-5 h-5 rounded-md flex items-center justify-center transition-all duration-150"
                      style={{ color: '#4A4640', background: 'transparent' }}
                      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#D4AF37'; }}
                      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#4A4640'; }}
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                )}
                <AnimatePresence mode="wait">
                  {contextType === 'finding' && findingTitle ? (
                    <motion.div
                      key="ctx-finding"
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.16 }}
                    >
                      <ContextStrip
                        icon={<FileText className="w-3 h-3 text-[#D4AF37]" />}
                        label="Finding Context"
                        title={findingTitle}
                        meta="Targeted Triage"
                        active
                      />
                    </motion.div>
                  ) : contextType === 'scan' && scanUrl ? (
                    <motion.div
                      key="ctx-scan"
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.16 }}
                    >
                      <ContextStrip
                        icon={<Globe className="w-3 h-3 text-[#D4AF37]" />}
                        label="Scan Context"
                        title={contextLabel()}
                        meta={scanId ? scanId.slice(0, 8) : undefined}
                        active
                      />
                    </motion.div>
                  ) : (
                    <motion.div
                      key="ctx-general"
                      initial={{ opacity: 0, y: -4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -4 }}
                      transition={{ duration: 0.16 }}
                    >
                      <ContextStrip
                        icon={<span className="text-[8px] text-[#D4AF37]/50 font-bold leading-none">✦</span>}
                        label="General Context"
                        title="Platform Knowledge"
                        meta="No scan selected"
                        active={false}
                      />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* ── Conversation area ─────────────────────────────────── */}
              <div
                ref={messagesRef}
                className="flex-1 overflow-y-auto px-4 py-4 si-panel-scroll"
                style={{ gap: '0' }}
              >
                <div className="flex flex-col gap-5">
                  {/* Welcome / empty state */}
                  {!hasMessages && !isLoading && (
                    <WelcomeScreen
                      cards={capabilityCards}
                      onCardClick={handleQuickAction}
                      contextType={contextType}
                      findingTitle={findingTitle}
                      onAction={handleQuickAction}
                      aiConfigured={aiConfigured}
                      isLoading={isLoading}
                    />
                  )}

                  {/* Messages */}
                  {messages.map((msg, idx) => {
                    const isLast = idx === messages.length - 1;
                    return (
                      <MessageBubble
                        key={msg.id}
                        message={msg}
                        isLast={isLast && msg.role === 'assistant'}
                        onRegenerate={
                          isLast && msg.role === 'assistant'
                            ? regenerateLastResponse
                            : undefined
                        }
                      />
                    );
                  })}

                  {/* Loading state */}
                  <AnimatePresence>
                    {isLoading && (
                      <motion.div
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.18 }}
                      >
                        <AnalyzingIndicator isVisual={isAnalyzingVisual} />
                        <p className="mt-2 ml-11 text-[10px] font-mono" style={{ color: '#3A3730' }}>
                          {loadingStageText}
                        </p>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Continue conversation — quick actions */}
                  {hasMessages && !isLoading && (
                    <div>
                      <div className="flex items-center gap-3 mb-2.5">
                        <div className="h-px flex-1" style={{ background: '#141414' }} />
                        <span className="text-[9px] font-mono uppercase" style={{ color: '#2C2A26', letterSpacing: '0.1em' }}>
                          Continue
                        </span>
                        <div className="h-px flex-1" style={{ background: '#141414' }} />
                      </div>
                      <QuickActions
                        contextType={contextType}
                        findingTitle={findingTitle}
                        onAction={handleQuickAction}
                        disabled={isLoading}
                      />
                    </div>
                  )}

                  <div ref={bottomRef} />
                </div>
              </div>

              {/* ── Input surface ─────────────────────────────────────── */}
              <div
                className="flex-shrink-0 p-4"
                style={{ borderTop: '1px solid #141414', background: '#080808' }}
              >
                <div
                  className="rounded-xl overflow-hidden transition-all duration-200"
                  style={{
                    background: '#0E0E0E',
                    border: `1px solid ${inputFocused ? 'rgba(212,175,55,0.40)' : '#202020'}`,
                    boxShadow: inputFocused ? '0 0 0 1px rgba(212,175,55,0.08)' : 'none',
                  }}
                >
                  <textarea
                    ref={inputRef}
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyDown={handleKeyDown}
                    onFocus={() => setInputFocused(true)}
                    onBlur={() => setInputFocused(false)}
                    placeholder={inputPlaceholder}
                    disabled={isLoading}
                    rows={1}
                    className="w-full resize-none bg-transparent px-4 pt-3.5 pb-2 text-[12px] leading-relaxed focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                    style={{
                      color: '#E6E4DD',
                      caretColor: '#D4AF37',
                      height: 'auto',
                      minHeight: '48px',
                      maxHeight: '120px',
                    }}
                    onInput={(e) => {
                      const el = e.currentTarget;
                      el.style.height = 'auto';
                      el.style.height = Math.min(el.scrollHeight, 120) + 'px';
                    }}
                  />

                  {/* Input footer bar */}
                  <div
                    className="flex items-center justify-between px-3 pb-2.5 pt-1"
                    style={{ borderTop: '1px solid #141414' }}
                  >
                    <div className="flex items-center gap-1.5">
                      <span className="text-[8px]" style={{ color: 'rgba(212,175,55,0.25)' }}>✦</span>
                      <span className="text-[9px] font-mono" style={{ color: '#2E2C28' }}>Intelligence mode</span>
                    </div>

                    <button
                      onClick={handleSend}
                      disabled={!canSend}
                      aria-label="Send message"
                      className="flex items-center gap-1.5 rounded-lg transition-all duration-150"
                      style={{
                        padding: '5px 12px',
                        fontSize: '11px',
                        fontWeight: 700,
                        fontFamily: 'ui-monospace,monospace',
                        letterSpacing: '0.03em',
                        background: canSend ? 'linear-gradient(135deg, #C8A030, #D4AF37)' : '#131313',
                        color: canSend ? '#070707' : '#333333',
                        border: canSend ? 'none' : '1px solid #1C1C1C',
                        boxShadow: canSend ? '0 0 14px rgba(212,175,55,0.28)' : 'none',
                        cursor: canSend ? 'pointer' : 'not-allowed',
                      }}
                    >
                      {isLoading ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <>
                          <span>Send</span>
                          <ArrowUp className="w-3 h-3" />
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Footer notice */}
                <div className="mt-2 flex items-center justify-between px-0.5">
                  <div className="flex items-center gap-1.5">
                    <span
                      className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                      style={{ background: '#4FAF72', boxShadow: '0 0 4px rgba(79,175,114,0.4)' }}
                    />
                    <span className="text-[9px] font-mono" style={{ color: '#2A2825' }}>
                      Grounded in SentinelScan telemetry
                    </span>
                  </div>
                  <span className="text-[9px] font-mono" style={{ color: '#2A2825' }}>Enter ↵</span>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}

// ─── Context strip ─────────────────────────────────────────────────────────────
function ContextStrip({
  icon, label, title, meta, active,
}: {
  icon: React.ReactNode;
  label: string;
  title: string;
  meta?: string;
  active: boolean;
}) {
  return (
    <div
      className="flex items-center gap-3 rounded-xl px-3 py-2.5"
      style={{
        background: active ? '#0F0F0F' : '#0A0A0A',
        border: active ? '1px solid rgba(212,175,55,0.18)' : '1px solid #171717',
        borderLeft: active ? '3px solid rgba(212,175,55,0.5)' : '3px solid #222222',
      }}
    >
      {/* Icon */}
      <div
        className="w-6 h-6 rounded-lg flex items-center justify-center flex-shrink-0"
        style={{
          background: active ? 'rgba(212,175,55,0.08)' : '#111111',
          border: active ? '1px solid rgba(212,175,55,0.18)' : '1px solid #1C1C1C',
        }}
      >
        {icon}
      </div>
      {/* Text */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span
            className="text-[9px] font-mono font-bold uppercase"
            style={{ color: active ? '#D4AF37' : '#4A4640', letterSpacing: '0.1em' }}
          >
            {label}
          </span>
          {meta && (
            <span className="text-[9px] font-mono flex-shrink-0 truncate max-w-[80px]" style={{ color: '#38352F' }}>
              {meta}
            </span>
          )}
        </div>
        <p
          className="text-[11px] font-medium truncate mt-0.5 leading-snug"
          style={{ color: active ? '#C8C5BD' : '#4A4640' }}
        >
          {title}
        </p>
      </div>
    </div>
  );
}

// ─── Welcome screen ────────────────────────────────────────────────────────────
interface CapCard {
  title: string;
  category: string;
  desc: string;
  Icon: React.ComponentType<{ className?: string }>;
  prompt: string;
}

function WelcomeScreen({
  cards, onCardClick, contextType, findingTitle, onAction, aiConfigured, isLoading,
}: {
  cards: CapCard[];
  onCardClick: (p: string) => void;
  contextType: 'general' | 'scan' | 'finding';
  findingTitle?: string | null;
  onAction: (m: string) => void;
  aiConfigured: boolean | null;
  isLoading: boolean;
}) {
  return (
    <div className="flex flex-col items-center text-center px-1 pt-2 pb-2">
      {/* Symbol */}
      <div className="relative mb-4">
        <div
          className="w-14 h-14 rounded-2xl flex items-center justify-center"
          style={{
            background: 'linear-gradient(145deg, #181408, #0A0806)',
            border: '1px solid rgba(212,175,55,0.25)',
            boxShadow: '0 0 24px rgba(212,175,55,0.10)',
          }}
        >
          <span className="text-[#D4AF37]">
            <SentinelMark size={26} />
          </span>
        </div>
        {/* Outer ping ring */}
        <div
          className="absolute inset-0 rounded-2xl pointer-events-none"
          style={{
            border: '1px solid rgba(212,175,55,0.15)',
            animation: 'siGlowPulse 4s ease-in-out infinite',
          }}
        />
      </div>

      <h3
        className="font-black font-mono uppercase leading-none"
        style={{ fontSize: '13px', letterSpacing: '0.12em', color: '#F0EDE6' }}
      >
        Sentinel Intelligence
      </h3>
      <p className="mt-1.5 font-medium" style={{ fontSize: '11px', color: '#5C5852' }}>
        Security Intelligence Assistant
      </p>
      <p className="mt-1" style={{ fontSize: '11px', color: '#3E3C38', maxWidth: '260px', lineHeight: 1.5 }}>
        Turn SentinelScan evidence into security insight.
      </p>

      {/* Capability cards */}
      <div className="mt-6 w-full grid grid-cols-2 gap-2">
        {cards.map((card) => {
          const { Icon } = card;
          return (
            <button
              key={card.title}
              onClick={() => onCardClick(card.prompt)}
              className="si-cap-card"
            >
              <div className="flex items-start justify-between mb-2.5">
                <div className="si-cap-icon">
                  <Icon className="w-3.5 h-3.5 si-cap-icon-svg" />
                </div>
                <span className="si-cap-arrow">→</span>
              </div>
              <span
                className="block text-[8.5px] font-mono font-bold uppercase mb-1"
                style={{ color: '#4A4640', letterSpacing: '0.1em' }}
              >
                {card.category}
              </span>
              <span
                className="block font-semibold leading-snug mb-1.5"
                style={{ fontSize: '12px', color: '#C0BDB5' }}
              >
                {card.title}
              </span>
              <p
                className="leading-relaxed"
                style={{ fontSize: '10.5px', color: '#3E3C38' }}
              >
                {card.desc}
              </p>
            </button>
          );
        })}
      </div>

      {/* AI offline notice */}
      {aiConfigured === false && (
        <div
          className="mt-4 w-full flex items-start gap-2.5 rounded-xl p-3 text-left"
          style={{ background: '#0E0A06', border: '1px solid rgba(212,175,55,0.18)' }}
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#D4AF37]" />
          <div style={{ fontSize: '11px', color: '#B8952C', lineHeight: 1.5 }}>
            <strong className="block mb-0.5" style={{ color: '#D4AF37' }}>Intelligence Provider Offline</strong>
            Set{' '}
            <code style={{ fontFamily: 'monospace', fontSize: '10px', color: '#F5C842' }}>AI_PROVIDER</code>
            {' '}and{' '}
            <code style={{ fontFamily: 'monospace', fontSize: '10px', color: '#F5C842' }}>AI_GEMINI_API_KEY</code>
            {' '}in{' '}
            <code style={{ fontFamily: 'monospace', fontSize: '10px', color: '#F5C842' }}>backend/.env</code>.
          </div>
        </div>
      )}

      {/* Suggested questions */}
      <div className="mt-5 w-full">
        <div className="flex items-center gap-3 mb-3">
          <div className="h-px flex-1" style={{ background: '#141414' }} />
          <span
            className="text-[9px] font-mono uppercase"
            style={{ color: '#2C2A26', letterSpacing: '0.1em' }}
          >
            Suggested questions
          </span>
          <div className="h-px flex-1" style={{ background: '#141414' }} />
        </div>
        <QuickActions
          contextType={contextType}
          findingTitle={findingTitle}
          onAction={onAction}
          disabled={isLoading}
        />
      </div>
    </div>
  );
}
