'use client';
import { useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Copy, Check, RotateCcw, AlertTriangle, Shield, FileText,
  ChevronDown, ChevronUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { AIMessage } from '@/types/ai';

interface MessageBubbleProps {
  message: AIMessage;
  onRegenerate?: () => void;
  isLast?: boolean;
}

// Shared Sentinel mark for assistant identity
function SentinelMark({ size = 13, error = false }: { size?: number; error?: boolean }) {
  if (error) return <AlertTriangle style={{ width: size, height: size }} className="text-[#F59E0B]" />;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" style={{ display: 'block' }}>
      <circle cx="12" cy="12" r="10.5" stroke="currentColor" strokeWidth="0.5" strokeDasharray="1.5 4" opacity="0.2" />
      <path d="M12 1.5 L12.9 9.5 L12 10.5 L11.1 9.5 Z" fill="currentColor" />
      <path d="M12 22.5 L12.9 14.5 L12 13.5 L11.1 14.5 Z" fill="currentColor" />
      <path d="M1.5 12 L9.5 12.9 L10.5 12 L9.5 11.1 Z" fill="currentColor" />
      <path d="M22.5 12 L14.5 12.9 L13.5 12 L14.5 11.1 Z" fill="currentColor" />
      <path d="M12 9.8 L14.2 12 L12 14.2 L9.8 12 Z" fill="currentColor" opacity="0.85" />
    </svg>
  );
}

export default function MessageBubble({ message, onRegenerate, isLast }: MessageBubbleProps) {
  const [copied, setCopied] = useState(false);
  const [sourcesOpen, setSourcesOpen] = useState(false);

  const isUser = message.role === 'user';
  const isError = message.isError;

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(message.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* clipboard unavailable */ }
  }, [message.content]);

  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch { return ''; }
  };

  // ── Content renderer ──────────────────────────────────────────────────────
  const renderContent = (text: string) => {
    const lines = text.split('\n');
    const result: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      // Fenced code block
      if (line.startsWith('```')) {
        const lang = line.slice(3).trim();
        const codeLines: string[] = [];
        i++;
        while (i < lines.length && !lines[i].startsWith('```')) {
          codeLines.push(lines[i]);
          i++;
        }
        const fullCode = codeLines.join('\n');
        result.push(
          <div key={`code-${i}`} className="my-3 rounded-xl overflow-hidden" style={{ background: '#080808', border: '1px solid #212121' }}>
            <div className="flex items-center justify-between px-3.5 py-1.5" style={{ background: '#0F0F0F', borderBottom: '1px solid #1A1A1A' }}>
              <div className="flex items-center gap-2">
                <div className="flex gap-1">
                  <span className="w-2 h-2 rounded-full" style={{ background: 'rgba(239,68,68,0.5)' }} />
                  <span className="w-2 h-2 rounded-full" style={{ background: 'rgba(245,158,11,0.5)' }} />
                  <span className="w-2 h-2 rounded-full" style={{ background: 'rgba(79,175,114,0.5)' }} />
                </div>
                {lang && <span className="text-[9px] font-mono uppercase" style={{ color: '#4A4640', letterSpacing: '0.1em' }}>{lang}</span>}
              </div>
              <button
                onClick={() => navigator.clipboard.writeText(fullCode)}
                className="flex items-center gap-1 text-[10px] font-mono transition-colors"
                style={{ color: '#4A4640' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#D4AF37'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#4A4640'; }}
              >
                <Copy className="w-3 h-3" /><span>Copy</span>
              </button>
            </div>
            <pre className="p-4 overflow-x-auto text-[11.5px] font-mono leading-relaxed" style={{ color: '#E0DDD5' }}>
              <code>{fullCode}</code>
            </pre>
          </div>,
        );
        i++;
        continue;
      }

      // Blockquote
      if (line.startsWith('> ')) {
        result.push(
          <div key={`bq-${i}`} className="my-2.5 pl-3.5 pr-3 py-2 text-[12px] leading-relaxed" style={{ borderLeft: '2px solid rgba(212,175,55,0.4)', background: 'rgba(212,175,55,0.03)', borderRadius: '0 8px 8px 0', color: '#C8C5BD' }}>
            {renderInline(line.slice(2))}
          </div>,
        );
        i++; continue;
      }

      // Headings
      if (line.startsWith('#### ')) {
        result.push(<h4 key={`h4-${i}`} className="text-[11px] font-semibold mt-3 mb-1 font-mono tracking-wider uppercase" style={{ color: '#D4AF37' }}>{renderInline(line.slice(5))}</h4>);
      } else if (line.startsWith('### ')) {
        result.push(<h3 key={`h3-${i}`} className="text-[11px] font-bold mt-4 mb-1.5 uppercase tracking-widest font-mono" style={{ color: '#E6E4DD' }}>{renderInline(line.slice(4))}</h3>);
      } else if (line.startsWith('## ')) {
        result.push(<h2 key={`h2-${i}`} className="text-[13px] font-bold mt-4 mb-2 pb-1.5" style={{ color: '#F0EDE6', borderBottom: '1px solid #1C1C1C' }}>{renderInline(line.slice(3))}</h2>);
      } else if (line.startsWith('# ')) {
        result.push(<h1 key={`h1-${i}`} className="text-sm font-extrabold mt-4 mb-2" style={{ color: '#F0EDE6' }}>{renderInline(line.slice(2))}</h1>);
      }
      // Bullet
      else if (line.match(/^[\s]*[-*+] /)) {
        const content = line.replace(/^[\s]*[-*+] /, '');
        result.push(
          <div key={`li-${i}`} className="flex items-start gap-2.5 my-1.5">
            <span className="mt-1 flex-shrink-0 text-[8px]" style={{ color: 'rgba(212,175,55,0.45)' }}>◈</span>
            <div className="text-[12px] leading-relaxed" style={{ color: '#D0CEC6' }}>{renderInline(content)}</div>
          </div>,
        );
      }
      // Numbered list
      else if (line.match(/^\d+\. /)) {
        const num = line.match(/^(\d+)\. /)?.[1];
        const content = line.replace(/^\d+\. /, '');
        result.push(
          <div key={`num-${i}`} className="flex items-start gap-2.5 my-1.5">
            <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold flex-shrink-0 mt-0.5" style={{ background: '#141414', border: '1px solid #222222', color: '#D4AF37' }}>{num}</span>
            <div className="text-[12px] leading-relaxed" style={{ color: '#D0CEC6' }}>{renderInline(content)}</div>
          </div>,
        );
      }
      // HR
      else if (line === '---' || line === '***') {
        result.push(<hr key={`hr-${i}`} className="my-3.5" style={{ borderColor: '#1C1C1C' }} />);
      }
      // Empty
      else if (line.trim() === '') {
        result.push(<div key={`sp-${i}`} className="h-1.5" />);
      }
      // Paragraph
      else {
        result.push(
          <p key={`p-${i}`} className="my-1 text-[12px] leading-relaxed" style={{ color: '#D0CEC6' }}>
            {renderInline(line)}
          </p>,
        );
      }
      i++;
    }
    return result;
  };

  const renderInline = (text: string): React.ReactNode => {
    const parts = text.split(
      /(\*\*\[(?:CRITICAL|HIGH|MEDIUM|LOW|INFO|EVIDENCE|CVE|OWASP|REMEDIATION|NOT_VERIFIABLE)\]\*\*|\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g,
    );
    return parts.map((part, idx) => {
      // Severity / tag badges
      const badges: Record<string, { bg: string; color: string; border: string; label: string }> = {
        '**[CRITICAL]**':       { bg: 'rgba(239,68,68,0.12)',    color: '#EF4444', border: 'rgba(239,68,68,0.25)',    label: 'CRITICAL' },
        '**[HIGH]**':           { bg: 'rgba(249,115,22,0.12)',   color: '#F97316', border: 'rgba(249,115,22,0.25)',   label: 'HIGH' },
        '**[MEDIUM]**':         { bg: 'rgba(234,179,8,0.12)',    color: '#EAB308', border: 'rgba(234,179,8,0.25)',    label: 'MEDIUM' },
        '**[LOW]**':            { bg: 'rgba(79,175,114,0.12)',   color: '#4FAF72', border: 'rgba(79,175,114,0.25)',   label: 'LOW' },
        '**[INFO]**':           { bg: 'rgba(107,114,128,0.12)',  color: '#9CA3AF', border: 'rgba(107,114,128,0.25)', label: 'INFO' },
        '**[EVIDENCE]**':       { bg: 'rgba(212,175,55,0.10)',   color: '#D4AF37', border: 'rgba(212,175,55,0.22)',  label: 'EVIDENCE' },
        '**[CVE]**':            { bg: 'rgba(239,68,68,0.08)',    color: '#EF4444', border: 'rgba(239,68,68,0.18)',   label: 'CVE' },
        '**[OWASP]**':          { bg: 'rgba(99,102,241,0.10)',   color: '#818CF8', border: 'rgba(99,102,241,0.20)',  label: 'OWASP' },
        '**[REMEDIATION]**':    { bg: 'rgba(79,175,114,0.08)',   color: '#4FAF72', border: 'rgba(79,175,114,0.18)',  label: 'REMEDIATION' },
        '**[NOT_VERIFIABLE]**': { bg: 'rgba(107,114,128,0.10)', color: '#6B7280', border: 'rgba(107,114,128,0.18)', label: 'NOT VERIFIABLE' },
      };

      if (badges[part]) {
        const b = badges[part];
        return (
          <span key={idx} style={{ display: 'inline-flex', alignItems: 'center', padding: '1px 6px', borderRadius: 4, background: b.bg, color: b.color, border: `1px solid ${b.border}`, fontSize: '9px', fontFamily: 'monospace', fontWeight: 700, margin: '0 2px', verticalAlign: 'middle' }}>
            {b.label}
          </span>
        );
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={idx} style={{ fontWeight: 600, color: '#F0EDE6' }}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('*') && part.endsWith('*')) {
        return <em key={idx} style={{ fontStyle: 'italic', color: 'rgba(212,175,55,0.80)' }}>{part.slice(1, -1)}</em>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={idx} style={{ fontFamily: 'ui-monospace,monospace', fontSize: '11px', background: '#141414', border: '1px solid #222222', padding: '1px 5px', borderRadius: 4, color: '#D4AF37', margin: '0 1px' }}>{part.slice(1, -1)}</code>;
      }
      return part;
    });
  };

  // ── USER MESSAGE ────────────────────────────────────────────────────────────
  if (isUser) {
    return (
      <motion.div
        initial={{ opacity: 0, y: 5 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.16 }}
        className="flex justify-end"
      >
        <div style={{ maxWidth: '85%' }}>
          {/* Visual context thumbnail badge — shown above the message text */}
          {message.visualContext && (
            <div className="flex justify-end mb-1.5">
              <div
                className="flex items-center gap-2 rounded-xl px-2.5 py-1.5"
                style={{
                  background: 'rgba(212,175,55,0.06)',
                  border: '1px solid rgba(212,175,55,0.18)',
                  borderRight: '2px solid rgba(212,175,55,0.35)',
                  borderRadius: '10px 10px 2px 10px',
                }}
              >
                {message.visualContext.thumbnailDataUrl && (
                  <img
                    src={message.visualContext.thumbnailDataUrl}
                    alt="Selected region"
                    className="rounded flex-shrink-0 object-cover"
                    style={{ width: 32, height: 22, border: '1px solid rgba(212,175,55,0.15)' }}
                  />
                )}
                <div>
                  <div className="text-[8px] font-mono font-bold uppercase" style={{ color: 'rgba(212,175,55,0.65)', letterSpacing: '0.1em' }}>
                    Visual Context
                  </div>
                  <div className="text-[9px] font-mono mt-0.5" style={{ color: '#4A4640' }}>
                    {Math.round(message.visualContext.region.width)}×{Math.round(message.visualContext.region.height)}px
                  </div>
                </div>
              </div>
            </div>
          )}
          <div
            className="px-4 py-3 text-[12px] leading-relaxed"
            style={{
              background: 'linear-gradient(135deg, #181818, #141414)',
              border: '1px solid #2A2A2A',
              borderRight: '2px solid rgba(212,175,55,0.5)',
              borderRadius: '14px 14px 4px 14px',
              color: '#E6E4DD',
            }}
          >
            {message.content}
          </div>
          <div className="flex justify-end mt-1 mr-1">
            <span style={{ fontSize: '9px', color: '#2E2C28', fontFamily: 'monospace' }}>
              {formatTime(message.timestamp)}
            </span>
          </div>
        </div>
      </motion.div>
    );
  }

  // ── ASSISTANT MESSAGE ────────────────────────────────────────────────────────
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
      className="flex gap-2.5"
    >
      {/* Avatar */}
      <div
        className="flex-shrink-0 mt-0.5 w-7 h-7 rounded-xl flex items-center justify-center"
        style={{
          background: isError ? 'linear-gradient(145deg, #1A1008, #100806)' : 'linear-gradient(145deg, #1C1808, #0D0B06)',
          border: isError ? '1px solid rgba(239,68,68,0.28)' : '1px solid rgba(212,175,55,0.30)',
          boxShadow: isError ? '0 0 8px rgba(239,68,68,0.08)' : '0 0 10px rgba(212,175,55,0.10)',
          color: isError ? '#F59E0B' : '#D4AF37',
        }}
      >
        <SentinelMark size={13} error={isError} />
      </div>

      <div className="flex-1 min-w-0">
        {/* Identity row */}
        <div className="flex items-center gap-2 mb-2">
          <span style={{ fontSize: '9px', fontFamily: 'monospace', fontWeight: 800, letterSpacing: '0.08em', color: 'rgba(212,175,55,0.60)', textTransform: 'uppercase' }}>
            Sentinel Intelligence
          </span>
          <span style={{ fontSize: '9px', color: '#252320', fontFamily: 'monospace' }}>
            {formatTime(message.timestamp)}
          </span>
          {message.model && (
            <span style={{ fontSize: '9px', color: '#35322C', fontFamily: 'monospace' }}>
              · {message.model}
            </span>
          )}
        </div>

        {/* Content */}
        <div
          className="rounded-2xl rounded-tl-sm px-4 py-3.5"
          style={
            isError
              ? { background: '#100808', border: '1px solid rgba(239,68,68,0.28)', color: '#EF4444', fontSize: '12px', lineHeight: 1.6 }
              : { background: 'linear-gradient(160deg, #111111, #0D0D0D)', border: '1px solid #1C1C1C', color: '#D0CEC6' }
          }
        >
          {renderContent(message.content)}
        </div>

        {/* Footer */}
        <div className="flex flex-wrap items-center justify-between gap-2 mt-2 px-0.5">
          {/* Sources */}
          <div>
            {message.sources && message.sources.length > 0 && (
              <button
                onClick={() => setSourcesOpen(!sourcesOpen)}
                className="flex items-center gap-1.5 px-2 py-1 rounded-lg text-[10px] font-mono font-semibold transition-all"
                style={{ background: '#0E0A06', border: '1px solid rgba(212,175,55,0.22)', color: '#D4AF37' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(212,175,55,0.45)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = 'rgba(212,175,55,0.22)'; }}
              >
                <Shield className="w-2.5 h-2.5" />
                <span>Evidence ({message.sources.length})</span>
                {sourcesOpen ? <ChevronUp className="w-2 h-2" /> : <ChevronDown className="w-2 h-2" />}
              </button>
            )}
          </div>

          {/* Actions */}
          {isError ? (
            isLast && onRegenerate && (
              <div className="flex items-center gap-1">
                <button
                  onClick={onRegenerate}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[10.5px] font-mono font-medium transition-all"
                  style={{
                    background: 'rgba(212,175,55,0.08)',
                    border: '1px solid rgba(212,175,55,0.3)',
                    color: '#D4AF37',
                  }}
                  onMouseEnter={e => {
                    (e.currentTarget as HTMLElement).style.background = 'rgba(212,175,55,0.18)';
                    (e.currentTarget as HTMLElement).style.borderColor = 'rgba(212,175,55,0.6)';
                  }}
                  onMouseLeave={e => {
                    (e.currentTarget as HTMLElement).style.background = 'rgba(212,175,55,0.08)';
                    (e.currentTarget as HTMLElement).style.borderColor = 'rgba(212,175,55,0.3)';
                  }}
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>{message.visualContext ? 'Retry analysis' : 'Retry'}</span>
                </button>
              </div>
            )
          ) : (
            <div className="flex items-center gap-0.5">
              <button
                onClick={handleCopy}
                className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono transition-colors"
                style={{ color: '#3A3730' }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#D4AF37'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#3A3730'; }}
              >
                {copied ? (
                  <><Check className="w-3 h-3 text-[#4FAF72]" /><span style={{ color: '#4FAF72' }}>Copied</span></>
                ) : (
                  <><Copy className="w-3 h-3" /><span>Copy</span></>
                )}
              </button>

              {isLast && onRegenerate && (
                <button
                  onClick={onRegenerate}
                  className="flex items-center gap-1 px-2 py-1 rounded-lg text-[10px] font-mono transition-colors"
                  style={{ color: '#3A3730' }}
                  onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = '#D4AF37'; }}
                  onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = '#3A3730'; }}
                >
                  <RotateCcw className="w-3 h-3" /><span>Retry</span>
                </button>
              )}
            </div>
          )}
        </div>

        {/* Evidence drawer */}
        <AnimatePresence>
          {sourcesOpen && message.sources && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.2 }}
              className="mt-2 overflow-hidden rounded-xl"
              style={{ background: '#090909', border: '1px solid #1A1A1A' }}
            >
              <div className="p-3">
                <div className="flex items-center gap-2 mb-2 pb-2" style={{ borderBottom: '1px solid #141414' }}>
                  <FileText className="w-3 h-3 text-[#D4AF37]" />
                  <span style={{ fontSize: '9px', fontFamily: 'monospace', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', color: '#4A4640' }}>
                    Telemetry Grounding References
                  </span>
                </div>
                <ul className="flex flex-col gap-1">
                  {message.sources.map((src, idx) => (
                    <li
                      key={idx}
                      className="flex items-center gap-2 px-2.5 py-1 rounded"
                      style={{ background: '#0F0F0F', border: '1px solid #181818', fontSize: '10px', fontFamily: 'monospace', color: '#8A8680' }}
                    >
                      <span className="w-1 h-1 rounded-full flex-shrink-0" style={{ background: '#D4AF37' }} />
                      <span className="truncate">{src}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
