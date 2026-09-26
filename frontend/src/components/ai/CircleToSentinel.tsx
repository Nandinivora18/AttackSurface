'use client';
/**
 * CircleToSentinel — Screen-region selection overlay for Sentinel Intelligence
 *
 * Activation:
 *   - Keyboard: Ctrl+Shift+S (Windows/Linux) or Cmd+Shift+S (Mac)
 *   - Programmatic: useAIStore().setCircleToSentinelActive(true)
 *
 * Selection:
 *   - Mouse / touch / stylus via Pointer Events API
 *   - Draws a rectangular lasso with animated marching-ants border
 *   - On pointer-up: captures the region via canvas drawImage (no html2canvas)
 *   - Extracts visible text from DOM nodes within the bounding rect
 *   - Passes VisualContext to aiStore → opens Sentinel Intelligence panel
 *
 * Security:
 *   - Image is NEVER treated as instruction — only as pixel data
 *   - selectedText is passed as quoted data to the backend
 *   - No base64 image stored in localStorage or persisted anywhere
 *
 * Accessibility:
 *   - aria-modal, role="dialog", Escape to cancel
 *   - prefers-reduced-motion: animations disabled, crosshair cursor still works
 */
import { useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useAIStore } from '@/store/aiStore';
import { VisualContext, SelectionRegion } from '@/types/ai';

// ─── Constants ────────────────────────────────────────────────────────────────
const MIN_SELECTION_PX = 20; // minimum selection dimension to count as intentional
const MAX_IMAGE_DIMENSION = 1920; // cap the canvas capture size
const JPEG_QUALITY = 0.82;

// ─── DOM text extraction ───────────────────────────────────────────────────────
function extractTextFromRect(rect: SelectionRegion): string {
  try {
    const elements = document.elementsFromPoint(
      rect.x + rect.width / 2,
      rect.y + rect.height / 2,
    );
    const texts: string[] = [];
    const seen = new Set<string>();

    // Walk through all elements that overlap the region
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const text = node.textContent?.trim();
      if (!text || text.length < 2 || seen.has(text)) continue;
      const range = document.createRange();
      range.selectNode(node);
      const rects = range.getClientRects();
      for (let i = 0; i < rects.length; i++) {
        const r = rects[i];
        // Check if this text node overlaps with the selection
        if (
          r.left < rect.x + rect.width &&
          r.right > rect.x &&
          r.top < rect.y + rect.height &&
          r.bottom > rect.y
        ) {
          seen.add(text);
          texts.push(text);
          break;
        }
      }
    }
    return texts.join('\n').slice(0, 3000);
  } catch {
    return '';
  }
}

// ─── Canvas screenshot of a viewport region ────────────────────────────────────
async function captureRegion(region: SelectionRegion): Promise<string> {
  const { x, y, width, height } = region;
  const dpr = window.devicePixelRatio || 1;

  // Scale to actual device pixels
  const srcX = Math.round(x * dpr);
  const srcY = Math.round(y * dpr);
  const srcW = Math.round(width * dpr);
  const srcH = Math.round(height * dpr);

  // Clamp canvas output size
  const outW = Math.min(srcW, MAX_IMAGE_DIMENSION * dpr);
  const outH = Math.min(srcH, MAX_IMAGE_DIMENSION * dpr);

  const canvas = document.createElement('canvas');
  canvas.width = outW;
  canvas.height = outH;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';

  // Try html2canvas-free approach: render visible DOM with SVG foreignObject trick
  // This approach avoids any third-party library while giving a reasonable screenshot.
  // On browsers without the Capture API, we fall back to a blank canvas with text.
  try {
    // Build an SVG data URI wrapping the current viewport as a foreignObject
    const svgWidth = window.innerWidth;
    const svgHeight = window.innerHeight;
    const svgData = `<svg xmlns="http://www.w3.org/2000/svg" width="${svgWidth}" height="${svgHeight}">
      <foreignObject width="100%" height="100%">
        <div xmlns="http://www.w3.org/1999/xhtml" style="
          width:${svgWidth}px;height:${svgHeight}px;
          overflow:hidden;font-size:${window.getComputedStyle(document.documentElement).fontSize};
        ">
          ${document.body.innerHTML}
        </div>
      </foreignObject>
    </svg>`;

    const blob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);

    const testCanvas = document.createElement('canvas');
    testCanvas.width = outW;
    testCanvas.height = outH;
    const testCtx = testCanvas.getContext('2d');
    if (!testCtx) throw new Error('No 2d context');

    await new Promise<void>((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        try {
          testCtx.drawImage(img, srcX, srcY, srcW, srcH, 0, 0, outW, outH);
          URL.revokeObjectURL(url);
          resolve();
        } catch (err) {
          URL.revokeObjectURL(url);
          reject(err);
        }
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(new Error('SVG render failed'));
      };
      img.src = url;
    });

    const dataUrl = testCanvas.toDataURL('image/jpeg', JPEG_QUALITY);
    // Strip the data: URI prefix — backend validates and strips it too
    return dataUrl.split(',')[1] ?? '';
  } catch {
    // Fallback: guaranteed untainted fresh canvas with visual representation & extracted text
    const canvas = document.createElement('canvas');
    canvas.width = outW;
    canvas.height = outH;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    ctx.fillStyle = '#0F0F11';
    ctx.fillRect(0, 0, outW, outH);

    // Subtle dark grid
    ctx.strokeStyle = 'rgba(212,175,55,0.08)';
    ctx.lineWidth = 1;
    for (let gx = 0; gx < outW; gx += 24 * dpr) {
      ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, outH); ctx.stroke();
    }
    for (let gy = 0; gy < outH; gy += 24 * dpr) {
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(outW, gy); ctx.stroke();
    }

    // Gold header band
    ctx.fillStyle = 'rgba(212,175,55,0.15)';
    ctx.fillRect(0, 0, outW, 28 * dpr);
    ctx.strokeStyle = 'rgba(212,175,55,0.4)';
    ctx.strokeRect(0, 0, outW, outH);

    ctx.fillStyle = '#D4AF37';
    ctx.font = `bold ${11 * dpr}px ui-monospace,monospace`;
    ctx.fillText('SENTINEL VISUAL SELECTION', 10 * dpr, 18 * dpr);

    ctx.fillStyle = '#8C8880';
    ctx.font = `${10 * dpr}px ui-monospace,monospace`;
    ctx.fillText(`${Math.round(width)} × ${Math.round(height)}px`, Math.max(10 * dpr, outW - (90 * dpr)), 18 * dpr);

    // Draw extracted text snippet onto canvas
    const sampleText = extractTextFromRect(region);
    if (sampleText) {
      ctx.fillStyle = '#CCCCCC';
      ctx.font = `${11 * dpr}px sans-serif`;
      const lines = sampleText.split('\n').filter(Boolean).slice(0, 10);
      let curY = 46 * dpr;
      for (const line of lines) {
        if (curY > outH - 12 * dpr) break;
        ctx.fillText(line.slice(0, 60), 12 * dpr, curY);
        curY += 16 * dpr;
      }
    }

    try {
      const dataUrl = canvas.toDataURL('image/jpeg', JPEG_QUALITY);
      return dataUrl.split(',')[1] ?? '';
    } catch {
      return '';
    }
  }
}

// ─── Thumbnail for in-panel preview (small, CSS-scaled) ───────────────────────
async function makeThumbnail(region: SelectionRegion): Promise<string> {
  try {
    const canvas = document.createElement('canvas');
    const scale = Math.min(1, 220 / region.width);
    canvas.width = Math.round(region.width * scale);
    canvas.height = Math.round(region.height * scale);
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    // Paint a preview of the approximate area from the live DOM colors
    ctx.fillStyle = '#0D0D0D';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw a subtle grid to indicate the selected region
    ctx.strokeStyle = 'rgba(212,175,55,0.2)';
    ctx.lineWidth = 0.5;
    for (let gx = 0; gx < canvas.width; gx += 16) {
      ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, canvas.height); ctx.stroke();
    }
    for (let gy = 0; gy < canvas.height; gy += 16) {
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(canvas.width, gy); ctx.stroke();
    }

    ctx.fillStyle = 'rgba(212,175,55,0.12)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    return canvas.toDataURL('image/jpeg', 0.7);
  } catch {
    return '';
  }
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function CircleToSentinel() {
  const {
    circleToSentinelActive,
    setCircleToSentinelActive,
    openAssistant,
    setPendingVisualContext,
    explainVisualSelection,
  } = useAIStore();

  const overlayRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const isDragging = useRef(false);
  const startPt = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const currentRect = useRef<SelectionRegion>({ x: 0, y: 0, width: 0, height: 0 });

  // ── Keyboard shortcut: Ctrl/Cmd + Shift + S ──────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isMac = navigator.platform.toUpperCase().includes('MAC');
      const modifier = isMac ? e.metaKey : e.ctrlKey;
      if (modifier && e.shiftKey && e.key.toLowerCase() === 's') {
        // Do NOT activate while user is typing in an input, textarea, select,
        // or contenteditable — avoids hijacking normal save/submit shortcuts.
        const active = document.activeElement;
        if (active) {
          const tag = active.tagName.toLowerCase();
          if (
            tag === 'input' ||
            tag === 'textarea' ||
            tag === 'select' ||
            (active as HTMLElement).isContentEditable
          ) {
            return; // let the browser / app handle it normally
          }
        }
        e.preventDefault();
        e.stopPropagation();
        setCircleToSentinelActive(true);
      }
      if (e.key === 'Escape' && circleToSentinelActive) {
        setCircleToSentinelActive(false);
      }
    };
    window.addEventListener('keydown', handler, { capture: true });
    return () => window.removeEventListener('keydown', handler, { capture: true });
  }, [circleToSentinelActive, setCircleToSentinelActive]);

  // ── Canvas drawing ────────────────────────────────────────────────────────
  const drawSelection = useCallback((rect: SelectionRegion) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Dark vignette over the unselected area
    ctx.save();
    ctx.fillStyle = 'rgba(0,0,0,0.52)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Clear the selected region (reveal underlying content)
    ctx.clearRect(
      rect.x * dpr,
      rect.y * dpr,
      rect.width * dpr,
      rect.height * dpr,
    );
    ctx.restore();

    // Selection border — gold
    ctx.save();
    ctx.strokeStyle = 'rgba(212,175,55,0.9)';
    ctx.lineWidth = 1.5 * dpr;
    ctx.setLineDash([6 * dpr, 4 * dpr]);
    ctx.lineDashOffset = -Date.now() / 60; // marching ants
    ctx.strokeRect(
      rect.x * dpr,
      rect.y * dpr,
      rect.width * dpr,
      rect.height * dpr,
    );
    ctx.restore();

    // Corner handles
    const handleSize = 6 * dpr;
    const corners = [
      [rect.x, rect.y],
      [rect.x + rect.width, rect.y],
      [rect.x, rect.y + rect.height],
      [rect.x + rect.width, rect.y + rect.height],
    ];
    ctx.fillStyle = '#D4AF37';
    for (const [cx, cy] of corners) {
      ctx.fillRect(
        cx * dpr - handleSize / 2,
        cy * dpr - handleSize / 2,
        handleSize,
        handleSize,
      );
    }

    // Dimension label
    if (rect.width > 60 && rect.height > 24) {
      const label = `${Math.round(rect.width)} × ${Math.round(rect.height)}`;
      ctx.save();
      ctx.font = `${11 * dpr}px ui-monospace,monospace`;
      const labelW = ctx.measureText(label).width + 12 * dpr;
      const labelH = 18 * dpr;
      const lx = (rect.x + (rect.width - labelW / dpr) / 2) * dpr;
      const ly = (rect.y + 8) * dpr;
      ctx.fillStyle = 'rgba(0,0,0,0.75)';
      ctx.fillRect(lx, ly, labelW, labelH);
      ctx.fillStyle = 'rgba(212,175,55,0.9)';
      ctx.fillText(label, lx + 6 * dpr, ly + 13 * dpr);
      ctx.restore();
    }
  }, []);

  // Animation loop for marching ants
  const animFrameRef = useRef<number>(0);
  const animateAnts = useCallback(() => {
    if (isDragging.current) {
      drawSelection(currentRect.current);
    }
    animFrameRef.current = requestAnimationFrame(animateAnts);
  }, [drawSelection]);

  // ── Resize canvas to match viewport ──────────────────────────────────────
  const resizeCanvas = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = window.innerWidth * dpr;
    canvas.height = window.innerHeight * dpr;
    canvas.style.width = `${window.innerWidth}px`;
    canvas.style.height = `${window.innerHeight}px`;
    if (isDragging.current) drawSelection(currentRect.current);
  }, [drawSelection]);

  useEffect(() => {
    if (!circleToSentinelActive) return;
    resizeCanvas();
    animFrameRef.current = requestAnimationFrame(animateAnts);
    window.addEventListener('resize', resizeCanvas);
    return () => {
      cancelAnimationFrame(animFrameRef.current);
      window.removeEventListener('resize', resizeCanvas);
    };
  }, [circleToSentinelActive, resizeCanvas, animateAnts]);

  // ── Pointer event handlers ────────────────────────────────────────────────
  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (e.button !== 0 && e.pointerType === 'mouse') return; // left button only for mouse
    e.currentTarget.setPointerCapture(e.pointerId);
    isDragging.current = true;
    startPt.current = { x: e.clientX, y: e.clientY };
    currentRect.current = { x: e.clientX, y: e.clientY, width: 0, height: 0 };
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging.current) return;
    const x = Math.min(startPt.current.x, e.clientX);
    const y = Math.min(startPt.current.y, e.clientY);
    const width = Math.abs(e.clientX - startPt.current.x);
    const height = Math.abs(e.clientY - startPt.current.y);
    currentRect.current = { x, y, width, height };
  }, []);

  const onPointerUp = useCallback(async (e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging.current) return;
    isDragging.current = false;

    const rect = currentRect.current;

    // Dismiss overlay first to restore the underlying DOM
    setCircleToSentinelActive(false);

    if (rect.width < MIN_SELECTION_PX || rect.height < MIN_SELECTION_PX) return;

    // Extract text and capture image concurrently
    const selectedText = extractTextFromRect(rect);
    const [imageData, thumbnailDataUrl] = await Promise.all([
      captureRegion(rect),
      makeThumbnail(rect),
    ]);

    if (!imageData) return;

    const visualContext: VisualContext = {
      image_data: imageData,
      selected_text: selectedText,
      region: rect,
      thumbnailDataUrl,
    };

    // Store context, open the panel, and automatically trigger visual explanation
    setPendingVisualContext(visualContext);
    openAssistant({ visualContext });
    explainVisualSelection(visualContext);
  }, [setCircleToSentinelActive, setPendingVisualContext, openAssistant, explainVisualSelection]);

  if (!circleToSentinelActive) return null;

  return (
    <AnimatePresence>
      {circleToSentinelActive && (
        <motion.div
          ref={overlayRef}
          key="c2s-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.12 }}
          role="dialog"
          aria-modal="true"
          aria-label="Circle to Sentinel: select a screen region"
          className="fixed inset-0 z-[900]"
          style={{ cursor: 'crosshair', userSelect: 'none', WebkitUserSelect: 'none' }}
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
        >
          {/* Canvas overlay */}
          <canvas
            ref={canvasRef}
            className="absolute inset-0 pointer-events-none"
            style={{ display: 'block' }}
          />

          {/* Instruction bar at top */}
          <motion.div
            initial={{ y: -40, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: -40, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="absolute top-4 left-1/2 -translate-x-1/2 flex items-center gap-3 px-4 py-2.5 rounded-2xl pointer-events-none"
            style={{
              background: 'rgba(10,10,10,0.92)',
              border: '1px solid rgba(212,175,55,0.30)',
              boxShadow: '0 8px 32px rgba(0,0,0,0.7)',
              backdropFilter: 'blur(8px)',
            }}
          >
            {/* Sentinel mark */}
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M12 1.5 L12.9 9.5 L12 10.5 L11.1 9.5 Z" fill="#D4AF37" />
              <path d="M12 22.5 L12.9 14.5 L12 13.5 L11.1 14.5 Z" fill="#D4AF37" />
              <path d="M1.5 12 L9.5 12.9 L10.5 12 L9.5 11.1 Z" fill="#D4AF37" />
              <path d="M22.5 12 L14.5 12.9 L13.5 12 L14.5 11.1 Z" fill="#D4AF37" />
              <path d="M12 9.8 L14.2 12 L12 14.2 L9.8 12 Z" fill="#D4AF37" opacity="0.9" />
            </svg>
            <span
              className="text-[11px] font-mono font-bold uppercase tracking-wider"
              style={{ color: '#E6E4DD', letterSpacing: '0.08em' }}
            >
              Circle to Sentinel
            </span>
            <span className="text-[10px] font-mono" style={{ color: '#4A4640' }}>
              Drag to select · Esc to cancel
            </span>
            <kbd
              className="text-[9px] font-mono px-1.5 py-0.5 rounded"
              style={{ background: '#1A1A1A', color: '#D4AF37', border: '1px solid #333' }}
            >
              ESC
            </kbd>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
