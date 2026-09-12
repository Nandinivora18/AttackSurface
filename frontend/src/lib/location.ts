import { Finding } from '@/types';

export interface ResolvedFindingLocation {
  label: string;       // e.g. "Found on", "Domain", "Host", "Exposed resource", "Affected component", "Scope"
  value: string;       // e.g. "https://example.com/phpinfo.php", "https://example.com/", "example.com", "example.com:443", "example.com — Apache 2.4.49"
  type: 'url' | 'endpoint' | 'domain' | 'dns' | 'host' | 'component' | 'domain_scope';
  badge: string;       // e.g. "Specific URL", "Specific Page", "Exposed File", "DNS Domain", "TLS Host", "Component", "Entire Domain"
  isSpecific: boolean; // true if specific location rather than generic domain
}

/**
 * Resolves the most accurate and specific location for a finding based on actual scan data and evidence.
 * Priority order:
 * 1. Exact evidence URL / endpoint returned by detector (e.g. https://example.com/phpinfo.php)
 * 2. Specific affected page/path (e.g. https://example.com/login)
 * 3. Host:Port for TLS findings (e.g. example.com:443)
 * 4. Host/Domain for DNS/Email security findings (e.g. example.com)
 * 5. Component/software for CVE/tech findings (e.g. example.com — Apache 2.4.49)
 * 6. "Entire website / domain" ONLY when detector genuinely operates across domain.
 */
export function resolveFindingLocation(
  finding: any,
  fallbackUrl?: string
): ResolvedFindingLocation {
  if (!finding) {
    return {
      label: 'Scope',
      value: fallbackUrl || 'Entire website / domain',
      type: 'domain_scope',
      badge: 'Entire Domain',
      isSpecific: false,
    };
  }
  const cat = (finding.category || '').toLowerCase();
  const title = (finding.title || '').toLowerCase();
  const ep = (finding.endpoint || '').trim();
  const ev = (finding.evidence || '').trim();
  const cveId = (finding.cve_id || '').trim();

  // Extract hostname / domain from fallbackUrl or endpoint
  const targetStr = fallbackUrl || ep || (finding as any).asset_url || '';
  let hostname = '';
  if (targetStr) {
    try {
      const raw = targetStr.startsWith('http://') || targetStr.startsWith('https://')
        ? targetStr
        : `https://${targetStr}`;
      const urlObj = new URL(raw);
      hostname = urlObj.hostname.toLowerCase();
    } catch {
      hostname = targetStr.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
    }
  }

  // 1. Content Exposure Findings (e.g., phpinfo, .env, backups, git, sensitive comments)
  const isContentExposure =
    cat.includes('exposure') ||
    cat.includes('source') ||
    cat.includes('credential') ||
    title.includes('exposed') ||
    title.includes('phpinfo') ||
    title.includes('sensitive information in html') ||
    title.includes('backup') ||
    title.includes('.env') ||
    title.includes('git') ||
    title.includes('sitemap') ||
    title.includes('admin panel');

  if (isContentExposure) {
    let urlVal = '';
    if (ep && (ep.startsWith('http://') || ep.startsWith('https://'))) {
      urlVal = ep;
    } else if (ev) {
      const match = ev.match(/GET\s+(https?:\/\/[^\s\),]+)/i);
      if (match) {
        urlVal = match[1];
      }
    }
    if (!urlVal && ep && ep.startsWith('/')) {
      const base = fallbackUrl ? fallbackUrl.replace(/\/+$/, '') : (hostname ? `https://${hostname}` : '');
      urlVal = `${base}${ep}`;
    }
    if (!urlVal && fallbackUrl) {
      urlVal = fallbackUrl;
    }

    if (urlVal) {
      return {
        label: 'Exposed resource',
        value: urlVal,
        type: 'url',
        badge: 'Exposed File',
        isSpecific: true,
      };
    }
  }

  // 2. DNS & Email Security Findings (Domain-level by nature)
  const isDns =
    cat.includes('dns') ||
    cat.includes('email') ||
    title.includes('spf') ||
    title.includes('dmarc') ||
    title.includes('dkim') ||
    title.includes('mx record') ||
    title.includes('dnssec');

  if (isDns) {
    let domainVal = hostname;
    if (!domainVal && ep) {
      try {
        domainVal = ep.startsWith('http') ? new URL(ep).hostname : ep;
      } catch {
        domainVal = ep;
      }
    }
    return {
      label: 'Domain',
      value: domainVal || 'Target Domain',
      type: 'dns',
      badge: 'DNS Domain',
      isSpecific: false,
    };
  }

  // 3. SSL / TLS Findings (Host:Port)
  const isSsl =
    cat.includes('ssl') ||
    cat.includes('tls') ||
    title.includes('certificate') ||
    title.includes('cipher') ||
    title.includes('tls version') ||
    title.includes('ssl/tls');

  if (isSsl) {
    let hostVal = '';
    if (ep.includes(':443')) {
      hostVal = ep;
    } else if (hostname) {
      hostVal = `${hostname}:443`;
    } else if (ep) {
      hostVal = ep.includes(':') ? ep : `${ep}:443`;
    } else {
      hostVal = 'Target Host:443';
    }

    return {
      label: 'Host',
      value: hostVal,
      type: 'host',
      badge: 'TLS Host',
      isSpecific: true,
    };
  }

  // 4. CVE / Vulnerable Component Findings
  const isCve = cat.includes('cve') || !!cveId || title.includes('cve-');
  if (isCve) {
    let comp = '';
    if (title.includes(' — ')) {
      comp = title.split(' — ')[0].trim();
    } else if (ev.toLowerCase().includes('detected ')) {
      const match = ev.match(/detected\s+([^|,\n]+)/i);
      if (match) comp = match[1].trim();
    }

    let locVal = '';
    if (comp && hostname) {
      locVal = `${hostname} — ${comp}`;
    } else if (comp) {
      locVal = comp;
    } else if (hostname) {
      locVal = `${hostname} — ${cveId || 'Vulnerable Component'}`;
    } else {
      locVal = ep || cveId || 'Software Component';
    }

    return {
      label: 'Affected component',
      value: locVal,
      type: 'component',
      badge: 'Component',
      isSpecific: true,
    };
  }

  // 5. HTTP Header / Cookie / Technology / General Web Findings
  if (ep && (ep.startsWith('http://') || ep.startsWith('https://'))) {
    let isSpecificPage = false;
    try {
      const parsed = new URL(ep);
      isSpecificPage = parsed.pathname.length > 1 && parsed.pathname !== '/';
    } catch {
      isSpecificPage = false;
    }

    return {
      label: 'Found on',
      value: ep,
      type: 'url',
      badge: isSpecificPage ? 'Specific Page' : 'Specific URL',
      isSpecific: true,
    };
  }

  if (fallbackUrl && (fallbackUrl.startsWith('http://') || fallbackUrl.startsWith('https://'))) {
    let isSpecificPage = false;
    try {
      const parsed = new URL(fallbackUrl);
      isSpecificPage = parsed.pathname.length > 1 && parsed.pathname !== '/';
    } catch {
      isSpecificPage = false;
    }

    return {
      label: 'Found on',
      value: fallbackUrl,
      type: 'url',
      badge: isSpecificPage ? 'Specific Page' : 'Specific URL',
      isSpecific: true,
    };
  }

  if (hostname) {
    return {
      label: 'Domain',
      value: hostname,
      type: 'domain',
      badge: 'Domain',
      isSpecific: false,
    };
  }

  // 6. Domain-wide Fallback
  return {
    label: 'Scope',
    value: 'Entire website / domain',
    type: 'domain_scope',
    badge: 'Entire Domain',
    isSpecific: false,
  };
}
