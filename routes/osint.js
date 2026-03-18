const express = require('express');
const axios = require('axios');
const NodeCache = require('node-cache');

const router = express.Router();
const cache = new NodeCache({ stdTTL: 300 }); // 5 min cache

// ─── IP LOOKUP ───────────────────────────────────────────────────────────────
router.post('/ip-lookup', async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP address required' });

  const cacheKey = `ip_${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const [geoRes, abuseRes] = await Promise.allSettled([
      axios.get(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query`),
      axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
        headers: { 'Key': process.env.ABUSEIPDB_KEY || 'demo', 'Accept': 'application/json' }
      }).catch(() => null)
    ]);

    const geo = geoRes.status === 'fulfilled' ? geoRes.value.data : {};
    const abuse = abuseRes.status === 'fulfilled' && abuseRes.value ? abuseRes.value.data : null;

    const result = {
      ip,
      geo: {
        country: geo.country || 'Unknown',
        countryCode: geo.countryCode || '??',
        region: geo.regionName || 'Unknown',
        city: geo.city || 'Unknown',
        lat: geo.lat || 0,
        lon: geo.lon || 0,
        timezone: geo.timezone || 'Unknown',
        isp: geo.isp || 'Unknown',
        org: geo.org || 'Unknown',
        asn: geo.as || 'Unknown',
        isProxy: geo.proxy || false,
        isHosting: geo.hosting || false,
        isMobile: geo.mobile || false
      },
      abuse: abuse ? {
        abuseScore: abuse.data?.abuseConfidenceScore || 0,
        totalReports: abuse.data?.totalReports || 0,
        lastReported: abuse.data?.lastReportedAt || null,
        isTor: abuse.data?.isTor || false
      } : { note: 'AbuseIPDB key not configured - add ABUSEIPDB_KEY env var' },
      riskLevel: geo.proxy ? 'HIGH' : geo.hosting ? 'MEDIUM' : 'LOW',
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Lookup failed', details: err.message });
  }
});

// ─── WHOIS LOOKUP ────────────────────────────────────────────────────────────
router.post('/whois', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });

  const cacheKey = `whois_${domain}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const response = await axios.get(`https://rdap.org/domain/${domain}`);
    const data = response.data;

    const getEvent = (type) => {
      const ev = (data.events || []).find(e => e.eventAction === type);
      return ev ? ev.eventDate : 'Unknown';
    };

    const getNameservers = () => {
      return (data.nameservers || []).map(ns => ns.ldhName || ns.unicodeName || '').filter(Boolean);
    };

    const getEntities = () => {
      return (data.entities || []).map(e => ({
        role: (e.roles || []).join(', '),
        name: e.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Private',
        email: e.vcardArray?.[1]?.find(v => v[0] === 'email')?.[3] || null
      }));
    };

    const result = {
      domain: domain,
      status: (data.status || []).join(', '),
      registered: getEvent('registration'),
      updated: getEvent('last changed'),
      expires: getEvent('expiration'),
      nameservers: getNameservers(),
      entities: getEntities(),
      handle: data.handle || 'Unknown',
      raw: data,
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'WHOIS lookup failed', details: err.message });
  }
});

// ─── DNS LOOKUP ──────────────────────────────────────────────────────────────
router.post('/dns', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });

  const cacheKey = `dns_${domain}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
    const results = {};

    const lookups = recordTypes.map(type =>
      axios.get(`https://dns.google/resolve?name=${domain}&type=${type}`)
        .then(r => { results[type] = (r.data.Answer || []).map(a => a.data); })
        .catch(() => { results[type] = []; })
    );

    await Promise.all(lookups);

    const result = {
      domain,
      records: results,
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'DNS lookup failed', details: err.message });
  }
});

// ─── SUBDOMAIN ENUMERATION ───────────────────────────────────────────────────
router.post('/subdomains', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });

  const cacheKey = `sub_${domain}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const response = await axios.get(`https://crt.sh/?q=%.${domain}&output=json`, {
      timeout: 15000
    });

    const entries = response.data || [];
    const subdomains = [...new Set(
      entries
        .map(e => e.name_value)
        .join('\n')
        .split('\n')
        .map(s => s.trim().toLowerCase())
        .filter(s => s.endsWith(domain) && s !== domain && !s.includes('*'))
    )].sort();

    const result = {
      domain,
      count: subdomains.length,
      subdomains: subdomains.slice(0, 200),
      source: 'crt.sh (Certificate Transparency)',
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Subdomain enumeration failed', details: err.message });
  }
});

// ─── EMAIL OSINT ─────────────────────────────────────────────────────────────
router.post('/email', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email address required' });

  const cacheKey = `email_${email}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const domain = email.split('@')[1];
    const [mxRes, breachRes] = await Promise.allSettled([
      axios.get(`https://dns.google/resolve?name=${domain}&type=MX`),
      axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}`, {
        headers: {
          'hibp-api-key': process.env.HIBP_KEY || '',
          'User-Agent': 'OSINT-Platform'
        }
      }).catch(e => ({ status: e.response?.status, data: null }))
    ]);

    const mxRecords = mxRes.status === 'fulfilled'
      ? (mxRes.value.data.Answer || []).map(a => a.data)
      : [];

    let breachData = null;
    if (breachRes.status === 'fulfilled') {
      if (Array.isArray(breachRes.value.data)) {
        breachData = breachRes.value.data.map(b => ({
          name: b.Name,
          domain: b.Domain,
          breachDate: b.BreachDate,
          pwnCount: b.PwnCount
        }));
      } else if (breachRes.value.status === 404) {
        breachData = [];
      }
    }

    const result = {
      email,
      domain,
      mxRecords,
      breaches: breachData,
      breachNote: !process.env.HIBP_KEY ? 'Add HIBP_KEY env var for breach data' : null,
      domainValid: mxRecords.length > 0,
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Email OSINT failed', details: err.message });
  }
});

// ─── USERNAME RECON ───────────────────────────────────────────────────────────
router.post('/username', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Username required' });

  const PLATFORMS = [
    { name: 'GitHub', url: `https://github.com/${username}`, api: `https://api.github.com/users/${username}` },
    { name: 'Twitter/X', url: `https://twitter.com/${username}`, api: null },
    { name: 'Reddit', url: `https://reddit.com/user/${username}`, api: `https://www.reddit.com/user/${username}/about.json` },
    { name: 'Instagram', url: `https://instagram.com/${username}`, api: null },
    { name: 'TikTok', url: `https://tiktok.com/@${username}`, api: null },
    { name: 'LinkedIn', url: `https://linkedin.com/in/${username}`, api: null },
    { name: 'YouTube', url: `https://youtube.com/@${username}`, api: null },
    { name: 'Twitch', url: `https://twitch.tv/${username}`, api: `https://api.twitch.tv/helix/users?login=${username}` },
    { name: 'Steam', url: `https://steamcommunity.com/id/${username}`, api: null },
    { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${username}`, api: `https://hacker-news.firebaseio.com/v0/user/${username}.json` },
    { name: 'Dev.to', url: `https://dev.to/${username}`, api: `https://dev.to/api/users/by_username?url=${username}` },
    { name: 'GitLab', url: `https://gitlab.com/${username}`, api: `https://gitlab.com/api/v4/users?username=${username}` },
    { name: 'Medium', url: `https://medium.com/@${username}`, api: null },
    { name: 'Pinterest', url: `https://pinterest.com/${username}`, api: null },
    { name: 'Keybase', url: `https://keybase.io/${username}`, api: `https://keybase.io/_/api/1.0/user/lookup.json?usernames=${username}` }
  ];

  const results = [];

  const checks = PLATFORMS.map(async (platform) => {
    try {
      if (platform.api) {
        const r = await axios.get(platform.api, {
          timeout: 5000,
          headers: { 'User-Agent': 'OSINT-Platform/1.0' },
          validateStatus: s => s < 500
        });
        const found = r.status === 200 && r.data && JSON.stringify(r.data) !== 'null';
        results.push({
          platform: platform.name,
          url: platform.url,
          found,
          status: found ? 'FOUND' : 'NOT FOUND'
        });
      } else {
        const r = await axios.get(platform.url, {
          timeout: 5000,
          headers: { 'User-Agent': 'Mozilla/5.0' },
          validateStatus: s => s < 500,
          maxRedirects: 3
        });
        const found = r.status === 200;
        results.push({
          platform: platform.name,
          url: platform.url,
          found,
          status: found ? 'FOUND' : 'NOT FOUND'
        });
      }
    } catch {
      results.push({ platform: platform.name, url: platform.url, found: false, status: 'ERROR' });
    }
  });

  await Promise.all(checks);
  results.sort((a, b) => b.found - a.found);

  res.json({
    username,
    found: results.filter(r => r.found).length,
    total: results.length,
    results,
    timestamp: new Date().toISOString()
  });
});

// ─── THREAT INTEL ────────────────────────────────────────────────────────────
router.post('/threat-intel', async (req, res) => {
  const { indicator, type } = req.body;
  if (!indicator) return res.status(400).json({ error: 'Indicator required' });

  const cacheKey = `threat_${type}_${indicator}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    const sources = [];

    // Check AlienVault OTX (free)
    try {
      const endpoint = type === 'ip'
        ? `https://otx.alienvault.com/api/v1/indicators/IPv4/${indicator}/general`
        : `https://otx.alienvault.com/api/v1/indicators/domain/${indicator}/general`;

      const r = await axios.get(endpoint, {
        headers: { 'X-OTX-API-KEY': process.env.OTX_KEY || '' },
        timeout: 8000
      });
      sources.push({
        source: 'AlienVault OTX',
        pulseCount: r.data.pulse_info?.count || 0,
        reputation: r.data.reputation || 0,
        malicious: (r.data.pulse_info?.count || 0) > 0,
        tags: r.data.pulse_info?.pulses?.slice(0, 3).map(p => p.name) || []
      });
    } catch {
      sources.push({ source: 'AlienVault OTX', note: 'Add OTX_KEY env var for threat intel' });
    }

    // VirusTotal
    if (process.env.VT_KEY) {
      try {
        const vtType = type === 'ip' ? 'ip_addresses' : 'domains';
        const r = await axios.get(`https://www.virustotal.com/api/v3/${vtType}/${indicator}`, {
          headers: { 'x-apikey': process.env.VT_KEY },
          timeout: 8000
        });
        const stats = r.data.data?.attributes?.last_analysis_stats || {};
        sources.push({
          source: 'VirusTotal',
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0
        });
      } catch {
        sources.push({ source: 'VirusTotal', note: 'VT_KEY env var needed' });
      }
    }

    const result = {
      indicator,
      type,
      sources,
      overallRisk: sources.some(s => s.malicious === true || s.malicious > 0) ? 'MALICIOUS' : 'CLEAN',
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Threat intel lookup failed', details: err.message });
  }
});

// ─── PORT SCANNER (passive via Shodan) ───────────────────────────────────────
router.post('/port-scan', async (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.status(400).json({ error: 'IP required' });

  const cacheKey = `ports_${ip}`;
  const cached = cache.get(cacheKey);
  if (cached) return res.json({ ...cached, cached: true });

  try {
    let shodanData = null;

    if (process.env.SHODAN_KEY) {
      try {
        const r = await axios.get(`https://api.shodan.io/shodan/host/${ip}?key=${process.env.SHODAN_KEY}`);
        shodanData = {
          ports: r.data.ports || [],
          os: r.data.os || 'Unknown',
          hostnames: r.data.hostnames || [],
          vulns: r.data.vulns ? Object.keys(r.data.vulns) : [],
          services: (r.data.data || []).map(s => ({
            port: s.port,
            transport: s.transport,
            product: s.product || '',
            version: s.version || '',
            banner: s.banner?.substring(0, 100) || ''
          }))
        };
      } catch { }
    }

    const result = {
      ip,
      shodan: shodanData,
      note: !process.env.SHODAN_KEY ? 'Add SHODAN_KEY env var for passive port scanning via Shodan' : null,
      warning: 'This tool uses passive scanning only (Shodan data). Active scanning requires target authorization.',
      timestamp: new Date().toISOString()
    };

    cache.set(cacheKey, result);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Port scan failed', details: err.message });
  }
});

// ─── DARK WEB MONITOR ────────────────────────────────────────────────────────
router.post('/darkweb', async (req, res) => {
  const { query, type } = req.body;
  if (!query) return res.status(400).json({ error: 'Search query required' });

  // Simulated response (real dark web monitoring requires paid services like Flare/Recorded Future)
  const result = {
    query,
    type: type || 'keyword',
    note: 'Dark web monitoring requires integration with services like Flare.io, Recorded Future, or DarkOwl. Configure DARKWEB_API_KEY env var.',
    mockResults: [
      {
        source: 'Demo: Paste Site',
        date: '2024-01-15',
        snippet: `Reference to "${query}" found in leaked data dump`,
        risk: 'HIGH',
        url: '[redacted]'
      },
      {
        source: 'Demo: Forum',
        date: '2024-02-03',
        snippet: `Credential matching "${query}" domain pattern`,
        risk: 'CRITICAL',
        url: '[redacted]'
      }
    ],
    disclaimer: 'Results above are DEMO DATA for illustration. Real monitoring requires API subscription.',
    timestamp: new Date().toISOString()
  };

  res.json(result);
});

// ─── ACTIVITY LOG ────────────────────────────────────────────────────────────
const activityLog = [];

router.post('/log', (req, res) => {
  const { action, target, tool } = req.body;
  activityLog.unshift({
    user: req.user.username,
    team: req.user.team,
    action,
    target,
    tool,
    timestamp: new Date().toISOString()
  });
  if (activityLog.length > 100) activityLog.pop();
  res.json({ ok: true });
});

router.get('/activity', (req, res) => {
  const userLog = req.user.role === 'admin'
    ? activityLog
    : activityLog.filter(e => e.user === req.user.username);
  res.json(userLog.slice(0, 50));
});

module.exports = router;

// ─── SSL ANALYZER ─────────────────────────────────────────────────────────────
router.post('/ssl', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required' });
  try {
    const r = await axios.get(`https://api.ssllabs.com/api/v3/analyze?host=${domain}&fromCache=on&all=done`, { timeout: 15000 });
    const ep = r.data?.endpoints?.[0];
    const cert = ep?.details?.cert;
    if (!cert) {
      return res.json({ domain, error: 'SSL analysis pending or unavailable', note: 'Try again in 60 seconds - SSL Labs may be analyzing the host', timestamp: new Date().toISOString() });
    }
    const now = Date.now();
    const validTo = new Date(cert.notAfter);
    const daysRemaining = Math.floor((validTo - now) / (1000*60*60*24));
    res.json({
      domain, expired: daysRemaining < 0,
      cert: {
        subject: cert.subject, issuer: cert.issuerLabel,
        validFrom: new Date(cert.notBefore).toLocaleDateString(),
        validTo: validTo.toLocaleDateString(),
        daysRemaining, protocol: ep.protocol || 'TLS',
        keyBits: cert.keyAlg + ' ' + cert.keySize + ' bits',
        sans: cert.altNames || []
      },
      grade: ep.grade || 'N/A',
      timestamp: new Date().toISOString()
    });
  } catch(e) {
    res.json({ domain, error: 'SSL check failed - try again', note: e.message, timestamp: new Date().toISOString() });
  }
});

// ─── NETWORK INTEL ────────────────────────────────────────────────────────────
router.post('/network', async (req, res) => {
  const { query, type } = req.body;
  if (!query) return res.status(400).json({ error: 'Query required' });
  try {
    const asn = type === 'asn' ? query.replace(/^AS/i,'') : null;
    const url = asn
      ? `https://api.bgpview.io/asn/${asn}`
      : `https://api.bgpview.io/ip/${query}`;
    const r = await axios.get(url, { timeout: 10000 });
    const d = r.data?.data || {};
    if (asn) {
      const prefR = await axios.get(`https://api.bgpview.io/asn/${asn}/prefixes`, { timeout: 10000 }).catch(()=>null);
      const prefixes = prefR?.data?.data?.ipv4_prefixes || [];
      res.json({ query, type: 'asn', asn: 'AS'+asn, name: d.name, description: d.description_short, country: d.country_code, org: d.org?.name, prefixes: prefixes.map(p=>({prefix:p.prefix})), timestamp: new Date().toISOString() });
    } else {
      const pfx = d.prefixes?.[0] || {};
      res.json({ query, type: 'ip', asn: pfx.asn?.asn ? 'AS'+pfx.asn.asn : 'Unknown', name: pfx.asn?.name || 'Unknown', description: pfx.description || pfx.name, country: pfx.country_code, org: pfx.asn?.org, prefix: pfx.prefix, timestamp: new Date().toISOString() });
    }
  } catch(e) {
    res.json({ query, type, error: 'Network lookup failed', note: e.message, timestamp: new Date().toISOString() });
  }
});
