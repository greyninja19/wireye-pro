#!/usr/bin/env python3
"""
WireEye Pro — Automated Report Generator
Produces professional HTML forensic reports from PCAP analysis results.
"""

from datetime import datetime
import json, os

SEVERITY_COLOR = {
    'CRITICAL': '#f85149',
    'HIGH':     '#f0883e',
    'MEDIUM':   '#d29922',
    'LOW':      '#58a6ff',
    'INFO':     '#8b949e',
}

SEVERITY_BADGE = {
    'CRITICAL': 'background:#3d0a0a;color:#f85149;border:1px solid #f8514940',
    'HIGH':     'background:#2d1400;color:#f0883e;border:1px solid #f0883e40',
    'MEDIUM':   'background:#2d2200;color:#d29922;border:1px solid #d2992240',
    'LOW':      'background:#0d2240;color:#58a6ff;border:1px solid #58a6ff40',
}


def bytes_human(b):
    for unit in ['B','KB','MB','GB']:
        if b < 1024: return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} TB'


def build_html_report(data: dict) -> str:
    meta   = data.get('meta', {})
    risk   = data.get('risk', {})
    protos = data.get('protocols', [])
    threats= data.get('threats', [])
    dns    = data.get('dns', {})
    http   = data.get('http', {})
    arp    = data.get('arp', {})
    convs  = data.get('conversations', [])
    endpts = data.get('endpoints', [])
    top_src= data.get('top_src_ips', [])
    top_dst_ports = data.get('top_dst_ports', [])
    susp_ports    = data.get('suspicious_ports', [])

    score = risk.get('score', 0)
    score_color = '#3fb950' if score < 30 else '#d29922' if score < 60 else '#f0883e' if score < 80 else '#f85149'
    risk_label  = risk.get('label', '–')

    # Protocol rows
    proto_rows = ''
    for p in protos[:10]:
        bar = min(int(p['pct']), 100)
        proto_rows += f"""
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#e6edf3">{p['name']}</td>
          <td style="padding:6px 10px;color:#8b949e">{p['count']:,}</td>
          <td style="padding:6px 10px">
            <div style="background:#1c2330;border-radius:3px;height:8px;width:160px">
              <div style="background:#58a6ff;height:8px;width:{bar}%;border-radius:3px"></div>
            </div>
          </td>
          <td style="padding:6px 10px;color:#58a6ff">{p['pct']}%</td>
        </tr>"""

    # Threat rows
    threat_rows = ''
    if threats:
        for t in threats:
            sev = t.get('severity','INFO')
            badge_style = SEVERITY_BADGE.get(sev, '')
            threat_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:8px 10px">
            <span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;{badge_style}">{sev}</span>
          </td>
          <td style="padding:8px 10px;color:#e6edf3;font-weight:600">{t.get('label','')}</td>
          <td style="padding:8px 10px;color:#8b949e;font-family:monospace;font-size:12px">{t.get('src','')}</td>
          <td style="padding:8px 10px;color:#8b949e;font-size:13px">{t.get('detail','')}</td>
        </tr>"""
    else:
        threat_rows = '<tr><td colspan="4" style="padding:16px;text-align:center;color:#3fb950">✅ No threats detected</td></tr>'

    # Top IPs
    ip_rows = ''
    for e in top_src[:10]:
        tag = '🏠' if e['private'] else '🌐'
        ip_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:6px 10px;font-family:monospace;color:#58a6ff">{tag} {e['ip']}</td>
          <td style="padding:6px 10px;color:#3fb950">{e['count']:,}</td>
          <td style="padding:6px 10px;color:#8b949e">{'Internal' if e['private'] else 'External'}</td>
        </tr>"""

    # Port rows
    port_rows = ''
    for p in top_dst_ports[:15]:
        warn = '⚠️' if p['service'] not in ('HTTP','HTTPS','SSH','SMTP','DNS','NTP','Unknown') else ''
        port_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:6px 10px;font-family:monospace;color:#e6edf3">{p['port']}</td>
          <td style="padding:6px 10px;color:#8b949e">{p['service']} {warn}</td>
          <td style="padding:6px 10px;color:#3fb950">{p['count']:,}</td>
        </tr>"""

    # DNS rows
    dns_rows = ''
    for d in dns.get('top_domains', [])[:15]:
        flag = '⚠️' if len(d['domain']) > 40 else ''
        dns_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:6px 10px;font-family:monospace;color:#bc8cff;font-size:12px">{d['domain'][:60]} {flag}</td>
          <td style="padding:6px 10px;color:#3fb950">{d['count']}</td>
        </tr>"""

    # Conversation rows
    conv_rows = ''
    for c in convs[:15]:
        ports_str = ', '.join(str(p) for p in c.get('ports', [])[:6])
        conv_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:6px 10px;font-family:monospace;font-size:12px;color:#58a6ff">{c['a']}</td>
          <td style="padding:6px 8px;color:#8b949e;text-align:center">↔</td>
          <td style="padding:6px 10px;font-family:monospace;font-size:12px;color:#f0883e">{c['b']}</td>
          <td style="padding:6px 10px;color:#8b949e">{c['packets']:,}</td>
          <td style="padding:6px 10px;color:#3fb950">{bytes_human(c['bytes'])}</td>
          <td style="padding:6px 10px;color:#8b949e;font-size:12px">{ports_str}</td>
        </tr>"""

    # Suspicious ports
    susp_rows = ''
    for sp in susp_ports[:10]:
        susp_rows += f"""
        <tr style="border-bottom:1px solid #21262d">
          <td style="padding:6px 10px;font-family:monospace;color:#f85149">{sp['port']}</td>
          <td style="padding:6px 10px;color:#f0883e">{sp['label']}</td>
          <td style="padding:6px 10px;color:#d29922">{sp['count']}</td>
        </tr>"""
    if not susp_rows:
        susp_rows = '<tr><td colspan="3" style="padding:12px;color:#3fb950;text-align:center">None detected</td></tr>'

    # ARP rows
    arp_spoof_section = ''
    if arp.get('spoof_events'):
        rows = ''
        for s in arp.get('spoof_events', []):
            rows += f"""
            <tr style="border-bottom:1px solid #21262d">
              <td style="padding:6px 10px;font-family:monospace;color:#f85149">{s['ip']}</td>
              <td style="padding:6px 10px;font-family:monospace;color:#8b949e;font-size:12px">{s['old_mac']}</td>
              <td style="padding:6px 10px;color:#8b949e;text-align:center">→</td>
              <td style="padding:6px 10px;font-family:monospace;color:#f85149;font-size:12px">{s['new_mac']}</td>
            </tr>"""
        arp_spoof_section = f"""
        <div style="margin-bottom:2rem">
          <h3 style="color:#f85149;margin-bottom:12px;font-size:14px;text-transform:uppercase;letter-spacing:.06em">🚨 ARP Spoofing Events</h3>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="background:#1c2330">
              <th style="padding:8px 10px;text-align:left;color:#8b949e;font-size:12px">IP</th>
              <th style="padding:8px 10px;text-align:left;color:#8b949e;font-size:12px">Old MAC</th>
              <th style="padding:8px 10px"></th>
              <th style="padding:8px 10px;text-align:left;color:#8b949e;font-size:12px">New MAC</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    generated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WireEye Forensic Report — {meta.get('filename','')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap');
  * {{ box-sizing:border-box;margin:0;padding:0 }}
  body {{ background:#0d1117;color:#e6edf3;font-family:'Syne',sans-serif;line-height:1.6 }}
  .page {{ max-width:1100px;margin:0 auto;padding:2rem 1.5rem }}
  .cover {{ background:linear-gradient(135deg,#161b22 0%,#0d1117 100%);border:1px solid #30363d;border-radius:12px;padding:2.5rem;margin-bottom:2rem;position:relative;overflow:hidden }}
  .cover::before {{ content:'';position:absolute;top:-60px;right:-60px;width:200px;height:200px;background:radial-gradient(circle,#58a6ff20,transparent 70%);border-radius:50% }}
  .cover-title {{ font-size:2rem;font-weight:800;letter-spacing:-1px;margin-bottom:4px }}
  .cover-sub {{ color:#8b949e;font-size:14px;margin-bottom:1.5rem }}
  .meta-grid {{ display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:1.5rem }}
  .meta-cell {{ background:#0d1117;border:1px solid #21262d;border-radius:8px;padding:12px }}
  .meta-cell .k {{ font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em }}
  .meta-cell .v {{ font-size:14px;font-weight:600;font-family:'JetBrains Mono',monospace;margin-top:3px }}
  .risk-banner {{ background:{score_color}18;border:1px solid {score_color}50;border-radius:12px;padding:1.5rem 2rem;margin-bottom:2rem;display:flex;align-items:center;gap:2rem }}
  .risk-score {{ font-size:3.5rem;font-weight:800;color:{score_color};line-height:1 }}
  .risk-label {{ font-size:1.3rem;font-weight:700;color:{score_color} }}
  .risk-sub {{ font-size:13px;color:#8b949e;margin-top:4px }}
  .section {{ background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.5rem;margin-bottom:1.5rem }}
  .section-title {{ font-size:12px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:1rem;padding-bottom:8px;border-bottom:1px solid #21262d }}
  table {{ width:100%;border-collapse:collapse }}
  th {{ padding:8px 10px;text-align:left;color:#8b949e;font-size:12px;font-weight:600;background:#1c2330 }}
  .footer {{ text-align:center;color:#8b949e;font-size:12px;padding:2rem 0 }}
  @media print {{ body {{ background:white;color:black }} .cover {{ background:#f6f8fa }} }}
</style>
</head>
<body>
<div class="page">

  <!-- Cover -->
  <div class="cover">
    <div class="cover-title">🔬 WireEye Forensic Report</div>
    <div class="cover-sub">PCAP Network Traffic Analysis — Generated {generated_at}</div>
    <div class="meta-grid">
      <div class="meta-cell"><div class="k">Capture file</div><div class="v" style="color:#58a6ff">{meta.get('filename','–')}</div></div>
      <div class="meta-cell"><div class="k">File size</div><div class="v">{bytes_human(meta.get('file_size',0))}</div></div>
      <div class="meta-cell"><div class="k">Total packets</div><div class="v">{meta.get('total_packets',0):,}</div></div>
      <div class="meta-cell"><div class="k">Total bytes</div><div class="v">{bytes_human(meta.get('total_bytes',0))}</div></div>
      <div class="meta-cell"><div class="k">Capture start</div><div class="v" style="font-size:12px">{meta.get('capture_start','–')}</div></div>
      <div class="meta-cell"><div class="k">Duration</div><div class="v">{meta.get('duration_sec',0):.1f}s</div></div>
    </div>
  </div>

  <!-- Risk Banner -->
  <div class="risk-banner">
    <div class="risk-score">{score}</div>
    <div>
      <div class="risk-label">{risk_label}</div>
      <div class="risk-sub">{risk.get('threat_count',0)} threat type(s) detected · Risk score out of 100</div>
    </div>
  </div>

  <!-- Threats -->
  <div class="section">
    <div class="section-title">⚠ Threat Intelligence</div>
    <table>
      <thead><tr><th>Severity</th><th>Attack Type</th><th>Source</th><th>Detail</th></tr></thead>
      <tbody>{threat_rows}</tbody>
    </table>
  </div>

  <!-- Protocols + Ports -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">
    <div class="section" style="margin-bottom:0">
      <div class="section-title">📡 Protocol Breakdown</div>
      <table><tbody>{proto_rows}</tbody></table>
    </div>
    <div class="section" style="margin-bottom:0">
      <div class="section-title">🔌 Top Destination Ports</div>
      <table>
        <thead><tr><th>Port</th><th>Service</th><th>Packets</th></tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Top IPs + Suspicious Ports -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem">
    <div class="section" style="margin-bottom:0">
      <div class="section-title">📤 Top Source IPs</div>
      <table>
        <thead><tr><th>IP Address</th><th>Packets Sent</th><th>Type</th></tr></thead>
        <tbody>{ip_rows}</tbody>
      </table>
    </div>
    <div class="section" style="margin-bottom:0">
      <div class="section-title">🚨 Suspicious Port Activity</div>
      <table>
        <thead><tr><th>Port</th><th>Known For</th><th>Count</th></tr></thead>
        <tbody>{susp_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Conversations -->
  <div class="section">
    <div class="section-title">💬 Top Conversations</div>
    <table>
      <thead><tr><th>Source</th><th></th><th>Destination</th><th>Packets</th><th>Data</th><th>Ports</th></tr></thead>
      <tbody>{conv_rows}</tbody>
    </table>
  </div>

  <!-- DNS -->
  <div class="section">
    <div class="section-title">🌐 DNS Activity</div>
    <p style="color:#8b949e;font-size:13px;margin-bottom:12px">
      Total queries: {len(dns.get('queries',[]))} &nbsp;·&nbsp; Unique domains: {len(dns.get('top_domains',[]))}
    </p>
    <table>
      <thead><tr><th>Domain Queried</th><th>Count</th></tr></thead>
      <tbody>{dns_rows}</tbody>
    </table>
  </div>

  <!-- ARP -->
  {arp_spoof_section}

  <!-- Footer -->
  <div class="footer">
    Generated by WireEye Pro · {generated_at} · For authorised forensic use only
  </div>
</div>
</body>
</html>"""

    return html


def build_text_report(data: dict) -> str:
    meta   = data.get('meta', {})
    risk   = data.get('risk', {})
    threats= data.get('threats', [])
    protos = data.get('protocols', [])
    top_src= data.get('top_src_ips', [])
    dns    = data.get('dns', {})

    lines = [
        '=' * 65,
        '  WIREEYE PRO — FORENSIC ANALYSIS REPORT',
        f'  Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}',
        '=' * 65,
        '',
        f'  File      : {meta.get("filename","–")}',
        f'  Packets   : {meta.get("total_packets",0):,}',
        f'  Bytes     : {meta.get("total_bytes",0):,}',
        f'  Start     : {meta.get("capture_start","–")}',
        f'  End       : {meta.get("capture_end","–")}',
        f'  Duration  : {meta.get("duration_sec",0):.1f}s',
        '',
        '─' * 65,
        f'  RISK SCORE: {risk.get("score",0)}/100  |  {risk.get("label","–")}',
        '─' * 65,
        '',
        '  THREATS DETECTED:',
    ]
    if threats:
        for t in threats:
            lines.append(f'  [{t.get("severity","?")}] {t.get("label","")} — {t.get("src","")}')
            lines.append(f'         {t.get("detail","")}')
    else:
        lines.append('  None.')
    lines += ['', '  PROTOCOLS:']
    for p in protos[:8]:
        lines.append(f'  {p["name"]:<10} {p["count"]:>8,}  ({p["pct"]}%)')
    lines += ['', '  TOP SOURCE IPs:']
    for e in top_src[:8]:
        lines.append(f'  {e["ip"]:<20} {e["count"]:>6,} packets')
    lines += ['', '  TOP DNS QUERIES:']
    for d in dns.get('top_domains', [])[:10]:
        lines.append(f'  {d["domain"]:<50} x{d["count"]}')
    lines += ['', '=' * 65]
    return '\n'.join(lines)
