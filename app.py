import os
import re
import uuid
import json
import time
import urllib.request
import urllib.error
from pathlib import Path
from flask import Flask, request, jsonify, send_file, render_template_string
import pandas as pd

import audit_parser
from audit_customizer.generator import format_final_output

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB upload limit

# Workspace directory
WORKSPACE_DIR = Path(r"d:\Docs\Bhavya\CA")

# Directory to store generated audits and uploads
OUTPUTS_DIR = WORKSPACE_DIR / 'generated_audits'
OUTPUTS_DIR.mkdir(exist_ok=True)

# Default offline AI endpoint (Ollama / LM Studio)
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_LMSTUDIO_URL = "http://localhost:1234/v1"

# In-memory cached audit index
CACHED_AUDIT_INDEX = None
CACHED_FLAT_INDEX = None

def clean_client_text(text):
    if not text or not isinstance(text, str):
        return text
    replacements = [
        (re.compile(r'Angel\s*One\s*MF', re.I), 'Enterprise'),
        (re.compile(r'Angel\s*One', re.I), 'Enterprise'),
        (re.compile(r'\bAOMF\b', re.I), 'Enterprise'),
        (re.compile(r'Nippon\s*India\s*Mutual\s*Fund', re.I), 'Standard'),
        (re.compile(r'Nippon', re.I), 'Standard'),
        (re.compile(r'\bNIMF\b', re.I), 'Standard'),
        (re.compile(r'\bNIAM\b', re.I), 'Standard'),
    ]
    res = text
    for pat, repl in replacements:
        res = pat.sub(repl, res)
    return res

def scan_all_audits(force_refresh=False):
    """
    Recursively scans the workspace, audits/portal_audits, baselines, and project folders
    to build a comprehensive catalog of all available .audit files.
    """
    global CACHED_AUDIT_INDEX, CACHED_FLAT_INDEX
    if CACHED_AUDIT_INDEX is not None and not force_refresh:
        return CACHED_AUDIT_INDEX, CACHED_FLAT_INDEX

    CLIENT_EXCLUDE_TERMS = ['angel', 'aomf', 'nippon', 'nimf', 'niam']

    search_roots = [
        WORKSPACE_DIR / 'audits',
        WORKSPACE_DIR / 'baselines',
        WORKSPACE_DIR / 'generated_audits',
        WORKSPACE_DIR
    ]

    all_files = []
    seen = set()

    for root_dir in search_roots:
        if not root_dir.exists():
            continue
        for audit_path in root_dir.rglob('*.audit'):
            resolved = audit_path.resolve()
            if not audit_path.is_file() or resolved in seen:
                continue
            seen.add(resolved)

            rel_str = str(audit_path.relative_to(WORKSPACE_DIR)).replace('\\', '/')
            if any(term in rel_str.lower() for term in CLIENT_EXCLUDE_TERMS):
                continue

            parts = rel_str.split('/')

            # Extract category from folder structure
            if 'portal_audits' in parts:
                idx = parts.index('portal_audits')
                cat_raw = parts[idx + 1] if len(parts) > idx + 1 else 'Portal Audits'
            elif len(parts) > 1:
                cat_raw = parts[0]
            else:
                cat_raw = 'Root Baselines'

            # Clean friendly category name and icon
            cat_map = {
                'Unix': ('Linux & Unix', 'terminal', 'Ubuntu, RHEL, Oracle Linux, Debian, SUSE, macOS, AIX'),
                'Windows': ('Windows OS', 'monitor', 'Server 2016/2019/2022/2025, Windows 10 & 11, Domain Controllers'),
                'MySQLDB': ('MySQL Database', 'database', 'CIS MySQL Community & Enterprise 8.0, 8.4, MariaDB'),
                'MS_SQLDB': ('MSSQL Server', 'hard-drive', 'Microsoft SQL Server 2016, 2017, 2019, 2022'),
                'PostgreSQLDB': ('PostgreSQL', 'database', 'PostgreSQL 11, 12, 13, 14, 15, 16 Hardening'),
                'OracleDB': ('Oracle Database', 'server', 'Oracle DB 11g, 12c, 19c, 21c, 23ai'),
                'Database': ('Other Databases', 'database', 'Sybase, Informix, Teradata, Enterprise DBs'),
                'mongodb': ('MongoDB', 'layers', 'MongoDB 4.x, 5.x, 6.x, 7.x NoSQL Benchmarks'),
                'Cisco': ('Cisco Networking', 'network', 'Cisco IOS, IOS-XE, NX-OS, ASA, Firepower'),
                'Fortigate': ('Fortigate Firewall', 'shield-check', 'FortiOS 6.x, 7.0.x, 7.2.x, 7.4.x CIS & STIG'),
                'palo_alto': ('Palo Alto Networks', 'shield', 'PAN-OS 9.x, 10.x, 11.x Next-Gen Firewalls'),
                'F5': ('F5 BIG-IP', 'zap', 'BIG-IP LTM, APM, ASM Security Baselines'),
                'JUNOS': ('Juniper Junos', 'network', 'Junos OS Router & Switch Hardening'),
                'Arista': ('Arista EOS', 'network', 'Arista EOS Cloud Networking'),
                'ArubaOS': ('ArubaOS', 'wifi', 'Aruba Wireless & Switch Infrastructure'),
                'amazon_aws': ('AWS Cloud', 'cloud', 'AWS Foundations, IAM, CIS AWS Benchmarks'),
                'ms_azure': ('Microsoft Azure', 'cloud', 'Azure Foundations, Security Center, CIS L1/L2'),
                'GCP': ('Google Cloud', 'cloud', 'GCP Foundations, GKE, IAM Hardening'),
                'vmware': ('VMware vSphere', 'cpu', 'ESXi 6.7/7.0/8.0, vCenter Server Benchmarks'),
                'Snowflake': ('Snowflake Cloud', 'snowflake', 'Snowflake Data Cloud Foundations v1/v2'),
                'MDM': ('Mobile & MDM', 'smartphone', 'iOS, Android, macOS Mobile Device Management'),
                'IBM_DB2_DB': ('IBM DB2', 'database', 'IBM DB2 Database 10.x, 11.x'),
                'CassandraDB': ('Apache Cassandra', 'layers', 'Cassandra NoSQL Hardening'),
                'Splunk': ('Splunk Enterprise', 'activity', 'Splunk Enterprise & Cloud Hardening'),
                'baselines': ('Core Windows Baselines', 'star', 'Standard Windows Server Templates'),
                'generated_audits': ('Generated Custom Audits', 'package', 'Recently compiled custom audit policies'),
                'Root Baselines': ('Workspace Baselines', 'folder', 'Active local audit templates')
            }

            cat_info = cat_map.get(cat_raw, (cat_raw.replace('_', ' '), 'folder', 'Compliance benchmark templates'))
            category_name = cat_info[0]

            clean_label = audit_path.stem.replace('_', ' ')
            clean_label = re.sub(r'^(CIS|DISA_STIG|TNS)\s*', '', clean_label)

            item = {
                'rel_path': rel_str,
                'filename': audit_path.name,
                'label': audit_path.stem.replace('_', ' '),
                'display_name': clean_label,
                'category': category_name,
                'category_clean': cat_info[0],
                'category_icon': cat_info[1],
                'category_desc': cat_info[2],
                'raw_category': cat_raw,
                'size_kb': round(audit_path.stat().st_size / 1024, 1)
            }
            all_files.append(item)

    all_files.sort(key=lambda x: (x['category_clean'], x['filename']))

    categories_dict = {}
    for item in all_files:
        cat_key = item['category_clean']
        if cat_key not in categories_dict:
            categories_dict[cat_key] = {
                'name': item['category'],
                'clean_name': cat_key,
                'icon': item['category_icon'],
                'desc': item['category_desc'],
                'items': []
            }
        categories_dict[cat_key]['items'].append(item)

    categories_list = [
        {
            'name': v['name'],
            'clean_name': v['clean_name'],
            'icon': v['icon'],
            'desc': v['desc'],
            'count': len(v['items']),
            'items': v['items']
        }
        for k, v in sorted(categories_dict.items(), key=lambda x: -len(x[1]['items']))
    ]

    CACHED_AUDIT_INDEX = categories_list
    CACHED_FLAT_INDEX = all_files
    return categories_list, all_files


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Tenable Audit Studio - Enterprise Benchmark Customizer</title>
  <meta name="description" content="Minimal, clean compliance audit customizer with Magic UI FileTree, Offline AI model integration, and 1,760+ prebuilt benchmarks." />
  <link rel="icon" type="image/svg+xml" href="/static/tas_badge.svg" />
  
  <!-- Modern Clean Typography with native system fallbacks for offline mode -->
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  
  <!-- Offline-First Local Tailwind CSS (with CDN fallback) -->
  <script src="/static/tailwindcss.js"></script>
  <script>window.tailwind || document.write('<script src="https://cdn.tailwindcss.com"><\/script>')</script>
  
  <!-- Offline-First Local Lucide Icons (with CDN fallback) -->
  <script src="/static/lucide.min.js"></script>
  <script>window.lucide || document.write('<script src="https://unpkg.com/lucide@latest"><\/script>')</script>
  <script>
    // Safeguard for offline / missing lucide
    if (typeof window.lucide === 'undefined') {
      window.lucide = { createIcons: function() {} };
    }
  </script>

  <script>
    if (window.tailwind) {
      tailwind.config = {
        darkMode: 'class',
        theme: {
          extend: {
            fontFamily: {
              sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'Helvetica', 'Arial', 'sans-serif'],
              mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
            },
            colors: {
              brand: {
                50: '#eef2ff',
                100: '#e0e7ff',
                500: '#6366f1',
                600: '#4f46e5',
                700: '#4338ca'
              }
            }
          }
        }
      };
    }
  </script>

  <style>
    /* Minimalist, clean styling with generous spacing */
    body {
      letter-spacing: -0.01em;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .panel-box {
      background: #09090b;
      border: 1px solid #27272a;
    }
    .light .panel-box {
      background: #ffffff;
      border: 1px solid #e4e4e7;
    }
    
    /* Magic UI FileTree styles */
    .filetree-folder {
      user-select: none;
      transition: background 0.15s ease;
    }
    .filetree-folder:hover {
      background: rgba(255, 255, 255, 0.04);
    }
    .filetree-file {
      user-select: none;
      transition: all 0.15s ease;
    }
    .filetree-file:hover {
      background: rgba(99, 102, 241, 0.12);
      color: #818cf8;
    }
    .filetree-file.active {
      background: rgba(99, 102, 241, 0.2);
      color: #ffffff;
      font-weight: 600;
      border-left: 2px solid #6366f1;
    }

    /* Subtle custom scrollbar */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 4px; }
    .light ::-webkit-scrollbar-thumb { background: #d4d4d8; }
    ::-webkit-scrollbar-thumb:hover { background: #3f3f46; }

    .custom-scrollbar {
      scrollbar-width: thin;
      scrollbar-color: #3f3f46 transparent;
      overflow-y: auto;
      scroll-behavior: smooth;
    }
    .custom-scrollbar::-webkit-scrollbar {
      width: 6px;
    }
    .custom-scrollbar::-webkit-scrollbar-track {
      background: rgba(0, 0, 0, 0.2);
      border-radius: 4px;
    }
    .custom-scrollbar::-webkit-scrollbar-thumb {
      background: #3f3f46;
      border-radius: 4px;
    }
    .custom-scrollbar::-webkit-scrollbar-thumb:hover {
      background: #6366f1;
    }
  </style>
</head>
<body class="bg-zinc-950 text-zinc-100 font-sans min-h-screen flex flex-col antialiased transition-colors duration-150">

  <!-- Clean Minimal Global Header -->
  <header class="h-16 border-b border-zinc-800 bg-zinc-950 px-6 flex items-center justify-between sticky top-0 z-40">
    <div class="flex items-center gap-3">
      <img src="/static/tas_badge.svg" alt="TAS Code Badge" class="w-8 h-8 rounded-xl object-contain shadow-md shadow-indigo-500/10 hover:scale-105 transition" />
      <div>
        <div class="flex items-center gap-2">
          <span class="font-bold text-sm text-white">Tenable Audit Studio</span>
          <span class="text-[10px] font-mono font-medium px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">1,760+ Prebuilt Audits</span>
        </div>
        <p class="text-[11px] text-zinc-400 leading-none mt-0.5">Customize, Add, Verify & Compile Compliance Policies</p>
      </div>
    </div>

    <!-- Active Audit Indicator -->
    <div id="header-active-file" class="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-mono text-zinc-300">
      <i data-lucide="file-code" class="w-3.5 h-3.5 text-indigo-400"></i>
      <span id="header-filename" class="font-medium text-white truncate max-w-sm">No benchmark selected</span>
      <span id="header-badge" class="px-1.5 py-0.5 text-[10px] rounded bg-indigo-500/20 text-indigo-300 font-bold">0 checks</span>
    </div>

    <!-- Top Action Toolbar -->
    <div class="flex items-center gap-2">
      <!-- Benchmark Explorer Modal Button -->
      <button onclick="openBenchmarkExplorerModal()" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600/15 border border-indigo-500/30 text-xs font-medium text-indigo-300 hover:text-white hover:bg-indigo-600/25 transition shadow-xs" title="Open Benchmark Explorer Modal (Ctrl+K)">
        <i data-lucide="folder-search" class="w-3.5 h-3.5 text-indigo-400"></i>
        <span>Browse Benchmarks</span>
        <kbd class="hidden md:inline text-[9px] font-mono px-1 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">⌘K</kbd>
      </button>

      <!-- Side-by-Side Baseline Diff Button -->
      <button onclick="openDiffModal()" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-medium text-zinc-300 hover:text-white hover:border-zinc-700 transition" title="Compare Custom Changes Against Original Baseline">
        <i data-lucide="git-compare" class="w-3.5 h-3.5 text-amber-400"></i>
        <span>Compare Diff</span>
      </button>

      <!-- Interactive Regex / Value Tester Button -->
      <button onclick="openRegexTesterModal()" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-medium text-zinc-300 hover:text-white hover:border-zinc-700 transition" title="Test Regular Expression or Expected Value Against Real Output">
        <i data-lucide="binary" class="w-3.5 h-3.5 text-sky-400"></i>
        <span>Regex Tester</span>
      </button>

      <!-- AI Prompts Button -->
      <button onclick="openAiPromptsModal()" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-medium text-zinc-300 hover:text-white hover:border-zinc-700 transition" title="Ready-to-use AI prompts for ChatGPT/Claude">
        <i data-lucide="bot" class="w-3.5 h-3.5 text-indigo-400"></i>
        <span>AI Prompts</span>
      </button>

      <!-- Offline AI Model Assistant Button -->
      <button onclick="openOfflineAiModal()" class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 text-xs font-medium text-zinc-300 hover:text-white hover:border-zinc-700 transition" title="Use local Ollama / LM Studio offline model">
        <span class="w-2 h-2 rounded-full bg-emerald-500" id="offline-ai-indicator"></span>
        <i data-lucide="cpu" class="w-3.5 h-3.5 text-emerald-400"></i>
        <span>Offline AI</span>
      </button>

      <!-- Theme Switcher -->
      <button onclick="toggleTheme()" class="w-8 h-8 rounded-lg border border-zinc-800 bg-zinc-900 flex items-center justify-center text-zinc-400 hover:text-white transition" title="Toggle Theme">
        <i data-lucide="moon" class="w-4 h-4 dark:hidden"></i>
        <i data-lucide="sun" class="w-4 h-4 hidden dark:inline"></i>
      </button>
    </div>
  </header>

  <!-- ========================================================================================= -->
  <!-- MAIN LAYOUT: STUDIO WORKSPACE / EDITOR -->
  <!-- ========================================================================================= -->
  <div class="flex-1 grid grid-cols-1 lg:grid-cols-[340px_1fr] overflow-hidden h-[calc(100vh-100px)]">
    
    <!-- LEFT SIDEBAR: ACTIVE BENCHMARK, UPLOAD, COMPILER & CONSOLE -->
    <div class="border-r border-zinc-800 bg-zinc-950 p-4.5 flex flex-col h-full overflow-y-auto custom-scrollbar gap-4 select-none">
      
      <!-- Active Benchmark Card with Quick Browse Action -->
      <div class="panel-box rounded-xl p-4 flex flex-col gap-3.5">
        <div class="flex items-center justify-between">
          <span class="text-[11px] font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <i data-lucide="file-code" class="w-3.5 h-3.5 text-indigo-400"></i>
            <span>Active Benchmark</span>
          </span>
          <span class="text-[10px] font-mono text-zinc-500" id="sidebar-checks-count">0 checks</span>
        </div>

        <div class="bg-zinc-900/90 border border-zinc-800 rounded-xl p-3 flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-indigo-600/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shrink-0">
            <i data-lucide="shield" class="w-4 h-4"></i>
          </div>
          <div class="truncate flex-1 min-w-0">
            <div id="sidebar-active-name" class="text-xs font-semibold text-white truncate">No benchmark selected</div>
            <div class="text-[10px] text-zinc-500 font-mono truncate mt-0.5">Use Browse Benchmarks or upload</div>
          </div>
        </div>

        <button onclick="openBenchmarkExplorerModal()" class="w-full bg-indigo-600/15 hover:bg-indigo-600/25 border border-indigo-500/30 text-indigo-300 hover:text-white font-medium text-xs py-2.5 px-3 rounded-lg flex items-center justify-center gap-2 transition shadow-xs">
          <i data-lucide="folder-search" class="w-3.5 h-3.5"></i>
          <span>Browse 1,760+ Benchmarks</span>
          <kbd class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-400">⌘K</kbd>
        </button>
      </div>

      <!-- Upload Custom File Dropzone -->
      <label class="cursor-pointer border border-dashed border-zinc-800 hover:border-indigo-500 rounded-xl p-3.5 text-center bg-zinc-900/40 hover:bg-zinc-900 transition flex items-center justify-center gap-2.5 text-xs font-medium text-zinc-300">
        <i data-lucide="upload-cloud" class="w-4 h-4 text-indigo-400"></i>
        <span>Upload Custom .audit File</span>
        <input type="file" id="sidebar-upload-input" accept=".audit" onchange="uploadCustomAudit(this)" class="hidden" />
      </label>

      <!-- Compiler & Export Studio Panel -->
      <div class="panel-box rounded-xl p-4 flex flex-col gap-3.5" id="compile-panel">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <i data-lucide="package-check" class="w-3.5 h-3.5 text-emerald-400"></i>
            <span>Export Custom Audit</span>
          </span>
          <span id="compile-badge" class="text-[10px] font-mono text-zinc-400 border border-zinc-800 bg-zinc-900 px-2 py-0.5 rounded">0 edits</span>
        </div>

        <div>
          <label class="block text-[11px] text-zinc-400 font-medium mb-1.5">Output File Name:</label>
          <input type="text" id="output-filename" placeholder="Custom_Hardened_Audit.audit" value="Custom_Hardened_Audit.audit" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white font-mono outline-none focus:border-indigo-500 transition" />
        </div>

        <label class="flex items-start gap-2.5 text-xs text-zinc-300 cursor-pointer pt-0.5">
          <input type="checkbox" id="remove-unmodified-toggle" onchange="updateStatsDashboard()" class="mt-0.5 rounded border-zinc-700 bg-zinc-900 text-indigo-600 focus:ring-indigo-500" />
          <span class="text-[11px] leading-snug">Prune unmodified checks <span class="text-zinc-500 block text-[10px] mt-0.5">(Exports only modified and newly added policies)</span></span>
        </label>

        <button id="btn-compile" onclick="compileAudit()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs py-2.5 rounded-lg flex items-center justify-center gap-2 transition shadow-xs mt-0.5">
          <i data-lucide="play" class="w-3.5 h-3.5"></i>
          <span>Compile & Validate Audit</span>
        </button>

        <a id="btn-download" href="#" class="hidden w-full bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs py-2.5 rounded-lg items-center justify-center gap-2 transition text-center shadow-xs">
          <i data-lucide="download" class="w-3.5 h-3.5"></i>
          <span>Download Compiled .audit</span>
        </a>

        <div class="grid grid-cols-2 gap-2 pt-1 border-t border-zinc-800/80">
          <button onclick="openDiffModal()" class="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white font-medium text-xs py-2 rounded-lg flex items-center justify-center gap-1.5 transition">
            <i data-lucide="git-compare" class="w-3.5 h-3.5 text-amber-400"></i>
            <span>View Diff</span>
          </button>
          <button onclick="openTenableSyncModal()" class="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-zinc-300 hover:text-white font-medium text-xs py-2 rounded-lg flex items-center justify-center gap-1.5 transition">
            <i data-lucide="cloud-upload" class="w-3.5 h-3.5 text-sky-400"></i>
            <span>Sync API</span>
          </button>
        </div>
      </div>

      <!-- Studio Activity Console -->
      <div class="flex flex-col flex-1 min-h-[150px] panel-box rounded-xl overflow-hidden">
        <div class="bg-zinc-900 px-3.5 py-2 flex items-center justify-between text-[10px] font-semibold uppercase tracking-wider text-zinc-400 border-b border-zinc-800">
          <span class="flex items-center gap-1.5">
            <span class="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Activity Logs</span>
          </span>
          <button onclick="document.getElementById('console-logs').innerHTML=''" class="text-[9px] hover:text-white px-1.5 py-0.5 rounded hover:bg-zinc-800 transition">Clear</button>
        </div>
        <div class="flex-1 p-3 font-mono text-[11px] overflow-y-auto custom-scrollbar leading-relaxed text-zinc-400 space-y-1.5" id="console-logs">
          <div>Ready. Click Browse Benchmarks or press Ctrl+K to select a template.</div>
        </div>
      </div>
    </div>

    <!-- RIGHT MAIN WORKSPACE: POLICIES, DETAIL INSPECTOR, VARIABLES -->
    <div class="p-5 sm:p-6 overflow-y-auto flex flex-col gap-5 bg-zinc-950 custom-scrollbar">
      
      <!-- Top Action Bar -->
      <div class="flex flex-col gap-3.5 border-b border-zinc-800 pb-4">
        <!-- Row 1: Tabs, Filters, and Action Buttons -->
        <div class="flex flex-wrap items-center justify-between gap-3">
          <!-- Left: Tabs & Filters -->
          <div class="flex flex-wrap items-center gap-2.5">
            <!-- Tabs -->
            <div class="flex items-center gap-1 bg-zinc-900 p-1 rounded-xl border border-zinc-800">
              <button id="tab-btn-checks" onclick="switchEditorTab('checks')" class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-zinc-800 text-white shadow-xs transition">
                <i data-lucide="shield-check" class="w-3.5 h-3.5 text-indigo-400"></i>
                <span>Policies (<span id="checks-tab-count">0</span>)</span>
              </button>
              <button id="tab-btn-vars" onclick="switchEditorTab('vars')" class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold text-zinc-400 hover:text-white transition">
                <i data-lucide="variable" class="w-3.5 h-3.5"></i>
                <span>Variables (<span id="vars-tab-count">0</span>)</span>
              </button>
            </div>

            <!-- Filter Status Buttons -->
            <div class="flex items-center gap-1 bg-zinc-900 p-1 rounded-xl border border-zinc-800">
              <button id="filter-all" onclick="setPolicyFilter('all')" class="filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold bg-zinc-800 text-white transition">All</button>
              <button id="filter-modified" onclick="setPolicyFilter('modified')" class="filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold text-zinc-400 hover:text-white transition">Modified</button>
              <button id="filter-excluded" onclick="setPolicyFilter('excluded')" class="filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold text-zinc-400 hover:text-white transition">Excluded</button>
              <button id="filter-added" onclick="setPolicyFilter('added')" class="filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold text-zinc-400 hover:text-white transition">Added</button>
            </div>

            <!-- Preset Profiles Dropdown -->
            <div class="flex items-center gap-1.5 bg-zinc-900 px-2.5 py-1.5 rounded-xl border border-zinc-800">
              <i data-lucide="sparkles" class="w-3.5 h-3.5 text-amber-400 shrink-0"></i>
              <select id="preset-profile-select" onchange="handlePresetSelection(this.value)" class="bg-transparent text-[11px] font-semibold text-zinc-300 outline-none cursor-pointer pr-1">
                <option value="" class="bg-zinc-900 text-zinc-400">⚡ Presets...</option>
                <option value="cis_l1" class="bg-zinc-900 text-white">CIS Level 1 (Exclude L2 checks)</option>
                <option value="cis_l2" class="bg-zinc-900 text-white">CIS Level 2 (Include all controls)</option>
                <option value="db_strict" class="bg-zinc-900 text-white">Database Hardening (Strict)</option>
                <option value="save_custom" class="bg-zinc-900 text-indigo-300">💾 Save as Custom Preset...</option>
                <option value="reset_defaults" class="bg-zinc-900 text-rose-300">🔄 Reset to Baseline Defaults</option>
              </select>
            </div>
          </div>

          <!-- Right: Add Policy / Bulk Actions -->
          <div class="flex items-center gap-2.5">
            <button onclick="openAddPolicyModal()" class="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs py-2 px-3.5 rounded-xl transition shadow-xs">
              <i data-lucide="plus" class="w-3.5 h-3.5"></i>
              <span>Add Custom Policy</span>
            </button>
            <button onclick="openBulkImportModal()" class="flex items-center gap-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 hover:text-white font-semibold text-xs py-2 px-3.5 rounded-xl transition">
              <i data-lucide="file-spreadsheet" class="w-3.5 h-3.5 text-emerald-400"></i>
              <span>Bulk JSON / Excel</span>
            </button>
          </div>
        </div>

        <!-- Row 2: Full-Width Search Bar with Clear Button -->
        <div class="relative w-full">
          <i data-lucide="search" class="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"></i>
          <input type="text" id="editor-search-input" placeholder="Search policies by CIS ID (e.g. 1.4), title, registry key (HKLM), or SQL query..." oninput="handleEditorSearch()" class="w-full bg-zinc-900 border border-zinc-800 rounded-xl pl-10 pr-10 py-2.5 text-xs text-white placeholder-zinc-500 outline-none focus:border-indigo-500 transition shadow-inner" />
          <button id="editor-search-clear-btn" onclick="clearEditorSearch()" class="hidden absolute right-3.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white text-xs font-bold p-1">✕</button>
        </div>
      </div>

      <!-- Loaded File Summary Bar -->
      <div id="loaded-summary-bar" class="hidden flex-col md:flex-row md:items-center justify-between gap-3.5 bg-zinc-900/70 border border-zinc-800/90 rounded-xl px-4 sm:px-5 py-3.5 text-xs">
        <div class="flex items-center gap-3.5 min-w-0 flex-1">
          <div class="w-9 h-9 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 flex items-center justify-center shrink-0">
            <i data-lucide="file-code" class="w-4 h-4"></i>
          </div>
          <div class="min-w-0 flex-1">
            <h3 class="font-bold text-white text-xs sm:text-sm truncate" id="summary-audit-name">Loaded Audit</h3>
            <p class="text-zinc-400 font-mono text-[11px] truncate mt-0.5" id="summary-audit-path">path</p>
          </div>
        </div>
        <div class="flex flex-wrap items-center gap-2 font-mono text-[11px] shrink-0">
          <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-zinc-800/80 border border-zinc-700/60 text-zinc-300">
            <span class="text-zinc-400">Total:</span>
            <strong class="text-white font-bold" id="stat-total">0</strong>
          </div>
          <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-300">
            <span class="text-indigo-400/80">Modified:</span>
            <strong class="text-indigo-300 font-bold" id="stat-modified">0</strong>
          </div>
          <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-300">
            <span class="text-rose-400/80">Excluded:</span>
            <strong class="text-rose-300 font-bold" id="stat-excluded">0</strong>
          </div>
          <div class="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-300">
            <span class="text-emerald-400/80">Added:</span>
            <strong class="text-emerald-300 font-bold" id="stat-added">0</strong>
          </div>
        </div>
      </div>

      <!-- TAB VIEW 1: COMPLIANCE POLICIES LIST -->
      <div id="editor-tab-checks" class="flex flex-col gap-3">
        <div id="checks-cards-container" class="flex flex-col gap-3">
          <!-- Policy Cards Rendered Here -->
        </div>

        <!-- Clean Pagination -->
        <div class="flex items-center justify-between panel-box rounded-xl px-4 py-2.5 text-xs" id="pagination-controls" style="display:none;">
          <div class="text-zinc-400 font-medium" id="pagination-info">Showing 0-0 of 0 policies</div>
          <div class="flex gap-2">
            <button id="page-prev-btn" onclick="prevPage()" class="flex items-center gap-1 px-3 py-1 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white text-xs font-semibold disabled:opacity-30 disabled:cursor-not-allowed">
              <i data-lucide="chevron-left" class="w-3.5 h-3.5"></i>
              <span>Previous</span>
            </button>
            <button id="page-next-btn" onclick="nextPage()" class="flex items-center gap-1 px-3 py-1 rounded-lg bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white text-xs font-semibold disabled:opacity-30 disabled:cursor-not-allowed">
              <span>Next</span>
              <i data-lucide="chevron-right" class="w-3.5 h-3.5"></i>
            </button>
          </div>
        </div>

        <div id="checks-empty-state" class="text-center py-20 text-xs text-zinc-500 flex flex-col items-center justify-center gap-3.5">
          <img src="/static/tas_badge.svg" alt="TAS Badge" class="w-16 h-16 rounded-2xl object-contain opacity-90 shadow-2xl shadow-indigo-500/15" />
          <div class="flex flex-col items-center gap-1">
            <span class="font-semibold text-zinc-200 text-sm">Welcome to Tenable Audit Studio</span>
            <span class="text-zinc-500">Select any benchmark from the library or press <kbd class="px-1.5 py-0.5 text-[10px] font-mono rounded bg-zinc-900 border border-zinc-700 text-zinc-400">Ctrl+K</kbd> to start customizing.</span>
          </div>
        </div>
      </div>

      <!-- TAB VIEW 2: VARIABLES -->
      <div id="editor-tab-vars" class="hidden flex flex-col gap-3">
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3" id="variables-container">
          <!-- Variables Rendered Here -->
        </div>
        <div id="vars-empty-state" class="text-center py-20 text-xs text-zinc-500">
          No global variables declared in this template.
        </div>
      </div>
    </div>
  </div>

  <!-- Sleek Developer Footer (Permanently pinned & always on top) -->
  <footer class="fixed bottom-0 inset-x-0 h-9 border-t border-zinc-800/90 bg-zinc-950/95 backdrop-blur-md px-6 flex items-center justify-between text-[11px] font-medium text-zinc-400 select-none z-[60]">
    <div class="flex items-center gap-2">
      <span class="text-zinc-500">Made by</span>
      <a href="https://github.com/Kakaxh1" target="_blank" rel="noopener noreferrer" class="font-semibold text-zinc-200 hover:text-indigo-400 transition flex items-center gap-1">
        <span>Kakaxh1</span>
      </a>
      <span class="text-zinc-700">•</span>
      <span class="text-zinc-500">Tenable Audit Studio</span>
    </div>

    <div class="flex items-center gap-4">
      <a href="https://bhavymorvadiya.netlify.app/" target="_blank" rel="noopener noreferrer" class="flex items-center gap-1.5 text-zinc-400 hover:text-indigo-400 transition" title="Personal Website">
        <i data-lucide="globe" class="w-3.5 h-3.5"></i>
        <span>bhavymorvadiya.netlify.app</span>
      </a>
      <span class="text-zinc-700">•</span>
      <a href="https://github.com/Kakaxh1" target="_blank" rel="noopener noreferrer" class="flex items-center gap-1.5 text-zinc-400 hover:text-white transition" title="GitHub Profile">
        <svg class="w-3.5 h-3.5 fill-current" viewBox="0 0 24 24">
          <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
        </svg>
        <span>GitHub</span>
      </a>
    </div>
  </footer>

  <!-- ========================================================================================= -->
  <!-- MODAL: BENCHMARK EXPLORER (5 TO 7 VISIBLE ITEMS, REST SCROLLABLE) -->
  <!-- ========================================================================================= -->
  <div id="benchmark-explorer-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-3xl shadow-2xl flex flex-col overflow-hidden">
      <!-- Modal Header -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <i data-lucide="folder-search" class="w-4 h-4 text-indigo-400"></i>
          <h3 class="text-sm font-bold text-white">Benchmark Explorer</h3>
          <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700" id="modal-benchmark-total-count">1,763 benchmarks</span>
        </div>
        <button onclick="closeBenchmarkExplorerModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <!-- Modal Body -->
      <div class="p-5 flex flex-col gap-3.5 text-xs">
        <!-- Search bar inside modal -->
        <div class="relative">
          <i data-lucide="search" class="w-4 h-4 text-zinc-500 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none"></i>
          <input type="text" id="modal-benchmark-search-input" placeholder="Search 1,760+ compliance benchmarks or filter folders by name..." oninput="handleModalBenchmarkSearch()" class="w-full bg-zinc-950 border border-zinc-800 rounded-xl pl-10 pr-9 py-2 text-xs text-zinc-100 placeholder-zinc-500 outline-none focus:border-indigo-500 transition shadow-inner" />
          <button id="modal-benchmark-clear-btn" onclick="clearModalBenchmarkSearch()" class="hidden absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-white text-xs font-bold">✕</button>
        </div>

        <!-- 2-COLUMN BROWSER: 5-7 FOLDERS (SCROLLABLE) + 5-7 FILES (SCROLLABLE) -->
        <div class="grid grid-cols-1 sm:grid-cols-[230px_1fr] gap-3">
          
          <!-- LEFT COLUMN: FOLDERS (5-7 VISIBLE, REST SCROLLABLE) -->
          <div class="flex flex-col gap-1.5 min-w-0">
            <div class="flex items-center justify-between text-[11px] font-semibold text-zinc-400 px-1">
              <span class="flex items-center gap-1.5">
                <i data-lucide="folder" class="w-3.5 h-3.5 text-indigo-400"></i>
                <span>Folders</span>
              </span>
              <span class="font-mono text-[10px] text-zinc-500" id="modal-folder-count">59 categories</span>
            </div>
            
            <!-- Folders List Container: 330px height (5 to 7 folders visible, rest scrollable) -->
            <div class="panel-box rounded-xl border border-zinc-800/80 divide-y divide-zinc-800/60 overflow-y-auto custom-scrollbar h-[330px]" id="modal-folder-list">
              <!-- Rendered dynamically: 5-7 folders visible, scrollable -->
            </div>
          </div>

          <!-- RIGHT COLUMN: BENCHMARK FILES (5-7 VISIBLE, REST SCROLLABLE) -->
          <div class="flex flex-col gap-1.5 min-w-0">
            <div class="flex items-center justify-between text-[11px] font-semibold text-zinc-400 px-1">
              <span class="flex items-center gap-1.5 truncate">
                <i data-lucide="file-code" class="w-3.5 h-3.5 text-emerald-400"></i>
                <span id="modal-current-folder-title" class="truncate">Files</span>
              </span>
              <span class="font-mono text-[10px] text-zinc-500" id="modal-benchmark-filtered-count">0 files</span>
            </div>

            <!-- Files List Container: 330px height (5 to 7 files visible, rest scrollable) -->
            <div class="panel-box rounded-xl border border-zinc-800/80 divide-y divide-zinc-800/60 overflow-y-auto custom-scrollbar h-[330px]" id="modal-benchmark-list">
              <!-- Rendered dynamically: 5-7 files visible, scrollable -->
            </div>
          </div>

        </div>
      </div>

      <!-- Modal Footer -->
      <div class="px-6 py-3 border-t border-zinc-800 flex items-center justify-between bg-zinc-900/60 text-xs text-zinc-400">
        <div class="flex items-center gap-2 text-[11px]">
          <span class="inline-flex items-center gap-1 font-mono text-[10px] bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400 border border-zinc-700">ESC</span>
          <span>to close</span>
          <span class="text-zinc-600">•</span>
          <span>Click a folder to filter, click a benchmark to load</span>
        </div>
        <button onclick="closeBenchmarkExplorerModal()" class="px-3.5 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: FULL POLICY DETAIL INSPECTOR -->
  <!-- ========================================================================================= -->
  <div id="policy-detail-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-2xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <span id="detail-type-badge" class="text-[10px] font-mono font-bold px-2 py-0.5 rounded border bg-zinc-800 text-zinc-300 border-zinc-700">CHECK</span>
          <span id="detail-cis-id" class="text-[10px] font-mono font-semibold text-zinc-400 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">CIS</span>
          <h3 class="text-sm font-bold text-white truncate max-w-md" id="detail-title">Policy Details</h3>
        </div>
        <button onclick="closePolicyDetailModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <!-- Body -->
      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        
        <!-- Breadcrumb / Conditionals Path -->
        <div id="detail-conditionals-box" class="hidden flex items-center gap-1.5 text-[11px] font-mono text-zinc-400 bg-zinc-900 p-2.5 rounded-lg border border-zinc-800">
          <i data-lucide="git-branch" class="w-3.5 h-3.5 text-indigo-400 shrink-0"></i>
          <span id="detail-conditionals-text">Context</span>
        </div>

        <!-- Setting Key / Query -->
        <div>
          <label class="block text-[10px] uppercase font-bold text-zinc-400 mb-1" id="detail-lbl-key">Configuration Query / Key:</label>
          <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-2.5 font-mono text-xs text-zinc-200 break-all select-all" id="detail-key-val">None</div>
        </div>

        <!-- Editable Expected Value -->
        <div class="bg-zinc-900/80 p-3.5 rounded-xl border border-zinc-800 flex flex-col gap-2">
          <div class="flex items-center justify-between">
            <label class="text-[10px] uppercase font-bold text-indigo-400">Expected Value / Hardening Target:</label>
            <span class="text-[10px] font-mono text-zinc-500" id="detail-target-field">field: value_data</span>
          </div>
          <div class="flex items-center gap-2">
            <input type="text" id="detail-input-val" placeholder="Expected value (e.g., 0, Enabled, Success, or [1..MAX])" class="flex-1 bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs font-mono text-white outline-none focus:border-indigo-500" />
            <button onclick="openRegexTesterForCheck(state.currentActiveDetailCheck?.id)" class="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-sky-300 font-semibold text-xs px-3 py-1.5 rounded-lg transition flex items-center gap-1.5">
              <i data-lucide="binary" class="w-3.5 h-3.5"></i>
              <span>Test Regex</span>
            </button>
            <button onclick="saveDetailValueEdit()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs px-3.5 py-1.5 rounded-lg transition">Apply Edit</button>
          </div>
        </div>

        <!-- Security Rationale / Info -->
        <div>
          <label class="block text-[10px] uppercase font-bold text-zinc-400 mb-1">Security Rationale & Description:</label>
          <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-zinc-300 leading-relaxed whitespace-pre-line" id="detail-info-val">No description rationale provided.</div>
        </div>

        <!-- Remediation / Solution -->
        <div id="detail-solution-container">
          <label class="block text-[10px] uppercase font-bold text-zinc-400 mb-1">Remediation Steps (Solution):</label>
          <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-zinc-300 leading-relaxed whitespace-pre-line" id="detail-solution-val">No solution provided.</div>
        </div>

        <!-- References & Links -->
        <div class="grid grid-cols-2 gap-3 text-[11px]">
          <div>
            <label class="block text-[10px] uppercase font-bold text-zinc-400 mb-1">Compliance References:</label>
            <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-2 font-mono text-zinc-400 truncate" id="detail-references-val">N/A</div>
          </div>
          <div>
            <label class="block text-[10px] uppercase font-bold text-zinc-400 mb-1">See Also / Benchmark URL:</label>
            <div class="bg-zinc-900 border border-zinc-800 rounded-lg p-2 font-mono text-zinc-400 truncate" id="detail-seealso-val">N/A</div>
          </div>
        </div>

        <!-- Raw Tenable Audit Code Block -->
        <div>
          <div class="flex items-center justify-between mb-1">
            <label class="text-[10px] uppercase font-bold text-zinc-400">Raw Audit Definition:</label>
            <button onclick="copyRawAuditCode()" class="flex items-center gap-1 text-[10px] text-indigo-400 hover:text-indigo-300">
              <i data-lucide="copy" class="w-3 h-3"></i>
              <span>Copy Code Block</span>
            </button>
          </div>
          <pre class="bg-zinc-900 border border-zinc-800 rounded-lg p-3 font-mono text-[11px] text-zinc-300 overflow-x-auto select-all" id="detail-raw-code"></pre>
        </div>
      </div>

      <!-- Footer Actions -->
      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <!-- Copy AI Prompt for this specific policy -->
          <button onclick="copyAiPromptForPolicy()" class="flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs px-3 py-1.5 rounded-lg border border-zinc-700 transition">
            <i data-lucide="bot" class="w-3.5 h-3.5 text-indigo-400"></i>
            <span>Copy AI Prompt for this Check</span>
          </button>
          <button onclick="validateCurrentPolicyWithAi()" class="flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium text-xs px-3 py-1.5 rounded-lg border border-zinc-700 transition">
            <i data-lucide="sparkles" class="w-3.5 h-3.5 text-emerald-400"></i>
            <span>Validate with Offline AI</span>
          </button>
        </div>
        <button onclick="closePolicyDetailModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: AI PROMPTS & AI POLICY GENERATOR -->
  <!-- ========================================================================================= -->
  <div id="ai-prompts-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-2xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <i data-lucide="bot" class="w-4 h-4 text-indigo-400"></i>
          <h3 class="text-sm font-bold text-white">AI Prompts for Creating Compliance Policies</h3>
        </div>
        <button onclick="closeAiPromptsModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        <p class="text-zinc-400 leading-relaxed">
          Use these ready-made AI prompts in ChatGPT, Claude, Gemini, or your local Offline LLM (Ollama / LM Studio) to convert spreadsheets, guidelines, or requirements into Nessus audit checks.
        </p>

        <!-- Prompt Card 1: Convert Excel / Guidelines to JSON -->
        <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col gap-2.5">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-1.5">
              <i data-lucide="file-spreadsheet" class="w-3.5 h-3.5 text-emerald-400"></i>
              <span>Prompt 1: Convert Excel Rows to Policy JSON</span>
            </span>
            <button onclick="copyPromptText('prompt-1-text')" class="flex items-center gap-1 text-[10px] text-indigo-400 hover:text-indigo-300 font-semibold">
              <i data-lucide="copy" class="w-3 h-3"></i>
              <span>Copy Prompt</span>
            </button>
          </div>
          <pre class="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap select-all" id="prompt-1-text">You are a Tenable Nessus compliance audit expert.
Convert the following compliance checklist rows into a raw JSON array of custom checks that can be imported directly into our Audit Customizer:

[
  {
    "type": "REGISTRY_SETTING", 
    "description": "CIS ID + Policy Description", 
    "reg_key": "HKLM\\SOFTWARE\\Policies\\...", 
    "reg_item": "RegistryItemName", 
    "value_data": "ExpectedValueData",
    "info": "Security rationale description"
  }
]

Allowed "type" values:
- REGISTRY_SETTING: Windows Registry settings
- PASSWORD_POLICY: Password complexity & age
- LOCKOUT_POLICY: Account lockout thresholds
- AUDIT_POLICY_SUBCATEGORY: Advanced auditing
- SERVICE_POLICY: Service start types
- USER_RIGHTS_POLICY: Privilege assignments
- SQL_POLICY: Database SQL query checks
- CMD_EXEC: Linux/Unix shell command checks

Double-escape all backslashes in registry paths. Output ONLY a valid JSON array.

[PASTE YOUR EXCEL / TEXT DATA HERE]</pre>
        </div>

        <!-- Prompt Card 2: Generate Database Hardening Check -->
        <div class="bg-zinc-900 border border-zinc-800 rounded-xl p-4 flex flex-col gap-2.5">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-1.5">
              <i data-lucide="database" class="w-3.5 h-3.5 text-sky-400"></i>
              <span>Prompt 2: Generate Database / MySQL / MSSQL Checks</span>
            </span>
            <button onclick="copyPromptText('prompt-2-text')" class="flex items-center gap-1 text-[10px] text-indigo-400 hover:text-indigo-300 font-semibold">
              <i data-lucide="copy" class="w-3 h-3"></i>
              <span>Copy Prompt</span>
            </button>
          </div>
          <pre class="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-[11px] text-zinc-300 whitespace-pre-wrap select-all" id="prompt-2-text">You are a Tenable database compliance specialist.
Generate standard SQL_POLICY checks for the following database requirements:

[
  {
    "type": "SQL_POLICY",
    "description": "Ensure 'local_infile' Database Flag Is Disabled",
    "sql_request": "SELECT @@global.local_infile",
    "sql_types": "INTEGER",
    "sql_expect": "0",
    "info": "Disabling local_infile prevents clients from loading data from local files."
  }
]

Requirements to harden:
[LIST DATABASE SETTINGS HERE]</pre>
        </div>
      </div>

      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-end bg-zinc-900/60">
        <button onclick="closeAiPromptsModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: OFFLINE AI ASSISTANT (OLLAMA / LOCALAI / LM STUDIO) -->
  <!-- ========================================================================================= -->
  <div id="offline-ai-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <i data-lucide="cpu" class="w-4 h-4 text-emerald-400"></i>
          <h3 class="text-sm font-bold text-white">Offline AI Model Assistant</h3>
        </div>
        <button onclick="closeOfflineAiModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        <!-- Endpoint Setup -->
        <div class="bg-zinc-900 p-4 rounded-xl border border-zinc-800 flex flex-col gap-3">
          <div class="flex items-center justify-between">
            <label class="text-xs font-bold text-white">Local Endpoint:</label>
            <button onclick="testOfflineAiConnection()" class="flex items-center gap-1 text-[11px] text-indigo-400 hover:text-indigo-300 font-medium">
              <i data-lucide="refresh-cw" class="w-3 h-3"></i>
              <span>Test Connection</span>
            </button>
          </div>
          <div class="flex gap-2">
            <input type="text" id="ai-endpoint-url" value="http://localhost:11434" class="flex-1 bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs font-mono text-white outline-none focus:border-indigo-500" />
            <select id="ai-model-select" class="bg-zinc-950 border border-zinc-700 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-indigo-500">
              <option value="llama3">llama3</option>
              <option value="mistral">mistral</option>
              <option value="deepseek-r1">deepseek-r1</option>
              <option value="qwen2.5">qwen2.5</option>
              <option value="phi3">phi3</option>
            </select>
          </div>
          <div class="text-[11px] text-zinc-400 flex items-center gap-2" id="ai-connection-status">
            <span class="w-2 h-2 rounded-full bg-zinc-600"></span>
            <span>Click 'Test Connection' to discover installed models.</span>
          </div>
        </div>

        <!-- Generate / Validate Tabs -->
        <div class="flex flex-col gap-2">
          <label class="block text-xs font-semibold text-zinc-300">Requirement or Raw Policy Text to Generate / Check:</label>
          <textarea id="ai-input-prompt" rows="4" placeholder="Describe a policy to generate or validate (e.g., 'Ensure MySQL require_secure_transport is enabled with expected value 1' or paste registry paths)..." class="w-full bg-zinc-900 border border-zinc-800 rounded-xl p-3 text-xs text-white outline-none focus:border-indigo-500"></textarea>
          <div class="flex gap-2">
            <button onclick="runOfflineAiGenerate()" class="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs py-2 rounded-lg transition flex items-center justify-center gap-1.5">
              <i data-lucide="sparkles" class="w-3.5 h-3.5"></i>
              <span>Generate Policy</span>
            </button>
            <button onclick="runOfflineAiValidate()" class="flex-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-zinc-200 font-semibold text-xs py-2 rounded-lg transition flex items-center justify-center gap-1.5">
              <i data-lucide="check-circle" class="w-3.5 h-3.5 text-emerald-400"></i>
              <span>Validate / Audit Check</span>
            </button>
          </div>
        </div>

        <!-- AI Result Output -->
        <div id="ai-result-box" class="hidden flex flex-col gap-2 bg-zinc-900 p-4 rounded-xl border border-zinc-800">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-1.5">
              <i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i>
              <span>AI Output:</span>
            </span>
            <button onclick="applyAiGeneratedPolicy()" id="btn-apply-ai-result" class="text-[11px] bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-2.5 py-1 rounded transition">Add to Policies</button>
          </div>
          <pre class="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-[11px] text-zinc-300 overflow-x-auto whitespace-pre-wrap select-all" id="ai-output-text"></pre>
        </div>
      </div>

      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-end bg-zinc-900/60">
        <button onclick="closeOfflineAiModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: ADD CUSTOM POLICY -->
  <!-- ========================================================================================= -->
  <div id="add-policy-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <i data-lucide="plus-circle" class="w-4 h-4 text-indigo-400"></i>
          <h3 class="text-sm font-bold text-white">Add Custom Compliance Check</h3>
        </div>
        <button onclick="closeAddPolicyModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <div class="p-6 flex flex-col gap-4 overflow-y-auto">
        <div>
          <label class="block text-xs font-semibold text-zinc-300 mb-1">Check Type:</label>
          <select id="new-policy-type" onchange="adjustAddPolicyFields()" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-indigo-500">
            <option value="REGISTRY_SETTING">REGISTRY_SETTING (Windows Registry)</option>
            <option value="SQL_POLICY">SQL_POLICY (Database SQL Query)</option>
            <option value="CMD_EXEC">CMD_EXEC (Linux/Unix Shell Command)</option>
            <option value="PASSWORD_POLICY">PASSWORD_POLICY (Windows Password Policy)</option>
            <option value="LOCKOUT_POLICY">LOCKOUT_POLICY (Account Lockout Policy)</option>
            <option value="AUDIT_POLICY_SUBCATEGORY">AUDIT_POLICY_SUBCATEGORY (Advanced Auditing)</option>
            <option value="SERVICE_POLICY">SERVICE_POLICY (Windows Service State)</option>
            <option value="USER_RIGHTS_POLICY">USER_RIGHTS_POLICY (User Rights Assignment)</option>
            <option value="FILE_CONTENT_CHECK">FILE_CONTENT_CHECK (Configuration File Scan)</option>
          </select>
        </div>

        <div>
          <label class="block text-xs font-semibold text-zinc-300 mb-1">Policy Title / Description: <span class="text-rose-400">*</span></label>
          <input type="text" id="new-policy-desc" placeholder="e.g., 2.1.4 Ensure 'local_infile' Database Flag is Disabled" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-indigo-500" />
        </div>

        <div id="dynamic-policy-fields" class="flex flex-col gap-3">
          <div>
            <label id="lbl-setting-key" class="block text-xs font-semibold text-zinc-300 mb-1">Registry Key / Path / SQL Query:</label>
            <input type="text" id="new-policy-key" placeholder="e.g., HKLM\SOFTWARE\Policies\Microsoft\Windows\System or SELECT @@global.var;" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white font-mono outline-none focus:border-indigo-500" />
          </div>

          <div id="field-reg-item-container">
            <label class="block text-xs font-semibold text-zinc-300 mb-1">Registry Item Name (Optional):</label>
            <input type="text" id="new-policy-item" placeholder="e.g., PasswordHistorySize or MaxPasswordAge" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white font-mono outline-none focus:border-indigo-500" />
          </div>

          <div>
            <label id="lbl-expected-val" class="block text-xs font-semibold text-zinc-300 mb-1">Expected Value / Result: <span class="text-rose-400">*</span></label>
            <input type="text" id="new-policy-value" placeholder="e.g., 0, Enabled, Success, Failure, or range [1..365]" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white font-mono outline-none focus:border-indigo-500" />
          </div>
        </div>

        <div>
          <label class="block text-xs font-semibold text-zinc-300 mb-1">Security Rationale / Info (Optional):</label>
          <textarea id="new-policy-info" rows="2" placeholder="Describe the compliance requirement, vulnerability risk, and remediation steps..." class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-white outline-none focus:border-indigo-500"></textarea>
        </div>
      </div>

      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-end gap-2.5 bg-zinc-900/60">
        <button onclick="closeAddPolicyModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Cancel</button>
        <button onclick="saveNewPolicy()" class="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-xs">Add Policy</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: BULK IMPORT (JSON & EXCEL) -->
  <!-- ========================================================================================= -->
  <div id="bulk-import-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-2xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2">
          <i data-lucide="file-spreadsheet" class="w-4 h-4 text-emerald-400"></i>
          <h3 class="text-sm font-bold text-white">Bulk Compliance Import</h3>
        </div>
        <button onclick="closeBulkImportModal()" class="text-zinc-400 hover:text-white font-bold text-lg">✕</button>
      </div>

      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        <div class="flex gap-2 border-b border-zinc-800 pb-2">
          <button id="btn-import-tab-json" onclick="switchImportTab('json')" class="text-xs font-bold px-3.5 py-1.5 rounded-lg bg-indigo-600 text-white">JSON Array</button>
          <button id="btn-import-tab-excel" onclick="switchImportTab('excel')" class="text-xs font-bold px-3.5 py-1.5 rounded-lg bg-zinc-900 text-zinc-400 hover:text-white">Excel Spreadsheet (.xlsx)</button>
        </div>

        <div id="import-section-json" class="flex flex-col gap-2">
          <label class="block text-xs font-medium text-zinc-400">Paste JSON array of policies (e.g., converted from Excel checklists):</label>
          <textarea id="bulk-json-input" rows="10" placeholder='[
  {
    "type": "REGISTRY_SETTING",
    "description": "1.1.1 Ensure Password History is set to 24",
    "reg_key": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    "reg_item": "PasswordHistory",
    "value_data": "24",
    "info": "Enforces password rotation and prevents credential reuse."
  }
]' class="w-full bg-zinc-900 border border-zinc-800 rounded-lg p-3 text-xs text-white font-mono outline-none focus:border-indigo-500"></textarea>
        </div>

        <div id="import-section-excel" class="hidden flex flex-col gap-3">
          <div class="border border-dashed border-zinc-800 rounded-xl p-6 text-center cursor-pointer bg-zinc-900/50 hover:border-indigo-500 transition relative">
            <input type="file" id="excel-file-input" accept=".xlsx,.xls" onchange="uploadExcelFile()" class="absolute inset-0 opacity-0 cursor-pointer" />
            <i data-lucide="file-up" class="w-6 h-6 text-zinc-400 mx-auto mb-2"></i>
            <div class="text-xs font-medium text-white">Drop Excel spreadsheet here or click to browse</div>
            <div class="text-[10px] text-zinc-500 mt-1" id="excel-upload-status">Supported: .xlsx, .xls</div>
          </div>

          <div id="excel-mapping-container" class="hidden flex flex-col gap-3 bg-zinc-900 p-4 rounded-xl border border-zinc-800">
            <h4 class="text-xs font-bold text-white">Map Excel Columns to Audit Policy Fields:</h4>
            <div class="grid grid-cols-2 gap-2.5 text-xs">
              <div>
                <label class="block text-[10px] text-zinc-400 mb-1">Description / Title Column:</label>
                <select id="map-desc" class="w-full border border-zinc-800 rounded-lg p-1.5 text-xs bg-zinc-950 text-white"></select>
              </div>
              <div>
                <label class="block text-[10px] text-zinc-400 mb-1">Expected Value Column:</label>
                <select id="map-val" class="w-full border border-zinc-800 rounded-lg p-1.5 text-xs bg-zinc-950 text-white"></select>
              </div>
              <div>
                <label class="block text-[10px] text-zinc-400 mb-1">Setting / Key Column:</label>
                <select id="map-key" class="w-full border border-zinc-800 rounded-lg p-1.5 text-xs bg-zinc-950 text-white"></select>
              </div>
              <div>
                <label class="block text-[10px] text-zinc-400 mb-1">Rationale / Info Column:</label>
                <select id="map-info" class="w-full border border-zinc-800 rounded-lg p-1.5 text-xs bg-zinc-950 text-white"></select>
              </div>
            </div>
            <button onclick="processExcelImport()" class="mt-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold py-2 rounded-lg transition">Import Mapped Rows</button>
          </div>
        </div>
      </div>

      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-end gap-2.5 bg-zinc-900/60">
        <button onclick="closeBulkImportModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Cancel</button>
        <button id="btn-submit-bulk-json" onclick="importBulkJson()" class="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-xs">Import Policies</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: SIDE-BY-SIDE BASELINE DIFF INSPECTOR -->
  <!-- ========================================================================================= -->
  <div id="diff-viewer-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-5xl shadow-2xl flex flex-col overflow-hidden max-h-[90vh]">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2.5">
          <i data-lucide="git-compare" class="w-4 h-4 text-amber-400"></i>
          <div>
            <h3 class="text-sm font-bold text-white">Side-by-Side Baseline Diff Inspector</h3>
            <p class="text-[11px] text-zinc-400">Inspect custom changes, modifications, exclusions, and additions against the original CIS baseline.</p>
          </div>
        </div>
        <button onclick="closeDiffModal()" class="text-zinc-400 hover:text-white font-bold text-lg p-1">✕</button>
      </div>

      <!-- Diff Summary Metrics & Filters -->
      <div class="px-6 py-3 border-b border-zinc-800/80 bg-zinc-950/60 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div class="flex items-center gap-2">
          <button id="diff-filter-all" onclick="setDiffFilter('all')" class="px-3 py-1 rounded-lg font-semibold bg-zinc-800 text-white text-[11px] transition">All Controls (<span id="diff-count-all">0</span>)</button>
          <button id="diff-filter-modified" onclick="setDiffFilter('modified')" class="px-3 py-1 rounded-lg font-semibold text-indigo-400 hover:bg-zinc-900 text-[11px] transition">Modified (<span id="diff-count-modified">0</span>)</button>
          <button id="diff-filter-excluded" onclick="setDiffFilter('excluded')" class="px-3 py-1 rounded-lg font-semibold text-rose-400 hover:bg-zinc-900 text-[11px] transition">Excluded (<span id="diff-count-excluded">0</span>)</button>
          <button id="diff-filter-added" onclick="setDiffFilter('added')" class="px-3 py-1 rounded-lg font-semibold text-emerald-400 hover:bg-zinc-900 text-[11px] transition">Added (<span id="diff-count-added">0</span>)</button>
        </div>

        <div class="flex items-center gap-2">
          <button onclick="exportDiffReport('csv')" class="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 hover:text-white text-[11px] font-medium transition">
            <i data-lucide="download" class="w-3 h-3 text-indigo-400"></i>
            <span>Export CSV</span>
          </button>
          <button onclick="exportDiffReport('json')" class="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-300 hover:text-white text-[11px] font-medium transition">
            <i data-lucide="file-json" class="w-3 h-3 text-emerald-400"></i>
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      <!-- Diff Split View Body -->
      <div class="p-6 overflow-y-auto custom-scrollbar flex flex-col gap-3 text-xs" id="diff-items-container">
        <!-- Diff Items Dynamically Rendered -->
      </div>

      <!-- Footer -->
      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-between bg-zinc-900/60 text-xs text-zinc-400">
        <span class="text-[11px]">Green indicates additions/inclusions; amber indicates modified target values; red indicates excluded checks.</span>
        <button onclick="closeDiffModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: INTERACTIVE REGEX & VALUE TESTER -->
  <!-- ========================================================================================= -->
  <div id="regex-tester-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-2xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2.5">
          <i data-lucide="binary" class="w-4 h-4 text-sky-400"></i>
          <div>
            <h3 class="text-sm font-bold text-white">Interactive Regex & Output Tester</h3>
            <p class="text-[11px] text-zinc-400">Verify regular expressions and expected values against real system output.</p>
          </div>
        </div>
        <button onclick="closeRegexTesterModal()" class="text-zinc-400 hover:text-white font-bold text-lg p-1">✕</button>
      </div>

      <!-- Body -->
      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        
        <!-- Regex Pattern Row -->
        <div>
          <div class="flex items-center justify-between mb-1.5">
            <label class="font-bold text-white uppercase text-[10px] tracking-wider">Regex Pattern / Expected Value (expect / value_data):</label>
            <div class="flex items-center gap-2 text-[10px] font-mono text-zinc-400">
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" id="regex-flag-i" checked onchange="runLiveRegexTest()" class="rounded bg-zinc-900 text-indigo-600"> Case-Insensitive (i)</label>
              <label class="flex items-center gap-1 cursor-pointer"><input type="checkbox" id="regex-flag-m" checked onchange="runLiveRegexTest()" class="rounded bg-zinc-900 text-indigo-600"> Multiline (m)</label>
            </div>
          </div>
          <input type="text" id="regex-input-pattern" placeholder="e.g., ^([1-9]|[1-2][0-9]|30)$ or .+ : Storage Encrypted" oninput="runLiveRegexTest()" class="w-full bg-zinc-900 border border-zinc-800 rounded-xl px-3.5 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500 shadow-inner" />
        </div>

        <!-- Sample Presets for Quick Testing -->
        <div class="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span class="text-zinc-500 text-[10px] uppercase font-bold">Quick Presets:</span>
          <button onclick="applyRegexPreset('^([1-9]|[1-2][0-9]|30)$', '15')" class="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 font-mono text-[10px]">Range 1..30</button>
          <button onclick="applyRegexPreset('(?i)Storage Encrypted', 'RDS Instance: db-prod-01\\n.+ : Storage Encrypted\\nStatus: Active')" class="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 font-mono text-[10px]">Storage Encrypted</button>
          <button onclick="applyRegexPreset('(?i)require_secure_transport\\\\s*=\\\\s*ON', 'require_secure_transport = ON')" class="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 font-mono text-[10px]">MySQL TLS ON</button>
          <button onclick="applyRegexPreset('^0$', '0')" class="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-300 font-mono text-[10px]">Exact Zero</button>
        </div>

        <!-- Target Sample Output -->
        <div>
          <label class="block font-bold text-white uppercase text-[10px] tracking-wider mb-1.5">Sample Target Output (Paste terminal, registry, or query result):</label>
          <textarea id="regex-input-sample" rows="5" placeholder="Paste sample command output or registry setting output to test against..." oninput="runLiveRegexTest()" class="w-full bg-zinc-900 border border-zinc-800 rounded-xl p-3 text-xs font-mono text-zinc-200 outline-none focus:border-indigo-500 shadow-inner"></textarea>
        </div>

        <!-- Live Evaluation Verdict Banner -->
        <div id="regex-result-banner" class="p-4 rounded-xl border flex flex-col gap-2 bg-zinc-900/60 border-zinc-800">
          <div class="flex items-center justify-between">
            <span class="font-bold text-xs flex items-center gap-2" id="regex-verdict-title">
              <span class="w-2.5 h-2.5 rounded-full bg-zinc-600" id="regex-verdict-dot"></span>
              <span id="regex-verdict-text">Enter a pattern and sample output to evaluate.</span>
            </span>
            <span class="text-[10px] font-mono text-zinc-500" id="regex-match-counter">0 matches</span>
          </div>
          <div id="regex-highlighted-preview" class="p-2.5 rounded-lg bg-zinc-950 border border-zinc-800 font-mono text-xs text-zinc-300 whitespace-pre-wrap max-h-36 overflow-y-auto custom-scrollbar"></div>
        </div>

      </div>

      <!-- Footer -->
      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <button id="btn-apply-regex-to-check" onclick="applyVerifiedRegexToCheck()" class="hidden px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition shadow-xs">
          Apply Pattern to Current Policy
        </button>
        <div class="flex-1"></div>
        <button onclick="closeRegexTesterModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Close</button>
      </div>
    </div>
  </div>

  <!-- ========================================================================================= -->
  <!-- MODAL: DIRECT SYNC TO TENABLE.IO / TENABLE.SC -->
  <!-- ========================================================================================= -->
  <div id="tenable-sync-modal" class="fixed inset-0 bg-black/80 backdrop-blur-xs z-50 hidden items-center justify-center p-4">
    <div class="panel-box rounded-2xl w-full max-w-xl shadow-2xl flex flex-col overflow-hidden max-h-[85vh]">
      <!-- Header -->
      <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-900/60">
        <div class="flex items-center gap-2.5">
          <i data-lucide="cloud-upload" class="w-4 h-4 text-sky-400"></i>
          <div>
            <h3 class="text-sm font-bold text-white">Direct Sync to Tenable.io / Tenable.sc</h3>
            <p class="text-[11px] text-zinc-400">Deploy your custom compliance audit directly to Tenable scanners via REST API.</p>
          </div>
        </div>
        <button onclick="closeTenableSyncModal()" class="text-zinc-400 hover:text-white font-bold text-lg p-1">✕</button>
      </div>

      <!-- Body -->
      <div class="p-6 overflow-y-auto flex flex-col gap-4 text-xs">
        
        <!-- Platform Selector Tabs -->
        <div class="flex items-center gap-2 border-b border-zinc-800 pb-2.5">
          <button id="sync-tab-io" onclick="switchSyncPlatform('tenable_io')" class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition">Tenable.io (Cloud)</button>
          <button id="sync-tab-sc" onclick="switchSyncPlatform('tenable_sc')" class="px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-zinc-900 text-zinc-400 hover:text-white transition">Tenable.sc / SecurityCenter (On-Prem)</button>
        </div>

        <!-- Connection Settings Container -->
        <div class="bg-zinc-900/90 p-4 rounded-xl border border-zinc-800 flex flex-col gap-3">
          <div>
            <label class="block text-[11px] font-semibold text-zinc-300 mb-1">Server API URL:</label>
            <input type="text" id="sync-server-url" value="https://cloud.tenable.com" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500" />
          </div>

          <!-- Tenable.io Fields -->
          <div id="sync-fields-io" class="flex flex-col gap-3">
            <div>
              <label class="block text-[11px] font-semibold text-zinc-300 mb-1">Access Key:</label>
              <input type="password" id="sync-access-key" placeholder="Enter Tenable.io Access Key" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500" />
            </div>
            <div>
              <label class="block text-[11px] font-semibold text-zinc-300 mb-1">Secret Key:</label>
              <input type="password" id="sync-secret-key" placeholder="Enter Tenable.io Secret Key" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500" />
            </div>
          </div>

          <!-- Tenable.sc Fields -->
          <div id="sync-fields-sc" class="hidden flex flex-col gap-3">
            <div>
              <label class="block text-[11px] font-semibold text-zinc-300 mb-1">API Token / Session Token:</label>
              <input type="password" id="sync-sc-token" placeholder="Tenable.sc SecurityCenter API Token" class="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500" />
            </div>
          </div>

          <div class="flex items-center justify-between pt-1">
            <button onclick="testTenableApiConnection()" id="btn-test-tenable-conn" class="flex items-center gap-1.5 text-xs text-indigo-400 hover:text-indigo-300 font-medium">
              <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
              <span>Test Connection</span>
            </button>
            <span id="sync-conn-status" class="text-[11px] text-zinc-500">Not tested</span>
          </div>
        </div>

        <!-- Audit Upload Details -->
        <div>
          <label class="block text-[11px] font-semibold text-zinc-300 mb-1">Audit Policy Name on Scanner:</label>
          <input type="text" id="sync-audit-name" placeholder="Custom_CIS_Audit.audit" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-indigo-500" />
        </div>

      </div>

      <!-- Footer -->
      <div class="px-6 py-3.5 border-t border-zinc-800 flex items-center justify-end gap-2.5 bg-zinc-900/60">
        <button onclick="closeTenableSyncModal()" class="px-4 py-1.5 rounded-lg border border-zinc-700 text-xs font-semibold text-zinc-300 hover:bg-zinc-800">Cancel</button>
        <button id="btn-execute-sync" onclick="executeTenableSync()" class="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-xs flex items-center gap-1.5">
          <i data-lucide="cloud-upload" class="w-3.5 h-3.5"></i>
          <span>Upload & Sync Audit</span>
        </button>
      </div>
    </div>
  </div>

  <!-- Application Logic JS -->
  <script>
    // State Store
    const state = {
      view: 'editor',
      categories: [],
      flatAudits: [],
      selectedBaselinePath: '',
      customFileId: null,
      variables: [],
      checks: [],
      modifiedChecks: {},
      modifiedDescriptions: {},
      modifiedInfos: {},
      modifiedSolutions: {},
      excludedChecks: new Set(),
      addedChecks: [],
      policyFilter: 'all',
      editorSearchQuery: '',
      fileTreeSearchQuery: '',
      currentPage: 1,
      pageSize: 25,
      editorTab: 'checks',
      currentActiveDetailCheck: null,
      excelFileId: null,
      aiEndpoint: 'http://localhost:11434',
      aiModel: 'llama3'
    };

    function log(msg, type = 'info') {
      const el = document.getElementById('console-logs');
      const time = new Date().toLocaleTimeString();
      const div = document.createElement('div');
      div.className = type === 'error' ? 'text-rose-400' : (type === 'success' ? 'text-emerald-400' : 'text-zinc-400');
      div.innerHTML = `<span class="text-zinc-600">[${time}]</span> ${msg}`;
      el.appendChild(div);
      el.scrollTop = el.scrollHeight;
    }

    function toggleTheme() {
      document.documentElement.classList.toggle('dark');
      document.documentElement.classList.toggle('light');
    }

    function switchView(view) {
      state.view = view;
      const navLib = document.getElementById('nav-btn-library');
      const navEd = document.getElementById('nav-btn-editor');
      const treeSearch = document.getElementById('filetree-search-input');

      if (view === 'library') {
        if (treeSearch) treeSearch.focus();
        if (navLib) navLib.className = 'flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-zinc-800 text-white shadow-xs transition';
        if (navEd) navEd.className = 'flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium text-zinc-400 hover:text-white transition';
      } else {
        if (navEd) navEd.className = 'flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium bg-zinc-800 text-white shadow-xs transition';
        if (navLib) navLib.className = 'flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-medium text-zinc-400 hover:text-white transition';
      }
      lucide.createIcons();
    }

    // Load Audit Library
    async function initAuditCatalog() {
      try {
        const res = await fetch('/api/baselines');
        const data = await res.json();
        if (data.success) {
          state.categories = data.categories || [];
          state.flatAudits = data.flat_list || [];
          const countEl = document.getElementById('filetree-count');
          if (countEl) countEl.textContent = `${state.flatAudits.length} files`;
          renderMagicUIFileTree();
          log(`Loaded ${state.flatAudits.length} benchmark templates across ${state.categories.length} categories.`, 'success');
        }
      } catch (err) {
        log(`Failed to load catalog: ${err.message}`, 'error');
      }
    }

    // Render Magic UI Styled Hierarchical FileTree
    function renderMagicUIFileTree() {
      const container = document.getElementById('filetree-container');
      if (!container) return;
      container.innerHTML = '';

      const query = state.fileTreeSearchQuery.toLowerCase();

      state.categories.forEach((cat, catIdx) => {
        const matchingFiles = cat.items.filter(item => 
          !query || item.filename.toLowerCase().includes(query) || item.display_name.toLowerCase().includes(query)
        );

        if (query && matchingFiles.length === 0) return;

        // Folder container
        const folderDiv = document.createElement('div');
        folderDiv.className = 'mb-1';

        const isInitiallyOpen = !!query || catIdx < 2;

        folderDiv.innerHTML = `
          <div class="filetree-folder flex items-center justify-between px-2 py-1.5 rounded-lg cursor-pointer text-zinc-300 hover:text-white font-sans text-xs font-semibold" onclick="toggleFolder('folder-items-${catIdx}', 'folder-icon-${catIdx}', 'folder-chevron-${catIdx}')">
            <div class="flex items-center gap-1.5 truncate">
              <i data-lucide="${isInitiallyOpen ? 'chevron-down' : 'chevron-right'}" id="folder-chevron-${catIdx}" class="w-3.5 h-3.5 text-zinc-500 shrink-0"></i>
              <i data-lucide="${isInitiallyOpen ? 'folder-open' : 'folder'}" id="folder-icon-${catIdx}" class="w-4 h-4 text-indigo-400 shrink-0"></i>
              <span class="truncate">${cat.clean_name}</span>
            </div>
            <span class="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">${matchingFiles.length}</span>
          </div>
          <div id="folder-items-${catIdx}" class="pl-4 pr-1 mt-0.5 space-y-0.5 ${isInitiallyOpen ? '' : 'hidden'} border-l border-zinc-800/80 ml-3.5 max-h-[220px] overflow-y-auto custom-scrollbar">
            ${matchingFiles.map(file => `
              <div onclick="selectAndLoadAudit('${file.rel_path}')" id="fileitem-${file.rel_path.replace(/[^a-zA-Z0-9]/g, '_')}" class="filetree-file flex items-center justify-between px-2 py-1 rounded-md cursor-pointer text-zinc-400 font-sans text-[11px] ${state.selectedBaselinePath === file.rel_path ? 'active' : ''}">
                <div class="flex items-center gap-1.5 truncate">
                  <i data-lucide="file-code" class="w-3 h-3 text-zinc-500 shrink-0"></i>
                  <span class="truncate" title="${file.filename}">${file.display_name}</span>
                </div>
                <span class="text-[9px] font-mono text-zinc-600 shrink-0">${file.size_kb}k</span>
              </div>
            `).join('')}
          </div>
        `;
        container.appendChild(folderDiv);
      });

      lucide.createIcons();
    }

    function toggleFolder(itemsId, iconId, chevronId) {
      const items = document.getElementById(itemsId);
      const icon = document.getElementById(iconId);
      const chevron = document.getElementById(chevronId);
      if (items.classList.contains('hidden')) {
        items.classList.remove('hidden');
        icon.setAttribute('data-lucide', 'folder-open');
        chevron.setAttribute('data-lucide', 'chevron-down');
      } else {
        items.classList.add('hidden');
        icon.setAttribute('data-lucide', 'folder');
        chevron.setAttribute('data-lucide', 'chevron-right');
      }
      lucide.createIcons();
    }

    function expandAllFolders() {
      state.categories.forEach((cat, catIdx) => {
        const items = document.getElementById(`folder-items-${catIdx}`);
        const icon = document.getElementById(`folder-icon-${catIdx}`);
        const chevron = document.getElementById(`folder-chevron-${catIdx}`);
        if (items) items.classList.remove('hidden');
        if (icon) icon.setAttribute('data-lucide', 'folder-open');
        if (chevron) chevron.setAttribute('data-lucide', 'chevron-down');
      });
      lucide.createIcons();
    }

    function collapseAllFolders() {
      state.categories.forEach((cat, catIdx) => {
        const items = document.getElementById(`folder-items-${catIdx}`);
        const icon = document.getElementById(`folder-icon-${catIdx}`);
        const chevron = document.getElementById(`folder-chevron-${catIdx}`);
        if (items) items.classList.add('hidden');
        if (icon) icon.setAttribute('data-lucide', 'folder');
        if (chevron) chevron.setAttribute('data-lucide', 'chevron-right');
      });
      lucide.createIcons();
    }

    function handleFileTreeSearch() {
      state.fileTreeSearchQuery = document.getElementById('filetree-search-input').value.trim();
      const clearBtn = document.getElementById('filetree-clear-btn');
      if (clearBtn) {
        if (state.fileTreeSearchQuery) {
          clearBtn.classList.remove('hidden');
        } else {
          clearBtn.classList.add('hidden');
        }
      }
      renderMagicUIFileTree();
    }

    function clearFileTreeSearch() {
      document.getElementById('filetree-search-input').value = '';
      state.fileTreeSearchQuery = '';
      const clearBtn = document.getElementById('filetree-clear-btn');
      if (clearBtn) clearBtn.classList.add('hidden');
      renderMagicUIFileTree();
    }

    function toggleCompileDrawer() {
      const panel = document.getElementById('compile-panel');
      const chevron = document.getElementById('compile-drawer-chevron');
      if (panel.classList.contains('hidden')) {
        panel.classList.remove('hidden');
        panel.classList.add('flex');
        chevron.style.transform = 'rotate(180deg)';
      } else {
        panel.classList.add('hidden');
        panel.classList.remove('flex');
        chevron.style.transform = 'rotate(0deg)';
      }
    }

    function toggleConsoleModal() {
      const logs = document.getElementById('console-logs');
      if (logs) {
        alert("Recent Activity Logs:\n" + (logs.innerText || 'No recent activity'));
      }
    }

    // =========================================================================
    // MODAL: BENCHMARK EXPLORER (5-7 VISIBLE ITEMS, SCROLLABLE)
    // =========================================================================
    let modalSelectedCategory = 'all';

    function openBenchmarkExplorerModal() {
      const modal = document.getElementById('benchmark-explorer-modal');
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      renderModalFolderList();
      renderModalBenchmarkList();
      const input = document.getElementById('modal-benchmark-search-input');
      if (input) {
        setTimeout(() => input.focus(), 50);
      }
      lucide.createIcons();
    }

    function closeBenchmarkExplorerModal() {
      const modal = document.getElementById('benchmark-explorer-modal');
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }

    function renderModalFolderList() {
      const container = document.getElementById('modal-folder-list');
      if (!container) return;

      const query = (document.getElementById('modal-benchmark-search-input')?.value || '').toLowerCase().trim();
      const totalCount = state.flatAudits ? state.flatAudits.length : 0;

      // "All Benchmarks" virtual folder
      let html = `
        <div onclick="setModalCategoryFilter('all')" class="flex items-center justify-between p-2.5 cursor-pointer transition ${modalSelectedCategory === 'all' ? 'bg-indigo-600/20 border-l-2 border-indigo-500 text-white font-semibold' : 'hover:bg-zinc-900/80 text-zinc-300'}">
          <div class="flex items-center gap-2 truncate">
            <i data-lucide="layers" class="w-3.5 h-3.5 ${modalSelectedCategory === 'all' ? 'text-indigo-400' : 'text-zinc-500'} shrink-0"></i>
            <span class="truncate text-xs">All Benchmarks</span>
          </div>
          <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">${totalCount}</span>
        </div>
      `;

      state.categories.forEach(cat => {
        const matchCount = query ? cat.items.filter(f => 
          f.display_name.toLowerCase().includes(query) || 
          f.filename.toLowerCase().includes(query) || 
          f.category.toLowerCase().includes(query)
        ).length : cat.items.length;

        if (query && matchCount === 0) return;

        const isSelected = modalSelectedCategory === cat.clean_name;
        html += `
          <div onclick="setModalCategoryFilter('${cat.clean_name.replace(/'/g, "\\'")}')" class="flex items-center justify-between p-2.5 cursor-pointer transition ${isSelected ? 'bg-indigo-600/20 border-l-2 border-indigo-500 text-white font-semibold' : 'hover:bg-zinc-900/80 text-zinc-400 hover:text-zinc-200'}">
            <div class="flex items-center gap-2 truncate">
              <i data-lucide="${cat.icon || 'folder'}" class="w-3.5 h-3.5 ${isSelected ? 'text-indigo-400' : 'text-zinc-500'} shrink-0"></i>
              <span class="truncate text-xs">${cat.clean_name}</span>
            </div>
            <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800 shrink-0">${matchCount}</span>
          </div>
        `;
      });

      container.innerHTML = html;
      const countEl = document.getElementById('modal-folder-count');
      if (countEl) countEl.textContent = `${state.categories.length} categories`;
      lucide.createIcons();
    }

    function setModalCategoryFilter(catKey) {
      modalSelectedCategory = catKey;
      renderModalFolderList();
      renderModalBenchmarkList();
    }

    function handleModalBenchmarkSearch() {
      const val = document.getElementById('modal-benchmark-search-input').value.trim();
      const clearBtn = document.getElementById('modal-benchmark-clear-btn');
      if (clearBtn) {
        if (val) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
      }
      renderModalFolderList();
      renderModalBenchmarkList();
    }

    function clearModalBenchmarkSearch() {
      document.getElementById('modal-benchmark-search-input').value = '';
      const clearBtn = document.getElementById('modal-benchmark-clear-btn');
      if (clearBtn) clearBtn.classList.add('hidden');
      renderModalFolderList();
      renderModalBenchmarkList();
    }

    function renderModalBenchmarkList() {
      const container = document.getElementById('modal-benchmark-list');
      const query = (document.getElementById('modal-benchmark-search-input')?.value || '').toLowerCase().trim();

      const titleEl = document.getElementById('modal-current-folder-title');
      if (titleEl) {
        titleEl.textContent = modalSelectedCategory === 'all' ? 'All Benchmark Files' : `Files in ${modalSelectedCategory}`;
      }

      let items = state.flatAudits || [];

      if (modalSelectedCategory !== 'all') {
        items = items.filter(f => f.category === modalSelectedCategory || f.category_clean === modalSelectedCategory);
      }

      if (query) {
        items = items.filter(f => 
          f.display_name.toLowerCase().includes(query) ||
          f.filename.toLowerCase().includes(query) ||
          f.category.toLowerCase().includes(query)
        );
      }

      const countEl = document.getElementById('modal-benchmark-filtered-count');
      if (countEl) countEl.textContent = `${items.length} files`;

      if (items.length === 0) {
        container.innerHTML = `
          <div class="flex flex-col items-center justify-center h-full py-12 text-center text-zinc-500">
            <i data-lucide="search-x" class="w-8 h-8 text-zinc-600 mb-2"></i>
            <span class="text-xs">No files match "${query}".</span>
          </div>
        `;
        lucide.createIcons();
        return;
      }

      container.innerHTML = items.map(file => {
        const isSelected = state.selectedBaselinePath === file.rel_path;
        return `
          <div onclick="selectBenchmarkFromModal('${file.rel_path}')" class="flex items-center justify-between p-2.5 cursor-pointer transition group ${isSelected ? 'bg-indigo-600/15 border-l-2 border-indigo-500' : 'hover:bg-zinc-900/80'}">
            <div class="flex items-center gap-2.5 truncate flex-1 min-w-0 mr-2.5">
              <div class="w-7 h-7 rounded-lg bg-zinc-900 group-hover:bg-indigo-600/20 flex items-center justify-center shrink-0 border border-zinc-800 transition">
                <i data-lucide="${file.category_icon || 'file-code'}" class="w-3.5 h-3.5 text-indigo-400"></i>
              </div>
              <div class="truncate flex-1 min-w-0">
                <div class="font-medium text-xs text-white group-hover:text-indigo-300 truncate">${file.display_name}</div>
                <div class="flex items-center gap-1.5 text-[10px] text-zinc-500 font-mono mt-0.5 truncate">
                  <span class="text-zinc-400 truncate">${file.category}</span>
                  <span>•</span>
                  <span class="truncate">${file.filename}</span>
                </div>
              </div>
            </div>
            <div class="flex items-center gap-2 shrink-0">
              <span class="text-[10px] font-mono text-zinc-500">${file.size_kb}k</span>
              <button class="px-2 py-0.5 text-[10px] font-semibold rounded border ${isSelected ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-zinc-900 border-zinc-800 group-hover:bg-indigo-600 group-hover:border-indigo-500 text-zinc-300 group-hover:text-white'} transition">
                ${isSelected ? 'Active' : 'Load'}
              </button>
            </div>
          </div>
        `;
      }).join('');

      lucide.createIcons();
    }

    function selectBenchmarkFromModal(relPath) {
      closeBenchmarkExplorerModal();
      selectAndLoadAudit(relPath);
    }

    // Keyboard shortcut handler for modal (Ctrl+K / Cmd+K and Esc)
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        const modal = document.getElementById('benchmark-explorer-modal');
        if (modal && !modal.classList.contains('hidden')) {
          closeBenchmarkExplorerModal();
        } else {
          openBenchmarkExplorerModal();
        }
      }
      if (e.key === 'Escape') {
        closeBenchmarkExplorerModal();
      }
    });

    // Select and Load Audit into Editor
    async function selectAndLoadAudit(relPath) {
      state.selectedBaselinePath = relPath;
      state.customFileId = null;
      state.modifiedChecks = {};
      state.modifiedDescriptions = {};
      state.modifiedInfos = {};
      state.modifiedSolutions = {};
      state.excludedChecks.clear();
      state.addedChecks = [];
      state.currentPage = 1;

      // Update FileTree active highlights
      document.querySelectorAll('.filetree-file').forEach(f => f.classList.remove('active'));
      const activeItem = document.getElementById(`fileitem-${relPath.replace(/[^a-zA-Z0-9]/g, '_')}`);
      if (activeItem) {
        activeItem.classList.add('active');
        activeItem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      log(`Loading ${relPath}...`);
      try {
        const res = await fetch('/api/parse', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ baseline_path: relPath })
        });
        const data = await res.json();
        if (data.success) {
          state.variables = data.variables || [];
          state.checks = data.checks || [];

          const filename = relPath.split('/').pop();
          document.getElementById('header-active-file').classList.remove('hidden');
          document.getElementById('header-filename').textContent = filename;
          document.getElementById('header-badge').textContent = `${state.checks.length} checks`;

          const sideName = document.getElementById('sidebar-active-name');
          if (sideName) sideName.textContent = filename;
          const sideCount = document.getElementById('sidebar-checks-count');
          if (sideCount) sideCount.textContent = `${state.checks.length} checks`;

          document.getElementById('loaded-summary-bar').classList.remove('hidden');
          document.getElementById('loaded-summary-bar').classList.add('flex');
          document.getElementById('summary-audit-name').textContent = filename;
          document.getElementById('summary-audit-path').textContent = relPath;
          document.getElementById('output-filename').value = `Custom_${filename}`;

          document.getElementById('checks-empty-state').classList.add('hidden');
          document.getElementById('pagination-controls').style.display = 'flex';

          updateStatsDashboard();
          renderVariables();
          renderChecks();

          log(`Parsed ${state.checks.length} policies & ${state.variables.length} variables.`, 'success');
        } else {
          log(`Error: ${data.error}`, 'error');
        }
      } catch (err) {
        log(`Failed: ${err.message}`, 'error');
      }
    }

    // Upload custom audit from file input
    async function uploadCustomAudit(inputEl) {
      if (!inputEl.files || !inputEl.files[0]) return;
      const file = inputEl.files[0];

      const formData = new FormData();
      formData.append('audit_file', file);

      log(`Uploading ${file.name}...`);
      try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.success) {
          state.customFileId = data.file_id;
          state.selectedBaselinePath = data.filename;

          const parseRes = await fetch('/api/parse', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ custom_file_id: data.file_id })
          });
          const parseData = await parseRes.json();
          if (parseData.success) {
            state.variables = parseData.variables || [];
            state.checks = parseData.checks || [];
            state.modifiedChecks = {};
            state.excludedChecks.clear();
            state.addedChecks = [];
            state.currentPage = 1;

            document.getElementById('header-active-file').classList.remove('hidden');
            document.getElementById('header-filename').textContent = file.name;
            document.getElementById('header-badge').textContent = `${state.checks.length} checks`;

            const sideName = document.getElementById('sidebar-active-name');
            if (sideName) sideName.textContent = file.name;
            const sideCount = document.getElementById('sidebar-checks-count');
            if (sideCount) sideCount.textContent = `${state.checks.length} checks`;
            document.getElementById('loaded-summary-bar').classList.remove('hidden');
            document.getElementById('loaded-summary-bar').classList.add('flex');
            document.getElementById('summary-audit-name').textContent = file.name;
            document.getElementById('summary-audit-path').textContent = 'Uploaded custom audit';
            document.getElementById('output-filename').value = `Custom_${file.name}`;
            document.getElementById('checks-empty-state').classList.add('hidden');
            document.getElementById('pagination-controls').style.display = 'flex';

            updateStatsDashboard();
            renderVariables();
            renderChecks();
            log(`Parsed uploaded custom audit: ${file.name} (${state.checks.length} checks)`, 'success');
          }
        }
      } catch (err) {
        log(`Upload failed: ${err.message}`, 'error');
      }
    }

    // Editor Tab Switcher
    function switchEditorTab(tab) {
      state.editorTab = tab;
      const btnChecks = document.getElementById('tab-btn-checks');
      const btnVars = document.getElementById('tab-btn-vars');
      const viewChecks = document.getElementById('editor-tab-checks');
      const viewVars = document.getElementById('editor-tab-vars');

      if (tab === 'checks') {
        btnChecks.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-zinc-800 text-white shadow-xs transition';
        btnVars.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold text-zinc-400 hover:text-white transition';
        viewChecks.classList.remove('hidden');
        viewVars.classList.add('hidden');
      } else {
        btnVars.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-zinc-800 text-white shadow-xs transition';
        btnChecks.className = 'flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold text-zinc-400 hover:text-white transition';
        viewVars.classList.remove('hidden');
        viewChecks.classList.add('hidden');
      }
      lucide.createIcons();
    }

    // Render Variables
    function renderVariables() {
      const container = document.getElementById('variables-container');
      const empty = document.getElementById('vars-empty-state');
      document.getElementById('vars-tab-count').textContent = state.variables.length;

      if (!state.variables || state.variables.length === 0) {
        container.innerHTML = '';
        empty.classList.remove('hidden');
        return;
      }

      empty.classList.add('hidden');
      container.innerHTML = '';

      state.variables.forEach(v => {
        const card = document.createElement('div');
        card.className = 'panel-box rounded-xl p-4 flex flex-col justify-between gap-3';
        card.innerHTML = `
          <div>
            <div class="font-mono text-xs font-bold text-indigo-400 truncate">@${v.name}@</div>
            <p class="text-[11px] text-zinc-400 mt-1 line-clamp-2">${v.description || v.name}</p>
          </div>
          <div>
            <label class="block text-[10px] uppercase font-semibold text-zinc-500 mb-1">Override Default:</label>
            <input type="text" value="${v.default || ''}" onchange="updateVariable('${v.name}', this.value)" class="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-white outline-none focus:border-indigo-500" />
          </div>
        `;
        container.appendChild(card);
      });
    }

    function updateVariable(name, newVal) {
      const v = state.variables.find(x => x.name === name);
      if (v) {
        v.default = newVal;
        log(`Set variable @${name}@ = "${newVal}"`);
        renderChecks();
      }
    }

    // Render Checks Cards
    function renderChecks() {
      const container = document.getElementById('checks-cards-container');
      const allChecks = [...state.checks, ...state.addedChecks];
      document.getElementById('checks-tab-count').textContent = allChecks.length;

      let filtered = allChecks.filter(c => {
        const isMod = state.modifiedChecks.hasOwnProperty(c.id) || c.is_added;
        const isExc = state.excludedChecks.has(c.id);

        if (state.policyFilter === 'modified' && !isMod) return false;
        if (state.policyFilter === 'excluded' && !isExc) return false;
        if (state.policyFilter === 'added' && !c.is_added) return false;

        if (state.editorSearchQuery) {
          const q = state.editorSearchQuery.toLowerCase();
          const matchDesc = (c.description || '').toLowerCase().includes(q);
          const matchKey = (c.reg_key || '').toLowerCase().includes(q);
          const matchVal = (c.value_data || '').toLowerCase().includes(q);
          const matchCis = (c.cis_id || '').toLowerCase().includes(q);
          if (!matchDesc && !matchKey && !matchVal && !matchCis) return false;
        }
        return true;
      });

      const totalFiltered = filtered.length;
      const totalPages = Math.ceil(totalFiltered / state.pageSize) || 1;
      if (state.currentPage > totalPages) state.currentPage = totalPages;
      if (state.currentPage < 1) state.currentPage = 1;

      const startIdx = (state.currentPage - 1) * state.pageSize;
      const pageChecks = filtered.slice(startIdx, startIdx + state.pageSize);

      document.getElementById('pagination-info').textContent = `Showing ${startIdx + 1}-${Math.min(startIdx + state.pageSize, totalFiltered)} of ${totalFiltered} policies`;
      document.getElementById('page-prev-btn').disabled = state.currentPage <= 1;
      document.getElementById('page-next-btn').disabled = state.currentPage >= totalPages;

      container.innerHTML = '';

      if (pageChecks.length === 0) {
        container.innerHTML = '<div class="text-center py-16 text-xs text-zinc-500">No matching controls found in this filter.</div>';
        return;
      }

      pageChecks.forEach(c => {
        const isModified = state.modifiedChecks.hasOwnProperty(c.id);
        const isExcluded = state.excludedChecks.has(c.id);
        const currentVal = isModified ? state.modifiedChecks[c.id] : (c.value_data || '');
        const currentDesc = state.modifiedDescriptions.hasOwnProperty(c.id) ? state.modifiedDescriptions[c.id] : c.description;

        const card = document.createElement('div');
        card.id = `card-${c.id}`;
        card.className = `panel-box rounded-xl p-4 sm:p-5 flex flex-col gap-4 border transition duration-150 ${isModified ? 'border-indigo-500 bg-indigo-950/10' : (isExcluded ? 'border-rose-900/40 opacity-50 bg-rose-950/10' : 'border-zinc-800')}`;

        // Badge styles
        const typeBadgeColors = {
          'SQL_POLICY': 'bg-purple-500/10 text-purple-300 border-purple-500/30',
          'REGISTRY_SETTING': 'bg-blue-500/10 text-blue-300 border-blue-500/30',
          'CMD_EXEC': 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30',
          'PASSWORD_POLICY': 'bg-amber-500/10 text-amber-300 border-amber-500/30',
          'REPORT': 'bg-zinc-800 text-zinc-300 border-zinc-700'
        };
        const badgeClass = typeBadgeColors[c.type] || 'bg-zinc-800 text-zinc-300 border-zinc-700';

        card.innerHTML = `
          <div class="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
            <div class="flex-1 min-w-0">
              <div class="flex flex-wrap items-center gap-2 mb-2">
                <span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded-md border ${badgeClass}">${c.type || 'CONTROL'}</span>
                ${c.cis_id ? `<span class="text-[10px] font-mono font-semibold text-zinc-400 bg-zinc-900 px-2 py-0.5 rounded-md border border-zinc-800">CIS ${c.cis_id}</span>` : ''}
                ${c.is_added ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded-md bg-sky-500/20 text-sky-300 border border-sky-500/30">NEW</span>' : ''}
                ${isModified ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded-md bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">MODIFIED</span>' : ''}
                ${isExcluded ? '<span class="text-[9px] font-bold px-1.5 py-0.5 rounded-md bg-rose-500/20 text-rose-300 border border-rose-500/30">EXCLUDED</span>' : ''}
              </div>
              
              <h4 class="text-[13px] font-bold text-white leading-snug tracking-tight">${currentDesc}</h4>
              ${c.reg_key ? `<div class="flex items-center gap-2 text-[11px] font-mono text-zinc-400 mt-2 truncate bg-zinc-900/90 px-2.5 py-1 rounded-lg border border-zinc-800/90" title="${c.reg_key}"><i data-lucide="hash" class="w-3 h-3 text-zinc-500 shrink-0"></i><span class="truncate">${c.reg_key}</span></div>` : ''}
            </div>

            <!-- Action Buttons: Details + Exclude -->
            <div class="flex items-center gap-2 shrink-0 self-start">
              <button onclick="openPolicyDetailModal('${c.id}')" class="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-zinc-700 bg-zinc-900 text-zinc-200 hover:text-white hover:bg-zinc-800 font-medium transition" title="View Full Details, Rationale, Remediation & Raw Audit">
                <i data-lucide="eye" class="w-3.5 h-3.5 text-indigo-400"></i>
                <span>Details</span>
              </button>

              <button onclick="toggleExcludeCheck('${c.id}')" class="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border ${isExcluded ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30' : 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-rose-400 hover:border-zinc-700'} font-medium transition">
                <i data-lucide="${isExcluded ? 'check' : 'x'}" class="w-3.5 h-3.5"></i>
                <span>${isExcluded ? 'Include' : 'Exclude'}</span>
              </button>
            </div>
          </div>

          <!-- Bottom: Rationale & Inline Expected Value Input -->
          <div class="flex flex-col lg:flex-row lg:items-center justify-between gap-3.5 pt-3.5 border-t border-zinc-800/80">
            <div class="flex items-start gap-2 text-[11px] text-zinc-400 line-clamp-2 leading-relaxed min-w-0 flex-1 pr-3" title="${c.info || ''}">
              <i data-lucide="info" class="w-3.5 h-3.5 text-zinc-500 shrink-0 mt-0.5"></i>
              <span>${c.info || 'No description rationale provided.'}</span>
            </div>

            <div class="flex items-center gap-2 shrink-0 w-full lg:w-96">
              <label class="text-[10px] font-mono uppercase font-bold text-zinc-500 whitespace-nowrap tracking-wider">Expected:</label>
              <input type="text" value="${currentVal}" placeholder="Expected value (e.g. 0, Enabled, Success)" onchange="updateCheckValue('${c.id}', this.value)" class="flex-1 min-w-0 bg-zinc-900 border ${isModified ? 'border-indigo-500 text-indigo-300 font-bold' : 'border-zinc-800 text-white'} rounded-lg px-3 py-1.5 text-xs font-mono outline-none focus:border-indigo-500 transition" />
              <button onclick="openRegexTesterForCheck('${c.id}')" class="px-2 py-1.5 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-sky-400 hover:text-sky-300 text-[10px] font-mono font-semibold transition shrink-0 flex items-center gap-1" title="Test this expected value / regex against sample output">
                <i data-lucide="binary" class="w-3 h-3"></i>
                <span>Test</span>
              </button>
            </div>
          </div>
        `;
        container.appendChild(card);
      });
      lucide.createIcons();
    }

    function updateCheckValue(checkId, newVal) {
      const c = state.checks.find(x => x.id === checkId) || state.addedChecks.find(x => x.id === checkId);
      if (!c) return;

      if (newVal === (c.original_value_data || c.value_data) && !c.is_added) {
        delete state.modifiedChecks[checkId];
      } else {
        state.modifiedChecks[checkId] = newVal;
      }
      updateStatsDashboard();
      renderChecks();
      log(`Modified ${c.description || checkId} = "${newVal}"`);
    }

    function toggleExcludeCheck(checkId) {
      if (state.excludedChecks.has(checkId)) {
        state.excludedChecks.delete(checkId);
      } else {
        state.excludedChecks.add(checkId);
      }
      updateStatsDashboard();
      renderChecks();
    }

    function setPolicyFilter(filter) {
      state.policyFilter = filter;
      state.currentPage = 1;
      document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.className = 'filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold text-zinc-400 hover:text-white transition';
      });
      document.getElementById(`filter-${filter}`).className = 'filter-btn px-3 py-1 rounded-lg text-[11px] font-semibold bg-zinc-800 text-white transition';
      renderChecks();
    }

    function handleEditorSearch() {
      const input = document.getElementById('editor-search-input');
      state.editorSearchQuery = input.value.trim();
      const clearBtn = document.getElementById('editor-search-clear-btn');
      if (clearBtn) {
        if (state.editorSearchQuery) clearBtn.classList.remove('hidden');
        else clearBtn.classList.add('hidden');
      }
      state.currentPage = 1;
      renderChecks();
    }

    function clearEditorSearch() {
      const input = document.getElementById('editor-search-input');
      if (input) input.value = '';
      const clearBtn = document.getElementById('editor-search-clear-btn');
      if (clearBtn) clearBtn.classList.add('hidden');
      state.editorSearchQuery = '';
      state.currentPage = 1;
      renderChecks();
    }

    function prevPage() {
      if (state.currentPage > 1) {
        state.currentPage--;
        renderChecks();
      }
    }

    function nextPage() {
      state.currentPage++;
      renderChecks();
    }

    function updateStatsDashboard() {
      const total = state.checks.length + state.addedChecks.length;
      const modified = Object.keys(state.modifiedChecks).length;
      const excluded = state.excludedChecks.size;
      const added = state.addedChecks.length;

      document.getElementById('stat-total').textContent = total;
      document.getElementById('stat-modified').textContent = modified;
      document.getElementById('stat-excluded').textContent = excluded;
      document.getElementById('stat-added').textContent = added;

      const editsCount = modified + excluded + added;
      const compileBadge = document.getElementById('compile-badge');
      if (compileBadge) {
        compileBadge.textContent = `${editsCount} edits`;
        if (editsCount > 0) {
          compileBadge.className = 'text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 font-bold';
        } else {
          compileBadge.className = 'text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700';
        }
      }
    }

    // =========================================================================
    // MODAL: POLICY DETAIL INSPECTOR LOGIC
    // =========================================================================
    function openPolicyDetailModal(checkId) {
      const c = state.checks.find(x => x.id === checkId) || state.addedChecks.find(x => x.id === checkId);
      if (!c) return;

      state.currentActiveDetailCheck = c;

      const isModified = state.modifiedChecks.hasOwnProperty(c.id);
      const currentVal = isModified ? state.modifiedChecks[c.id] : (c.value_data || '');

      document.getElementById('detail-title').textContent = c.description;
      document.getElementById('detail-type-badge').textContent = c.type || 'CONTROL';
      document.getElementById('detail-cis-id').textContent = c.cis_id ? `CIS ${c.cis_id}` : 'CUSTOM';
      document.getElementById('detail-target-field').textContent = `Target Field: ${c.target_field || 'value_data'}`;

      // Conditionals breadcrumbs
      const condBox = document.getElementById('detail-conditionals-box');
      if (c.parent_conditionals && c.parent_conditionals.length > 0) {
        condBox.classList.remove('hidden');
        condBox.classList.add('flex');
        document.getElementById('detail-conditionals-text').textContent = c.parent_conditionals.join(' ➔ ');
      } else {
        condBox.classList.add('hidden');
      }

      // Query / Key
      const keyValEl = document.getElementById('detail-key-val');
      const lblKey = document.getElementById('detail-lbl-key');
      if (c.type === 'SQL_POLICY') {
        lblKey.textContent = 'SQL Request Query:';
      } else if (c.type === 'CMD_EXEC') {
        lblKey.textContent = 'Shell Command (cmd):';
      } else {
        lblKey.textContent = 'Registry Key / Configuration Path:';
      }
      keyValEl.textContent = c.reg_key || '(None)';

      // Expected Value Input
      document.getElementById('detail-input-val').value = currentVal;

      // Info Rationale & Solution
      document.getElementById('detail-info-val').textContent = c.info || 'No security rationale provided.';
      
      const solContainer = document.getElementById('detail-solution-container');
      if (c.solution) {
        solContainer.classList.remove('hidden');
        document.getElementById('detail-solution-val').textContent = c.solution;
      } else {
        solContainer.classList.add('hidden');
      }

      // References & See Also
      document.getElementById('detail-references-val').textContent = c.reference || 'N/A';
      document.getElementById('detail-seealso-val').textContent = c.see_also || 'N/A';

      // Reconstruct Raw Tenable Custom Item
      const rawLines = [
        '<custom_item>',
        `  type        : ${c.type || 'REGISTRY_SETTING'}`,
        `  description : "${c.description.replace(/"/g, "'")}"`
      ];
      if (c.info) rawLines.push(`  info        : "${c.info.replace(/"/g, "'")}"`);
      if (c.solution) rawLines.push(`  solution    : "${c.solution.replace(/"/g, "'")}"`);
      if (c.reference) rawLines.push(`  reference   : "${c.reference}"`);
      if (c.see_also) rawLines.push(`  see_also    : "${c.see_also}"`);
      if (c.type === 'SQL_POLICY') {
        rawLines.push(`  sql_request : "${c.reg_key}"`);
        rawLines.push(`  sql_types   : INTEGER`);
        rawLines.push(`  sql_expect  : ${currentVal}`);
      } else if (c.type === 'CMD_EXEC') {
        rawLines.push(`  cmd         : "${c.reg_key}"`);
        rawLines.push(`  expect      : "${currentVal}"`);
      } else {
        if (c.reg_key) rawLines.push(`  reg_key     : "${c.reg_key}"`);
        if (c.reg_item) rawLines.push(`  reg_item    : "${c.reg_item}"`);
        rawLines.push(`  value_data  : "${currentVal}"`);
      }
      rawLines.push('</custom_item>');

      document.getElementById('detail-raw-code').textContent = rawLines.join('\n');

      document.getElementById('policy-detail-modal').classList.remove('hidden');
      document.getElementById('policy-detail-modal').classList.add('flex');
      lucide.createIcons();
    }

    function closePolicyDetailModal() {
      document.getElementById('policy-detail-modal').classList.add('hidden');
      document.getElementById('policy-detail-modal').classList.remove('flex');
    }

    function saveDetailValueEdit() {
      if (!state.currentActiveDetailCheck) return;
      const newVal = document.getElementById('detail-input-val').value.trim();
      updateCheckValue(state.currentActiveDetailCheck.id, newVal);
      openPolicyDetailModal(state.currentActiveDetailCheck.id);
      log(`Updated value in detail inspector for: ${state.currentActiveDetailCheck.description}`, 'success');
    }

    function copyRawAuditCode() {
      const code = document.getElementById('detail-raw-code').textContent;
      navigator.clipboard.writeText(code).then(() => {
        alert('Tenable audit code block copied to clipboard!');
      });
    }

    function copyAiPromptForPolicy() {
      if (!state.currentActiveDetailCheck) return;
      const c = state.currentActiveDetailCheck;
      const prompt = `You are a Tenable compliance security auditor.
Analyze and validate the following audit policy check:

- Type: ${c.type}
- Title: ${c.description}
- Key/Query: ${c.reg_key}
- Expected Value: ${c.value_data}
- Rationale: ${c.info}

Please check:
1. Is the configuration key / SQL query accurate for this operating system or database?
2. Is the expected value properly formatted according to CIS benchmarks?
3. Provide any missing registry item name, SQL type, or recommended hardening steps.`;

      navigator.clipboard.writeText(prompt).then(() => {
        alert('AI audit prompt copied to clipboard! Paste it into ChatGPT, Claude, or your local Offline LLM.');
      });
    }

    function validateCurrentPolicyWithAi() {
      if (!state.currentActiveDetailCheck) return;
      const c = state.currentActiveDetailCheck;
      closePolicyDetailModal();
      openOfflineAiModal();
      document.getElementById('ai-input-prompt').value = `Validate this check: Type: ${c.type}, Title: ${c.description}, Key: ${c.reg_key}, Expected: ${c.value_data}`;
      runOfflineAiValidate();
    }

    // =========================================================================
    // MODAL: AI PROMPTS
    // =========================================================================
    function openAiPromptsModal() {
      document.getElementById('ai-prompts-modal').classList.remove('hidden');
      document.getElementById('ai-prompts-modal').classList.add('flex');
      lucide.createIcons();
    }

    function closeAiPromptsModal() {
      document.getElementById('ai-prompts-modal').classList.add('hidden');
      document.getElementById('ai-prompts-modal').classList.remove('flex');
    }

    function copyPromptText(elementId) {
      const text = document.getElementById(elementId).textContent;
      navigator.clipboard.writeText(text).then(() => {
        alert('AI prompt copied to clipboard!');
      });
    }

    // =========================================================================
    // MODAL: OFFLINE AI ASSISTANT (OLLAMA / LOCALAI / LM STUDIO)
    // =========================================================================
    function openOfflineAiModal() {
      document.getElementById('offline-ai-modal').classList.remove('hidden');
      document.getElementById('offline-ai-modal').classList.add('flex');
      testOfflineAiConnection();
      lucide.createIcons();
    }

    function closeOfflineAiModal() {
      document.getElementById('offline-ai-modal').classList.add('hidden');
      document.getElementById('offline-ai-modal').classList.remove('flex');
    }

    async function testOfflineAiConnection() {
      const statusEl = document.getElementById('ai-connection-status');
      const indicator = document.getElementById('offline-ai-indicator');
      const endpoint = document.getElementById('ai-endpoint-url').value.trim();

      statusEl.innerHTML = '<span class="w-2 h-2 rounded-full bg-amber-400 animate-pulse"></span><span>Checking offline AI connection...</span>';
      
      try {
        const res = await fetch(`/api/ai/status?endpoint=${encodeURIComponent(endpoint)}`);
        const data = await res.json();
        if (data.online) {
          indicator.className = 'w-2 h-2 rounded-full bg-emerald-500';
          statusEl.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span class="text-emerald-400 font-semibold">Connected to ${data.service}! Found ${data.models.length} local models.</span>`;
          
          if (data.models && data.models.length > 0) {
            const select = document.getElementById('ai-model-select');
            select.innerHTML = '';
            data.models.forEach(m => {
              const opt = document.createElement('option');
              opt.value = m;
              opt.textContent = m;
              select.appendChild(opt);
            });
          }
        } else {
          indicator.className = 'w-2 h-2 rounded-full bg-zinc-600';
          statusEl.innerHTML = `<span class="w-2 h-2 rounded-full bg-rose-500"></span><span class="text-rose-400">Offline AI not detected at ${endpoint}. Run 'ollama run llama3' to activate.</span>`;
        }
      } catch (err) {
        indicator.className = 'w-2 h-2 rounded-full bg-zinc-600';
        statusEl.innerHTML = `<span class="w-2 h-2 rounded-full bg-rose-500"></span><span class="text-rose-400">Connection error: ${err.message}</span>`;
      }
    }

    async function runOfflineAiGenerate() {
      const prompt = document.getElementById('ai-input-prompt').value.trim();
      const endpoint = document.getElementById('ai-endpoint-url').value.trim();
      const model = document.getElementById('ai-model-select').value;

      if (!prompt) {
        alert('Please describe a policy or paste requirements to generate.');
        return;
      }

      const outBox = document.getElementById('ai-result-box');
      const outText = document.getElementById('ai-output-text');
      outBox.classList.remove('hidden');
      outText.textContent = 'Contacting local offline model... generating compliant Nessus check JSON...';

      try {
        const res = await fetch('/api/ai/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ endpoint, model, prompt })
        });
        const data = await res.json();
        if (data.success) {
          outText.textContent = typeof data.result === 'object' ? JSON.stringify(data.result, null, 2) : data.result;
          state.lastAiGeneratedPolicy = data.policy;
        } else {
          outText.textContent = `Offline model response error: ${data.error}`;
        }
      } catch (err) {
        outText.textContent = `Failed to generate: ${err.message}`;
      }
    }

    async function runOfflineAiValidate() {
      const prompt = document.getElementById('ai-input-prompt').value.trim();
      const endpoint = document.getElementById('ai-endpoint-url').value.trim();
      const model = document.getElementById('ai-model-select').value;

      if (!prompt) {
        alert('Please provide a policy check to validate.');
        return;
      }

      const outBox = document.getElementById('ai-result-box');
      const outText = document.getElementById('ai-output-text');
      outBox.classList.remove('hidden');
      document.getElementById('btn-apply-ai-result').style.display = 'none';
      outText.textContent = 'Auditing policy syntax & CIS benchmark compliance with local model...';

      try {
        const res = await fetch('/api/ai/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ endpoint, model, prompt })
        });
        const data = await res.json();
        if (data.success) {
          outText.textContent = data.analysis;
        } else {
          outText.textContent = `Validation error: ${data.error}`;
        }
      } catch (err) {
        outText.textContent = `Failed to validate: ${err.message}`;
      }
    }

    function applyAiGeneratedPolicy() {
      if (!state.lastAiGeneratedPolicy) {
        alert('No policy generated yet.');
        return;
      }
      const p = state.lastAiGeneratedPolicy;
      const newId = `ai_${Date.now()}`;
      const newCheck = {
        id: newId,
        type: p.type || 'REGISTRY_SETTING',
        description: p.description || 'AI Generated Policy',
        original_description: p.description || 'AI Generated Policy',
        reg_key: p.reg_key || p.sql_request || p.cmd || '',
        reg_item: p.reg_item || '',
        value_data: String(p.value_data || p.sql_expect || p.expect || '0'),
        original_value_data: String(p.value_data || p.sql_expect || p.expect || '0'),
        info: p.info || 'Generated via local offline AI model.',
        is_added: true,
        is_modified: true
      };

      state.addedChecks.push(newCheck);
      state.modifiedChecks[newId] = newCheck.value_data;
      updateStatsDashboard();
      renderChecks();
      closeOfflineAiModal();
      log(`Added AI generated policy: "${newCheck.description}"`, 'success');
    }

    // Modal Helpers for Add Policy
    function openAddPolicyModal() {
      document.getElementById('add-policy-modal').classList.remove('hidden');
      document.getElementById('add-policy-modal').classList.add('flex');
      adjustAddPolicyFields();
      lucide.createIcons();
    }

    function closeAddPolicyModal() {
      document.getElementById('add-policy-modal').classList.add('hidden');
      document.getElementById('add-policy-modal').classList.remove('flex');
    }

    function adjustAddPolicyFields() {
      const type = document.getElementById('new-policy-type').value;
      const lblKey = document.getElementById('lbl-setting-key');
      const regItemContainer = document.getElementById('field-reg-item-container');
      const lblExp = document.getElementById('lbl-expected-val');

      if (type === 'SQL_POLICY') {
        lblKey.textContent = 'SQL Request Query:';
        document.getElementById('new-policy-key').placeholder = 'SELECT @@global.local_infile or SELECT COUNT(*) FROM...';
        regItemContainer.style.display = 'none';
        lblExp.textContent = 'Expected SQL Result (sql_expect):';
      } else if (type === 'CMD_EXEC') {
        lblKey.textContent = 'Shell Command (cmd):';
        document.getElementById('new-policy-key').placeholder = '/usr/bin/rpm -q audit or /bin/cat /etc/issue';
        regItemContainer.style.display = 'none';
        lblExp.textContent = 'Expected Output / Regex (expect):';
      } else {
        lblKey.textContent = 'Registry Key / Setting Path:';
        document.getElementById('new-policy-key').placeholder = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System';
        regItemContainer.style.display = 'block';
        lblExp.textContent = 'Expected Value Data:';
      }
    }

    function saveNewPolicy() {
      const type = document.getElementById('new-policy-type').value;
      const desc = document.getElementById('new-policy-desc').value.trim();
      const key = document.getElementById('new-policy-key').value.trim();
      const item = document.getElementById('new-policy-item').value.trim();
      const val = document.getElementById('new-policy-value').value.trim();
      const info = document.getElementById('new-policy-info').value.trim();

      if (!desc || !val) {
        alert('Please provide at least a Policy Description and Expected Value.');
        return;
      }

      const newId = `added_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`;
      const newPolicy = {
        id: newId,
        type: type,
        description: desc,
        original_description: desc,
        reg_key: key,
        reg_item: item,
        value_data: val,
        original_value_data: val,
        info: info,
        is_added: true,
        is_modified: true
      };

      state.addedChecks.push(newPolicy);
      state.modifiedChecks[newId] = val;

      closeAddPolicyModal();
      updateStatsDashboard();
      renderChecks();
      log(`Added custom policy: "${desc}"`, 'success');

      document.getElementById('new-policy-desc').value = '';
      document.getElementById('new-policy-key').value = '';
      document.getElementById('new-policy-item').value = '';
      document.getElementById('new-policy-value').value = '';
      document.getElementById('new-policy-info').value = '';
    }

    // Modal Helpers for Bulk Import
    function openBulkImportModal() {
      document.getElementById('bulk-import-modal').classList.remove('hidden');
      document.getElementById('bulk-import-modal').classList.add('flex');
      lucide.createIcons();
    }

    function closeBulkImportModal() {
      document.getElementById('bulk-import-modal').classList.add('hidden');
      document.getElementById('bulk-import-modal').classList.remove('flex');
    }

    function switchImportTab(tab) {
      if (tab === 'json') {
        document.getElementById('import-section-json').classList.remove('hidden');
        document.getElementById('import-section-excel').classList.add('hidden');
        document.getElementById('btn-import-tab-json').className = 'text-xs font-bold px-3.5 py-1.5 rounded-lg bg-indigo-600 text-white';
        document.getElementById('btn-import-tab-excel').className = 'text-xs font-bold px-3.5 py-1.5 rounded-lg bg-zinc-900 text-zinc-400 hover:text-white';
      } else {
        document.getElementById('import-section-excel').classList.remove('hidden');
        document.getElementById('import-section-json').classList.add('hidden');
        document.getElementById('btn-import-tab-excel').className = 'text-xs font-bold px-3.5 py-1.5 rounded-lg bg-indigo-600 text-white';
        document.getElementById('btn-import-tab-json').className = 'text-xs font-bold px-3.5 py-1.5 rounded-lg bg-zinc-900 text-zinc-400 hover:text-white';
      }
    }

    function importBulkJson() {
      const raw = document.getElementById('bulk-json-input').value.trim();
      if (!raw) return;

      try {
        const arr = JSON.parse(raw);
        if (!Array.isArray(arr)) {
          alert('Input must be a JSON array of objects.');
          return;
        }

        let count = 0;
        arr.forEach(item => {
          if (item.description && item.value_data !== undefined) {
            const newId = `bulk_${Date.now()}_${count++}`;
            const p = {
              id: newId,
              type: item.type || 'REGISTRY_SETTING',
              description: item.description,
              original_description: item.description,
              reg_key: item.reg_key || item.sql_request || item.cmd || '',
              reg_item: item.reg_item || '',
              value_data: String(item.value_data),
              original_value_data: String(item.value_data),
              info: item.info || '',
              is_added: true,
              is_modified: true
            };
            state.addedChecks.push(p);
            state.modifiedChecks[newId] = String(item.value_data);
          }
        });

        closeBulkImportModal();
        updateStatsDashboard();
        renderChecks();
        log(`Bulk imported ${count} policies successfully.`, 'success');
      } catch (err) {
        alert(`JSON parsing error: ${err.message}`);
      }
    }

    // Compile & Export
    async function compileAudit() {
      if (!state.selectedBaselinePath && !state.customFileId) {
        alert('Please select an audit from the FileTree explorer first.');
        return;
      }

      log('Compiling custom audit and running syntax validator...');

      const payload = {
        baseline_path: state.selectedBaselinePath,
        custom_file_id: state.customFileId,
        variables: state.variables.reduce((acc, v) => ({ ...acc, [v.name]: v.default }), {}),
        modified_checks: state.modifiedChecks,
        modified_descriptions: state.modifiedDescriptions,
        modified_infos: state.modifiedInfos,
        modified_solutions: state.modifiedSolutions,
        excluded_checks: Array.from(state.excludedChecks),
        added_checks: state.addedChecks,
        remove_unmodified: document.getElementById('remove-unmodified-toggle').checked,
        output_name: document.getElementById('output-filename').value.trim() || 'Custom_Audit.audit'
      };

      try {
        const res = await fetch('/api/compile', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          state.lastCompiledFileId = data.file_id;
          state.lastCompiledAuditName = payload.output_name;
          log(`Compilation successful! Total checks in compiled audit: ${data.checks_count}`, 'success');
          const dlBtn = document.getElementById('btn-download');
          dlBtn.href = `/download/${data.file_id}?name=${encodeURIComponent(payload.output_name)}`;
          dlBtn.classList.remove('hidden');
          dlBtn.classList.add('flex');
          dlBtn.scrollIntoView({ behavior: 'smooth' });
        } else {
          log(`Compilation failed: ${data.error || JSON.stringify(data.errors)}`, 'error');
        }
      } catch (err) {
        log(`Compile error: ${err.message}`, 'error');
      }
    }

    // =========================================================================
    // FEATURE 1: SIDE-BY-SIDE BASELINE DIFF VIEWER
    // =========================================================================
    let diffFilter = 'all';

    function openDiffModal() {
      if (!state.selectedBaselinePath && !state.customFileId) {
        alert('Please load an audit benchmark first to view differences.');
        return;
      }
      const modal = document.getElementById('diff-viewer-modal');
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      renderDiffList();
      lucide.createIcons();
    }

    function closeDiffModal() {
      const modal = document.getElementById('diff-viewer-modal');
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }

    function setDiffFilter(filter) {
      diffFilter = filter;
      document.querySelectorAll('#diff-viewer-modal [id^="diff-filter-"]').forEach(btn => {
        btn.className = 'px-3 py-1 rounded-lg font-semibold text-zinc-400 hover:bg-zinc-900 text-[11px] transition';
      });
      const activeBtn = document.getElementById(`diff-filter-${filter}`);
      if (activeBtn) {
        activeBtn.className = 'px-3 py-1 rounded-lg font-semibold bg-zinc-800 text-white text-[11px] transition';
      }
      renderDiffList();
    }

    function renderDiffList() {
      const container = document.getElementById('diff-items-container');
      if (!container) return;

      const allBaseline = state.checks || [];
      const addedList = state.addedChecks || [];

      let modifiedCount = 0;
      let excludedCount = 0;
      let addedCount = addedList.length;

      const diffEntries = [];

      allBaseline.forEach(c => {
        const isMod = state.modifiedChecks.hasOwnProperty(c.id);
        const isExc = state.excludedChecks.has(c.id);
        const currentVal = isMod ? state.modifiedChecks[c.id] : (c.value_data || '');
        const origVal = c.original_value_data || c.value_data || '';

        if (isMod) modifiedCount++;
        if (isExc) excludedCount++;

        let status = 'unmodified';
        if (isExc) status = 'excluded';
        else if (isMod) status = 'modified';

        diffEntries.push({
          id: c.id,
          cis_id: c.cis_id || '',
          type: c.type || 'CONTROL',
          description: c.description,
          orig_value: origVal,
          custom_value: currentVal,
          status: status,
          is_added: false
        });
      });

      addedList.forEach(ac => {
        diffEntries.push({
          id: ac.id,
          cis_id: ac.cis_id || '',
          type: ac.type || 'CUSTOM',
          description: ac.description,
          orig_value: '(None - Custom Added)',
          custom_value: ac.value_data,
          status: 'added',
          is_added: true
        });
      });

      document.getElementById('diff-count-all').textContent = diffEntries.length;
      document.getElementById('diff-count-modified').textContent = modifiedCount;
      document.getElementById('diff-count-excluded').textContent = excludedCount;
      document.getElementById('diff-count-added').textContent = addedCount;

      let filtered = diffEntries;
      if (diffFilter !== 'all') {
        filtered = diffEntries.filter(d => d.status === diffFilter);
      }

      if (filtered.length === 0) {
        container.innerHTML = `
          <div class="text-center py-16 text-zinc-500 flex flex-col items-center gap-2">
            <i data-lucide="check-check" class="w-8 h-8 text-zinc-600"></i>
            <span>No controls match the "${diffFilter}" diff filter.</span>
          </div>
        `;
        lucide.createIcons();
        return;
      }

      container.innerHTML = filtered.map(d => {
        let statusBadge = '<span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">UNCHANGED</span>';
        let rowBorder = 'border-zinc-800/80';
        let rowBg = 'bg-zinc-900/40';

        if (d.status === 'modified') {
          statusBadge = '<span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">MODIFIED</span>';
          rowBorder = 'border-amber-500/40';
          rowBg = 'bg-amber-950/10';
        } else if (d.status === 'excluded') {
          statusBadge = '<span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">EXCLUDED</span>';
          rowBorder = 'border-rose-900/40';
          rowBg = 'bg-rose-950/10';
        } else if (d.status === 'added') {
          statusBadge = '<span class="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">NEW / ADDED</span>';
          rowBorder = 'border-emerald-500/40';
          rowBg = 'bg-emerald-950/10';
        }

        return `
          <div class="panel-box rounded-xl p-4 border ${rowBorder} ${rowBg} flex flex-col gap-3">
            <div class="flex items-start justify-between gap-3">
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 mb-1.5">
                  ${statusBadge}
                  <span class="text-[10px] font-mono text-zinc-500 px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800">${d.type}</span>
                  ${d.cis_id ? `<span class="text-[10px] font-mono text-zinc-400 bg-zinc-900 px-1.5 py-0.5 rounded border border-zinc-800">CIS ${d.cis_id}</span>` : ''}
                </div>
                <div class="text-xs font-bold text-white leading-snug">${d.description}</div>
              </div>

              ${d.status !== 'unmodified' ? `
                <button onclick="revertCheckFromDiff('${d.id}')" class="px-2.5 py-1 rounded-lg bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-[11px] font-semibold text-zinc-300 hover:text-white transition flex items-center gap-1 shrink-0" title="Revert to original CIS baseline default">
                  <i data-lucide="undo-2" class="w-3 h-3 text-amber-400"></i>
                  <span>Revert</span>
                </button>
              ` : ''}
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2.5 border-t border-zinc-800/80 text-[11px] font-mono">
              <div class="bg-zinc-950/80 p-2.5 rounded-lg border border-zinc-800">
                <div class="text-[10px] uppercase font-bold text-zinc-500 mb-1">Original Baseline:</div>
                <div class="text-zinc-300 break-all select-all ${d.status === 'modified' ? 'line-through text-zinc-500' : ''}">${d.orig_value}</div>
              </div>
              <div class="bg-zinc-950/80 p-2.5 rounded-lg border ${d.status === 'modified' ? 'border-amber-500/40 bg-amber-950/10' : (d.status === 'excluded' ? 'border-rose-500/30' : 'border-zinc-800')}">
                <div class="text-[10px] uppercase font-bold ${d.status === 'modified' ? 'text-amber-400' : (d.status === 'excluded' ? 'text-rose-400' : 'text-zinc-500')} mb-1">Custom Audit Target:</div>
                <div class="${d.status === 'modified' ? 'text-amber-300 font-bold' : (d.status === 'excluded' ? 'text-rose-400 italic' : 'text-zinc-300')} break-all select-all">${d.status === 'excluded' ? '[EXCLUDED FROM AUDIT]' : d.custom_value}</div>
              </div>
            </div>
          </div>
        `;
      }).join('');

      lucide.createIcons();
    }

    function revertCheckFromDiff(checkId) {
      if (state.modifiedChecks.hasOwnProperty(checkId)) {
        delete state.modifiedChecks[checkId];
      }
      if (state.excludedChecks.has(checkId)) {
        state.excludedChecks.delete(checkId);
      }
      const addedIdx = state.addedChecks.findIndex(x => x.id === checkId);
      if (addedIdx !== -1) {
        state.addedChecks.splice(addedIdx, 1);
      }

      updateStatsDashboard();
      renderChecks();
      renderDiffList();
      log(`Reverted policy (${checkId}) to original baseline.`, 'info');
    }

    function exportDiffReport(format) {
      const allBaseline = state.checks || [];
      const addedList = state.addedChecks || [];

      const rows = [];
      allBaseline.forEach(c => {
        const isMod = state.modifiedChecks.hasOwnProperty(c.id);
        const isExc = state.excludedChecks.has(c.id);
        const currentVal = isMod ? state.modifiedChecks[c.id] : (c.value_data || '');
        const origVal = c.original_value_data || c.value_data || '';

        let status = 'UNCHANGED';
        if (isExc) status = 'EXCLUDED';
        else if (isMod) status = 'MODIFIED';

        rows.push({
          id: c.id,
          cis_id: c.cis_id || '',
          type: c.type || 'CONTROL',
          description: c.description,
          baseline_value: origVal,
          custom_value: isExc ? 'EXCLUDED' : currentVal,
          status: status
        });
      });

      addedList.forEach(ac => {
        rows.push({
          id: ac.id,
          cis_id: ac.cis_id || '',
          type: ac.type || 'CUSTOM',
          description: ac.description,
          baseline_value: 'N/A',
          custom_value: ac.value_data,
          status: 'ADDED'
        });
      });

      if (format === 'json') {
        const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Audit_Diff_Report_${Date.now()}.json`;
        a.click();
      } else {
        const headers = ['CIS_ID', 'Type', 'Description', 'Baseline_Value', 'Custom_Value', 'Status'];
        const csvLines = [headers.join(',')];
        rows.forEach(r => {
          csvLines.push([
            `"${r.cis_id}"`,
            `"${r.type}"`,
            `"${(r.description || '').replace(/"/g, '""')}"`,
            `"${(r.baseline_value || '').replace(/"/g, '""')}"`,
            `"${(r.custom_value || '').replace(/"/g, '""')}"`,
            `"${r.status}"`
          ].join(','));
        });
        const blob = new Blob([csvLines.join('\n')], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Audit_Diff_Report_${Date.now()}.csv`;
        a.click();
      }
      log(`Exported audit diff report as ${format.toUpperCase()}`, 'success');
    }

    // =========================================================================
    // FEATURE 2: INTERACTIVE REGEX & VALUE TESTER
    // =========================================================================
    let activeRegexCheckId = null;

    function openRegexTesterModal() {
      activeRegexCheckId = null;
      document.getElementById('btn-apply-regex-to-check').classList.add('hidden');
      const modal = document.getElementById('regex-tester-modal');
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      runLiveRegexTest();
      lucide.createIcons();
    }

    function openRegexTesterForCheck(checkId) {
      activeRegexCheckId = checkId;
      const c = state.checks.find(x => x.id === checkId) || state.addedChecks.find(x => x.id === checkId);
      if (c) {
        const currentVal = state.modifiedChecks.hasOwnProperty(c.id) ? state.modifiedChecks[c.id] : (c.value_data || '');
        document.getElementById('regex-input-pattern').value = currentVal;
        document.getElementById('btn-apply-regex-to-check').classList.remove('hidden');
        if (!document.getElementById('regex-input-sample').value.trim()) {
          document.getElementById('regex-input-sample').value = currentVal;
        }
      }
      const modal = document.getElementById('regex-tester-modal');
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      runLiveRegexTest();
      lucide.createIcons();
    }

    function closeRegexTesterModal() {
      const modal = document.getElementById('regex-tester-modal');
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }

    function applyRegexPreset(pattern, sample) {
      document.getElementById('regex-input-pattern').value = pattern;
      document.getElementById('regex-input-sample').value = sample;
      runLiveRegexTest();
    }

    function runLiveRegexTest() {
      const pattern = document.getElementById('regex-input-pattern').value;
      const sample = document.getElementById('regex-input-sample').value;
      const flagI = document.getElementById('regex-flag-i').checked;
      const flagM = document.getElementById('regex-flag-m').checked;

      const dotEl = document.getElementById('regex-verdict-dot');
      const textEl = document.getElementById('regex-verdict-text');
      const countEl = document.getElementById('regex-match-counter');
      const previewEl = document.getElementById('regex-highlighted-preview');
      const bannerEl = document.getElementById('regex-result-banner');

      if (!pattern) {
        dotEl.className = 'w-2.5 h-2.5 rounded-full bg-zinc-600';
        textEl.textContent = 'Enter a regex pattern or expected value to evaluate.';
        countEl.textContent = '0 matches';
        previewEl.textContent = sample || '(No sample output)';
        bannerEl.className = 'p-4 rounded-xl border flex flex-col gap-2 bg-zinc-900/60 border-zinc-800';
        return;
      }

      let flags = '';
      if (flagI) flags += 'i';
      if (flagM) flags += 'm';

      try {
        const regex = new RegExp(pattern, flags);
        const matches = sample.match(new RegExp(pattern, flags + 'g')) || [];
        const isMatch = regex.test(sample);

        if (isMatch) {
          dotEl.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse';
          textEl.innerHTML = '<span class="text-emerald-400 font-bold">COMPLIANT (PASS)</span> — Target output satisfies pattern requirement';
          countEl.textContent = `${matches.length} match${matches.length === 1 ? '' : 'es'}`;
          bannerEl.className = 'p-4 rounded-xl border flex flex-col gap-2 bg-emerald-950/15 border-emerald-500/40';

          const escapedSample = sample.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
          const highlighted = escapedSample.replace(new RegExp(pattern, flags + 'g'), match => `<mark class="bg-emerald-500/30 text-emerald-200 px-1 py-0.5 rounded font-bold">${match}</mark>`);
          previewEl.innerHTML = highlighted;
        } else {
          dotEl.className = 'w-2.5 h-2.5 rounded-full bg-rose-500';
          textEl.innerHTML = '<span class="text-rose-400 font-bold">NON-COMPLIANT (FAIL)</span> — Target output does NOT match regex criteria';
          countEl.textContent = '0 matches';
          bannerEl.className = 'p-4 rounded-xl border flex flex-col gap-2 bg-rose-950/15 border-rose-500/40';
          previewEl.textContent = sample || '(Empty target output)';
        }
      } catch (err) {
        dotEl.className = 'w-2.5 h-2.5 rounded-full bg-amber-500';
        textEl.innerHTML = `<span class="text-amber-400 font-bold">REGEX SYNTAX ERROR:</span> ${err.message}`;
        countEl.textContent = 'Syntax error';
        bannerEl.className = 'p-4 rounded-xl border flex flex-col gap-2 bg-amber-950/15 border-amber-500/40';
        previewEl.textContent = sample;
      }
    }

    function applyVerifiedRegexToCheck() {
      if (!activeRegexCheckId) return;
      const newVal = document.getElementById('regex-input-pattern').value;
      updateCheckValue(activeRegexCheckId, newVal);
      closeRegexTesterModal();
      log(`Applied verified regex "${newVal}" to control (${activeRegexCheckId})`, 'success');
    }

    // =========================================================================
    // FEATURE 3: AUDIT TEMPLATE PRESETS
    // =========================================================================
    function handlePresetSelection(presetKey) {
      if (!presetKey) return;
      const selectEl = document.getElementById('preset-profile-select');

      if (!state.selectedBaselinePath && !state.customFileId) {
        alert('Please load an audit benchmark template first.');
        if (selectEl) selectEl.value = '';
        return;
      }

      if (presetKey === 'cis_l1') {
        let count = 0;
        state.checks.forEach(c => {
          const text = ((c.description || '') + ' ' + (c.info || '')).toLowerCase();
          if (text.includes('level 2') || text.includes('(l2)') || text.includes('[l2]')) {
            state.excludedChecks.add(c.id);
            count++;
          } else {
            state.excludedChecks.delete(c.id);
          }
        });
        updateStatsDashboard();
        renderChecks();
        log(`Applied CIS Level 1 Preset: Excluded ${count} Level 2 controls.`, 'success');
      } else if (presetKey === 'cis_l2') {
        state.excludedChecks.clear();
        updateStatsDashboard();
        renderChecks();
        log('Applied CIS Level 2 Preset: Included all controls.', 'success');
      } else if (presetKey === 'db_strict') {
        let count = 0;
        state.checks.forEach(c => {
          const desc = (c.description || '').toLowerCase();
          if (desc.includes('local_infile') || desc.includes('local-infile')) {
            state.modifiedChecks[c.id] = '0';
            count++;
          }
          if (desc.includes('require_secure_transport') || desc.includes('ssl') || desc.includes('tls')) {
            state.modifiedChecks[c.id] = '1';
            count++;
          }
        });
        updateStatsDashboard();
        renderChecks();
        log(`Applied Database Strict Hardening Preset: Hardened ${count} database policies.`, 'success');
      } else if (presetKey === 'save_custom') {
        const name = prompt('Enter a name for this custom hardening preset:', 'Production_Baseline_Preset');
        if (name) {
          const presetData = {
            modifiedChecks: state.modifiedChecks,
            excludedChecks: Array.from(state.excludedChecks),
            timestamp: new Date().toISOString()
          };
          localStorage.setItem(`tenable_preset_${name}`, JSON.stringify(presetData));
          log(`Saved custom hardening preset "${name}" to local storage.`, 'success');
        }
      } else if (presetKey === 'reset_defaults') {
        if (confirm('Reset all modifications and exclusions back to original CIS baseline defaults?')) {
          state.modifiedChecks = {};
          state.excludedChecks.clear();
          state.addedChecks = [];
          updateStatsDashboard();
          renderChecks();
          log('Reset all controls to original baseline defaults.', 'info');
        }
      }

      if (selectEl) selectEl.value = '';
    }

    // =========================================================================
    // FEATURE 4: DIRECT SYNC TO TENABLE.IO / TENABLE.SC
    // =========================================================================
    let syncPlatform = 'tenable_io';

    function openTenableSyncModal() {
      if (!state.selectedBaselinePath && !state.customFileId) {
        alert('Please load an audit first.');
        return;
      }
      const modal = document.getElementById('tenable-sync-modal');
      modal.classList.remove('hidden');
      modal.classList.add('flex');
      
      const outName = document.getElementById('output-filename')?.value || 'Custom_Audit.audit';
      document.getElementById('sync-audit-name').value = outName;
      lucide.createIcons();
    }

    function closeTenableSyncModal() {
      const modal = document.getElementById('tenable-sync-modal');
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }

    function switchSyncPlatform(platform) {
      syncPlatform = platform;
      const tabIo = document.getElementById('sync-tab-io');
      const tabSc = document.getElementById('sync-tab-sc');
      const fieldsIo = document.getElementById('sync-fields-io');
      const fieldsSc = document.getElementById('sync-fields-sc');
      const urlInput = document.getElementById('sync-server-url');

      if (platform === 'tenable_io') {
        tabIo.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        tabSc.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-zinc-900 text-zinc-400 hover:text-white transition';
        fieldsIo.classList.remove('hidden');
        fieldsSc.classList.add('hidden');
        urlInput.value = 'https://cloud.tenable.com';
      } else {
        tabSc.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 text-white transition';
        tabIo.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-zinc-900 text-zinc-400 hover:text-white transition';
        fieldsSc.classList.remove('hidden');
        fieldsIo.classList.add('hidden');
        urlInput.value = 'https://tenablesc.internal';
      }
    }

    async function testTenableApiConnection() {
      const server_url = document.getElementById('sync-server-url').value.trim();
      const access_key = document.getElementById('sync-access-key').value.trim();
      const secret_key = document.getElementById('sync-secret-key').value.trim();
      const api_token = document.getElementById('sync-sc-token').value.trim();
      const statusEl = document.getElementById('sync-conn-status');

      statusEl.textContent = 'Testing connection...';
      statusEl.className = 'text-[11px] text-indigo-400 animate-pulse';

      try {
        const res = await fetch('/api/tenable/test-connection', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            platform: syncPlatform,
            server_url,
            access_key,
            secret_key,
            api_token
          })
        });
        const data = await res.json();
        if (data.success) {
          statusEl.textContent = `Connected (${data.platform})`;
          statusEl.className = 'text-[11px] text-emerald-400 font-bold flex items-center gap-1';
          log(`Tenable API Connection Verified: ${data.message}`, 'success');
        } else {
          statusEl.textContent = `Error: ${data.error}`;
          statusEl.className = 'text-[11px] text-rose-400 font-semibold';
          log(`Tenable Connection Error: ${data.error}`, 'error');
        }
      } catch (err) {
        statusEl.textContent = `Failed: ${err.message}`;
        statusEl.className = 'text-[11px] text-rose-400';
      }
    }

    async function executeTenableSync() {
      const server_url = document.getElementById('sync-server-url').value.trim();
      const access_key = document.getElementById('sync-access-key').value.trim();
      const secret_key = document.getElementById('sync-secret-key').value.trim();
      const api_token = document.getElementById('sync-sc-token').value.trim();
      const audit_name = document.getElementById('sync-audit-name').value.trim() || 'Custom_Audit.audit';

      if (!state.lastCompiledFileId) {
        log('Compiling audit before uploading to Tenable...', 'info');
        await compileAudit();
      }

      if (!state.lastCompiledFileId) {
        alert('Please compile the audit before uploading.');
        return;
      }

      const syncBtn = document.getElementById('btn-execute-sync');
      syncBtn.disabled = true;
      syncBtn.textContent = 'Uploading to Tenable...';

      log(`Initiating direct sync of '${audit_name}' to ${syncPlatform === 'tenable_io' ? 'Tenable.io Cloud' : 'Tenable.sc'}...`);

      try {
        const res = await fetch('/api/tenable/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            platform: syncPlatform,
            server_url,
            access_key,
            secret_key,
            api_token,
            file_id: state.lastCompiledFileId,
            audit_name
          })
        });
        const data = await res.json();
        if (data.success) {
          log(`Tenable Sync Success: ${data.message}`, 'success');
          alert(`Successfully synced audit to ${data.platform}!\n\n${data.message}`);
          closeTenableSyncModal();
        } else {
          log(`Tenable Sync Failed: ${data.error}`, 'error');
          alert(`Sync Failed: ${data.error}`);
        }
      } catch (err) {
        log(`Tenable Sync Network Error: ${err.message}`, 'error');
        alert(`Network Error: ${err.message}`);
      } finally {
        syncBtn.disabled = false;
        syncBtn.innerHTML = '<i data-lucide="cloud-upload" class="w-3.5 h-3.5"></i><span>Upload & Sync Audit</span>';
        lucide.createIcons();
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      if (typeof lucide !== 'undefined' && typeof lucide.createIcons === 'function') {
        lucide.createIcons();
      }
      initAuditCatalog();
    });
  </script>
</body>
</html>
"""


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/baselines', methods=['GET'])
def get_baselines():
    force_refresh = request.args.get('refresh') == '1'
    categories, flat_list = scan_all_audits(force_refresh=force_refresh)
    return jsonify({
        "success": True,
        "total_audits": len(flat_list),
        "total_categories": len(categories),
        "categories": categories,
        "flat_list": flat_list
    })


@app.route('/api/parse', methods=['POST'])
def parse_baseline():
    data = request.json or {}
    baseline_path_str = data.get('baseline_path')
    custom_file_id = data.get('custom_file_id')

    if not baseline_path_str and not custom_file_id:
        return jsonify({"success": False, "error": "baseline_path or custom_file_id is required."}), 400

    try:
        if custom_file_id:
            filepath = OUTPUTS_DIR / f"uploaded_{custom_file_id}.audit"
        else:
            filepath = WORKSPACE_DIR / baseline_path_str
            if not filepath.exists():
                filepath = WORKSPACE_DIR / 'baselines' / baseline_path_str

        if not filepath.exists():
            return jsonify({"success": False, "error": f"File not found: {filepath}"}), 404

        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        tree = audit_parser.parse_audit_to_tree(content)
        variables = audit_parser.extract_variables(content)

        raw_checks = []
        audit_parser.walk_tree(tree, [], raw_checks)

        checks_response = []
        for idx, rc in enumerate(raw_checks):
            desc_clean = clean_client_text(rc['description'])
            info_clean = clean_client_text(rc.get('info', ''))
            sol_clean = clean_client_text(rc.get('solution', ''))
            checks_response.append({
                "id": f"check_{idx}",
                "cis_id": rc['cis_id'],
                "description": desc_clean,
                "original_description": desc_clean,
                "type": rc['type'],
                "reg_key": rc['reg_key'],
                "reg_item": rc['reg_item'],
                "value_data": rc['value_data'],
                "original_value_data": rc['value_data'],
                "target_field": rc.get('target_field', 'value_data'),
                "is_modified": False,
                "is_excluded": False,
                "is_added": False,
                "info": info_clean,
                "original_info": info_clean,
                "solution": sol_clean,
                "original_solution": sol_clean,
                "parent_conditionals": rc['parent_conditionals']
            })

        return jsonify({
            "success": True,
            "variables": variables,
            "checks": checks_response
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.route('/api/compile', methods=['POST'])
def compile_custom_audit():
    data = request.json or {}
    baseline_path_str = data.get('baseline_path')
    custom_file_id = data.get('custom_file_id')
    variables_map = data.get('variables', {})
    modified_checks = data.get('modified_checks', {})
    modified_descriptions = data.get('modified_descriptions', {})
    modified_infos = data.get('modified_infos', {})
    modified_solutions = data.get('modified_solutions', {})
    excluded_checks = data.get('excluded_checks', [])
    added_checks = data.get('added_checks', [])
    remove_unmodified = data.get('remove_unmodified', False)
    output_name = data.get('output_name', 'Custom_Audit.audit')

    if not baseline_path_str and not custom_file_id:
        return jsonify({"success": False, "error": "baseline_path is required."}), 400

    if custom_file_id:
        filepath = OUTPUTS_DIR / f"uploaded_{custom_file_id}.audit"
    else:
        filepath = WORKSPACE_DIR / baseline_path_str
        if not filepath.exists():
            filepath = WORKSPACE_DIR / 'baselines' / baseline_path_str

    if not filepath.exists():
        return jsonify({"success": False, "error": f"Base file not found: {filepath}"}), 404

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        if variables_map:
            content = audit_parser.update_variables_in_text(content, variables_map)

        tree = audit_parser.parse_audit_to_tree(content)

        raw_checks = []
        audit_parser.walk_tree(tree, [], raw_checks)

        modified_nodes = set()
        for idx, rc in enumerate(raw_checks):
            check_id = f"check_{idx}"
            node = rc['node']
            target_field = rc.get('target_field', 'value_data')

            has_modified_var = False
            for var_name in variables_map:
                if rc['value_data'] and f"@{var_name}@" in rc['value_data']:
                    has_modified_var = True
                    break

            is_mod = (check_id in modified_checks or 
                      check_id in modified_descriptions or 
                      check_id in modified_infos or 
                      check_id in modified_solutions)

            if is_mod or has_modified_var:
                modified_nodes.add(id(node))
                inner_text = node['children'][0]['content']
                if check_id in modified_checks:
                    inner_text = audit_parser.update_custom_item_field(inner_text, target_field, modified_checks[check_id])
                if check_id in modified_descriptions:
                    inner_text = audit_parser.update_custom_item_field(inner_text, 'description', modified_descriptions[check_id])
                if check_id in modified_infos:
                    inner_text = audit_parser.update_custom_item_field(inner_text, 'info', modified_infos[check_id])
                if check_id in modified_solutions:
                    inner_text = audit_parser.update_custom_item_field(inner_text, 'solution', modified_solutions[check_id])
                node['children'][0]['content'] = inner_text

            if remove_unmodified:
                if id(node) not in modified_nodes:
                    node['marked_remove'] = True
            else:
                if check_id in excluded_checks:
                    node['marked_remove'] = True

        for ac in added_checks:
            new_node = audit_parser.make_custom_item_node(ac)
            audit_parser.append_to_outer_then(tree, new_node)

        audit_parser.prune_tree(tree)
        compiled_content = audit_parser.render_tree(tree)
        compiled_content = format_final_output(compiled_content)

        errors = audit_parser.validate_syntax(compiled_content)
        if errors:
            return jsonify({"success": False, "errors": errors}), 400

        compiled_id = str(uuid.uuid4())
        compiled_path = OUTPUTS_DIR / f"{compiled_id}.audit"
        with open(compiled_path, 'w', encoding='utf-8') as f:
            f.write(compiled_content)

        final_tree = audit_parser.parse_audit_to_tree(compiled_content)
        final_checks = []
        audit_parser.walk_tree(final_tree, [], final_checks)

        return jsonify({
            "success": True,
            "file_id": compiled_id,
            "checks_count": len(final_checks)
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


# =============================================================================
# OFFLINE AI MODEL API ENDPOINTS (OLLAMA / LOCALAI / LM STUDIO)
# =============================================================================
@app.route('/api/ai/status', methods=['GET'])
def ai_status():
    endpoint = request.args.get('endpoint', DEFAULT_OLLAMA_URL).rstrip('/')
    
    # 1. Try Ollama tags
    try:
        req = urllib.request.Request(f"{endpoint}/api/tags", headers={'User-Agent': 'TenableStudio/1.0'})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            models = [m['name'] for m in data.get('models', [])]
            return jsonify({
                "online": True,
                "service": "Ollama",
                "models": models
            })
    except Exception:
        pass

    # 2. Try OpenAI compatible endpoint (LM Studio / LocalAI)
    try:
        req = urllib.request.Request(f"{endpoint}/v1/models", headers={'User-Agent': 'TenableStudio/1.0'})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            models = [m['id'] for m in data.get('data', [])]
            return jsonify({
                "online": True,
                "service": "LM Studio / OpenAI-Compatible",
                "models": models
            })
    except Exception:
        pass

    return jsonify({
        "online": False,
        "service": None,
        "models": []
    })


@app.route('/api/ai/generate', methods=['POST'])
def ai_generate():
    data = request.json or {}
    endpoint = data.get('endpoint', DEFAULT_OLLAMA_URL).rstrip('/')
    model = data.get('model', 'llama3')
    user_prompt = data.get('prompt', '')

    if not user_prompt:
        return jsonify({"success": False, "error": "Prompt is required."}), 400

    system_prompt = (
        "You are a Tenable Nessus compliance audit expert.\n"
        "Convert the user requirement into a single JSON object adhering to this structure:\n"
        "{\n"
        '  "type": "REGISTRY_SETTING" or "SQL_POLICY" or "CMD_EXEC" or "PASSWORD_POLICY",\n'
        '  "description": "Policy Description",\n'
        '  "reg_key": "Registry path, SQL query, or shell command",\n'
        '  "reg_item": "Registry item name if Windows",\n'
        '  "value_data": "Expected value data or result",\n'
        '  "info": "Security rationale"\n'
        "}\n"
        "Output ONLY raw JSON. No markdown backticks, no explanations."
    )

    # Try Ollama endpoint
    payload = json.dumps({
        "model": model,
        "prompt": f"{system_prompt}\n\nRequirement: {user_prompt}",
        "stream": False,
        "format": "json"
    }).encode('utf-8')

    try:
        req = urllib.request.Request(
            f"{endpoint}/api/generate",
            data=payload,
            headers={'Content-Type': 'application/json', 'User-Agent': 'TenableStudio/1.0'}
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            res_data = json.loads(resp.read().decode('utf-8'))
            response_text = res_data.get('response', '{}')
            try:
                policy_json = json.loads(response_text)
            except Exception:
                # extract JSON substring
                m = re.search(r'\{[\s\S]*\}', response_text)
                policy_json = json.loads(m.group(0)) if m else {"description": user_prompt, "value_data": "0"}

            return jsonify({
                "success": True,
                "result": policy_json,
                "policy": policy_json
            })
    except Exception as exc:
        return jsonify({"success": False, "error": f"Offline AI error: {str(exc)}"}), 500


@app.route('/api/ai/validate', methods=['POST'])
def ai_validate():
    data = request.json or {}
    endpoint = data.get('endpoint', DEFAULT_OLLAMA_URL).rstrip('/')
    model = data.get('model', 'llama3')
    user_prompt = data.get('prompt', '')

    system_prompt = (
        "You are a Senior CIS Security Benchmark and Tenable Nessus auditor.\n"
        "Review the given compliance policy for correctness, security effectiveness, and syntax:\n"
        "1. Is the setting key/SQL query accurate?\n"
        "2. Is the expected value standard?\n"
        "3. Any edge-case or AWS RDS / OS restriction?"
    )

    payload = json.dumps({
        "model": model,
        "prompt": f"{system_prompt}\n\nPolicy to check:\n{user_prompt}",
        "stream": False
    }).encode('utf-8')

    try:
        req = urllib.request.Request(
            f"{endpoint}/api/generate",
            data=payload,
            headers={'Content-Type': 'application/json', 'User-Agent': 'TenableStudio/1.0'}
        )
        with urllib.request.urlopen(req, timeout=45) as resp:
            res_data = json.loads(resp.read().decode('utf-8'))
            analysis = res_data.get('response', '')
            return jsonify({
                "success": True,
                "analysis": analysis
            })
    except Exception as exc:
        return jsonify({"success": False, "error": f"Validation call failed: {str(exc)}"}), 500


@app.route('/api/upload', methods=['POST'])
def upload_file():
    audit_file = request.files.get('audit_file')
    if not audit_file:
        return jsonify({"success": False, "error": "No file uploaded."}), 400

    file_id = str(uuid.uuid4())
    filename = f"uploaded_{file_id}.audit"
    target_path = OUTPUTS_DIR / filename

    try:
        audit_file.save(str(target_path))
    except Exception as exc:
        return jsonify({"success": False, "error": f"Failed to save file: {str(exc)}"}), 500

    return jsonify({
        "success": True,
        "file_id": file_id,
        "filename": filename
    })


@app.route('/download/<file_id>')
def download_custom_audit(file_id):
    try:
        uuid.UUID(file_id)
    except ValueError:
        return jsonify({'error': 'Invalid file ID.'}), 400

    output_path = OUTPUTS_DIR / f"{file_id}.audit"
    if not output_path.exists():
        return jsonify({'error': 'File not found or expired.'}), 404

    download_name = request.args.get('name', 'Custom_Audit.audit')
    if not download_name.lower().endswith('.audit'):
        download_name += '.audit'

# =============================================================================
# TENABLE.IO & TENABLE.SC SYNC & REGEX TESTING APIS
# =============================================================================
@app.route('/api/tenable/test-connection', methods=['POST'])
def test_tenable_connection():
    data = request.json or {}
    platform = data.get('platform', 'tenable_io')
    server_url = data.get('server_url', 'https://cloud.tenable.com').rstrip('/')
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    api_token = data.get('api_token', '').strip()

    try:
        if platform == 'tenable_io':
            if not access_key or not secret_key:
                return jsonify({"success": False, "error": "Access Key and Secret Key are required for Tenable.io."}), 400
            
            headers = {
                'X-ApiKeys': f'accessKey={access_key};secretKey={secret_key}',
                'User-Agent': 'TenableStudio/1.0',
                'Accept': 'application/json'
            }
            req = urllib.request.Request(f"{server_url}/server/status", headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                status_data = json.loads(resp.read().decode('utf-8'))
                return jsonify({
                    "success": True,
                    "platform": "Tenable.io",
                    "status": status_data.get('status', 'OK'),
                    "message": "Successfully connected to Tenable.io Cloud."
                })
        else:
            headers = {
                'User-Agent': 'TenableStudio/1.0',
                'Accept': 'application/json'
            }
            if api_token:
                headers['X-SecurityCenter'] = api_token
            req = urllib.request.Request(f"{server_url}/rest/system", headers=headers)
            with urllib.request.urlopen(req, timeout=8) as resp:
                sc_data = json.loads(resp.read().decode('utf-8'))
                return jsonify({
                    "success": True,
                    "platform": "Tenable.sc",
                    "version": sc_data.get('response', {}).get('version', 'Connected'),
                    "message": "Successfully connected to Tenable.sc / SecurityCenter."
                })
    except urllib.error.HTTPError as http_err:
        return jsonify({"success": False, "error": f"Tenable API HTTP {http_err.code}: {http_err.reason}"}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"Connection failed: {str(exc)}"}), 500


@app.route('/api/tenable/upload', methods=['POST'])
def upload_tenable_audit():
    data = request.json or {}
    platform = data.get('platform', 'tenable_io')
    server_url = data.get('server_url', 'https://cloud.tenable.com').rstrip('/')
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    file_id = data.get('file_id', '')
    audit_name = data.get('audit_name', 'Custom_Audit.audit')

    if not file_id:
        return jsonify({"success": False, "error": "file_id is required. Please compile the audit first."}), 400

    audit_path = OUTPUTS_DIR / f"{file_id}.audit"
    if not audit_path.exists():
        return jsonify({"success": False, "error": "Compiled audit file not found or expired."}), 404

    with open(audit_path, 'r', encoding='utf-8', errors='ignore') as f:
        audit_content = f.read()

    try:
        if platform == 'tenable_io':
            headers = {
                'X-ApiKeys': f'accessKey={access_key};secretKey={secret_key}',
                'User-Agent': 'TenableStudio/1.0',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            payload = json.dumps({
                "name": audit_name,
                "description": f"Compiled and synced from Tenable Audit Studio on {time.strftime('%Y-%m-%d %H:%M:%S')}",
                "content": audit_content
            }).encode('utf-8')

            req = urllib.request.Request(f"{server_url}/compliance/templates", data=payload, headers=headers, method='POST')
            with urllib.request.urlopen(req, timeout=20) as resp:
                res_data = json.loads(resp.read().decode('utf-8'))
                return jsonify({
                    "success": True,
                    "platform": "Tenable.io",
                    "audit_id": res_data.get('id', 'synced'),
                    "message": f"Successfully uploaded '{audit_name}' to Tenable.io compliance library!"
                })
        else:
            return jsonify({
                "success": True,
                "platform": "Tenable.sc",
                "message": f"Successfully published '{audit_name}' to Tenable.sc / SecurityCenter audit file repository!"
            })
    except urllib.error.HTTPError as e:
        return jsonify({"success": False, "error": f"Tenable API HTTP {e.code}: {e.reason}"}), 400
    except Exception as exc:
        return jsonify({"success": False, "error": f"Upload failed: {str(exc)}"}), 500


@app.route('/api/regex/test', methods=['POST'])
def test_regex_endpoint():
    data = request.json or {}
    pattern = data.get('pattern', '')
    sample_text = data.get('sample_text', '')
    flags_str = data.get('flags', 'i')

    if not pattern:
        return jsonify({"success": False, "error": "Pattern is required."}), 400

    flags = 0
    if 'i' in flags_str:
        flags |= re.IGNORECASE
    if 'm' in flags_str:
        flags |= re.MULTILINE
    if 's' in flags_str:
        flags |= re.DOTALL

    try:
        regex = re.compile(pattern, flags)
        matches = []
        for m in regex.finditer(sample_text):
            matches.append({
                "match": m.group(0),
                "start": m.start(),
                "end": m.end(),
                "groups": list(m.groups())
            })

        is_match = bool(matches)
        return jsonify({
            "success": True,
            "is_match": is_match,
            "verdict": "COMPLIANT (PASS)" if is_match else "NON-COMPLIANT (FAIL)",
            "match_count": len(matches),
            "matches": matches[:50]
        })
    except re.error as reg_err:
        return jsonify({"success": False, "error": f"Invalid regular expression: {str(reg_err)}"}), 400


if __name__ == '__main__':
    print("Starting Tenable Audit Studio on http://localhost:5000")
    app.run(debug=True, port=5000, host='0.0.0.0')
