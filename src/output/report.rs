use super::OutputRecord;

fn json_for_script_tag(value: &str) -> String {
    value.replace("</", "<\\/")
}

pub fn render_html(records: &[OutputRecord]) -> Vec<u8> {
    let json = serde_json::to_string(records).unwrap_or_else(|_| "[]".to_string());
    let json = json_for_script_tag(&json);

    let html = format!(
        r####"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
  <title>Pathbuster Report</title>
  <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
  <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@700;800&amp;family=Inter:wght@400;500;600;700&amp;display=swap" rel="stylesheet"/>
  <script id="tailwind-config">
    tailwind.config = {{
      darkMode: "class",
      theme: {{
        extend: {{
          colors: {{
            "primary": "#135bec",
            "background-light": "#f8fafc",
            "background-dark": "#0f172a"
          }},
          fontFamily: {{
            "sans": ["Inter", "sans-serif"],
            "display": ["Montserrat", "sans-serif"]
          }},
          borderRadius: {{
            "DEFAULT": "0.375rem",
            "lg": "0.5rem",
            "xl": "0.75rem",
            "2xl": "1rem",
            "full": "9999px"
          }}
        }}
      }}
    }};
  </script>
  <style type="text/tailwindcss">
    .material-symbols-outlined {{
      font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
    }}
    body {{
      font-family: 'Inter', sans-serif;
    }}
    h1, h2, h3, .font-bold-display {{
      font-family: 'Montserrat', sans-serif;
      font-weight: 800;
      letter-spacing: -0.025em;
    }}
  </style>
</head>
<body class="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 min-h-screen transition-colors duration-200">
  <script type="application/json" id="records-data">{json}</script>
  <div class="layout-container flex h-full grow flex-col">
    <header class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-8 py-4 sticky top-0 z-50">
      <div class="flex items-center gap-4">
        <div class="size-10 bg-primary rounded-xl flex items-center justify-center text-white shadow-lg shadow-primary/20">
          <span class="material-symbols-outlined text-[24px]">security</span>
        </div>
        <h2 class="text-slate-900 dark:text-white text-xl font-display uppercase tracking-tight">Pathbuster Report</h2>
      </div>
      <div class="flex items-center gap-3">
        <button id="theme-toggle" class="flex size-10 cursor-pointer items-center justify-center overflow-hidden rounded-xl bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-white hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors" type="button">
          <span id="theme-icon" class="material-symbols-outlined">light_mode</span>
        </button>
      </div>
    </header>

    <main class="flex-1 max-w-[1440px] mx-auto w-full px-8 py-10">
      <div class="flex flex-col md:flex-row justify-between items-start md:items-end mb-10 gap-4">
        <div>
          <h1 class="text-slate-900 dark:text-white text-5xl mb-2">SCAN RESULTS</h1>
          <p class="text-slate-500 dark:text-slate-400 text-base font-medium">Client-side report viewer (search, filters, pagination).</p>
        </div>
      </div>

      <div class="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-5 mb-8 shadow-sm">
        <div class="flex flex-wrap items-center justify-between gap-5">
          <div class="flex flex-1 min-w-[320px] items-center gap-3 bg-slate-50 dark:bg-slate-800/50 rounded-xl px-4 py-3 border border-slate-200 dark:border-slate-700 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/10 transition-all">
            <span class="material-symbols-outlined text-slate-400">search</span>
            <input id="search" class="bg-transparent border-none focus:ring-0 text-sm w-full text-slate-900 dark:text-white placeholder:text-slate-400 font-medium" placeholder="Search URLs, payloads, titles, server..." type="text"/>
          </div>

          <div class="flex flex-wrap items-center gap-4">
            <div id="filters" class="flex flex-wrap items-center gap-4"></div>

            <div class="h-10 w-px bg-slate-200 dark:bg-slate-700 mx-1 hidden lg:block"></div>

            <div class="flex items-center gap-3">
              <div class="relative">
                <select id="page-size" class="appearance-none bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-bold px-5 py-3 pr-10 text-slate-700 dark:text-slate-300 focus:ring-primary focus:border-primary cursor-pointer transition-all">
                  <option value="25">25 / page</option>
                  <option value="50">50 / page</option>
                  <option value="100">100 / page</option>
                </select>
                <span class="material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none text-[18px]">expand_more</span>
              </div>

              <div class="flex bg-slate-100 dark:bg-slate-800 p-1 rounded-xl">
                <button id="view-table" class="flex items-center gap-2 px-4 py-2 rounded-lg bg-white dark:bg-slate-700 shadow-sm text-primary text-xs font-bold transition-all" type="button">
                  <span class="material-symbols-outlined text-[18px]">table_chart</span>
                  TABLE
                </button>
                <button id="view-grid" class="flex items-center gap-2 px-4 py-2 rounded-lg text-slate-500 dark:text-slate-400 text-xs font-bold hover:text-slate-700 dark:hover:text-slate-200 transition-all" type="button">
                  <span class="material-symbols-outlined text-[18px]">grid_view</span>
                  GRID
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <noscript>
        <div class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-900/30 rounded-2xl p-5 mb-8">
          <div class="text-amber-800 dark:text-amber-300 font-bold">This report requires JavaScript to render results.</div>
        </div>
      </noscript>

      <div class="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-sm">
        <div id="table-view" class="overflow-x-auto">
          <table class="w-full text-left border-collapse">
            <thead>
              <tr class="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">URL</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Payload</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Tech</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">WAF</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Status</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Title</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Size</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest">Content-Type</th>
                <th class="px-6 py-5 text-[11px] font-display text-slate-900 dark:text-slate-200 uppercase tracking-widest text-right">Words</th>
              </tr>
            </thead>
            <tbody id="table-body" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
          </table>
        </div>

        <div id="grid-view" class="hidden p-6">
          <div id="grid-cards" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5"></div>
        </div>

        <div class="px-8 py-5 border-t border-slate-100 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div class="flex flex-col gap-1">
            <p id="results-total" class="text-sm text-slate-500 dark:text-slate-400 font-bold">0 TOTAL RESULTS</p>
            <p id="results-range" class="text-xs text-slate-500 dark:text-slate-400 font-medium">Showing 0-0</p>
          </div>
          <div class="flex items-center gap-2">
            <button id="page-prev" class="flex items-center justify-center size-9 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-colors border border-slate-200 dark:border-slate-700" type="button">
              <span class="material-symbols-outlined text-[20px]">chevron_left</span>
            </button>
            <div id="page-buttons" class="flex gap-2"></div>
            <button id="page-next" class="flex items-center justify-center size-9 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-colors border border-slate-200 dark:border-slate-700" type="button">
              <span class="material-symbols-outlined text-[20px]">chevron_right</span>
            </button>
          </div>
        </div>
      </div>
    </main>

    <footer class="mt-auto py-8 border-t border-slate-200 dark:border-slate-800 text-center">
      <p class="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest">PATHBUSTER REPORT</p>
    </footer>
  </div>

  <script>
    (function() {{
      function escapeHtml(value) {{
        return String(value)
          .replaceAll('&', '&amp;')
          .replaceAll('<', '&lt;')
          .replaceAll('>', '&gt;')
          .replaceAll('"', '&quot;')
          .replaceAll("'", '&#39;');
      }}

      function bytesHuman(n) {{
        const v = Number(n || 0);
        if (v < 1024) return `${{v}} B`;
        const kb = v / 1024.0;
        if (kb < 1024.0) return `${{kb.toFixed(1)}} KB`;
        const mb = kb / 1024.0;
        return `${{mb.toFixed(1)}} MB`;
      }}

      function statusLabel(status) {{
        const s = Number(status);
        const map = {{
          200: '200 OK',
          201: '201 Created',
          202: '202 Accepted',
          204: '204 No Content',
          301: '301 Moved Permanently',
          302: '302 Found',
          303: '303 See Other',
          307: '307 Temporary Redirect',
          308: '308 Permanent Redirect',
          400: '400 Bad Request',
          401: '401 Unauthorized',
          403: '403 Forbidden',
          404: '404 Not Found',
          405: '405 Method Not Allowed',
          409: '409 Conflict',
          429: '429 Too Many Requests',
          500: '500 Internal Server Error',
          502: '502 Bad Gateway',
          503: '503 Service Unavailable',
          504: '504 Gateway Timeout'
        }};
        return map[s] || String(s);
      }}

      function statusClass(status) {{
        const s = Number(status);
        if (s >= 200 && s <= 299) return 'bg-emerald-100/50 dark:bg-emerald-900/20 text-emerald-700 dark:text-emerald-400';
        if (s >= 300 && s <= 399) return 'bg-amber-100/50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400';
        if (s >= 400 && s <= 599) return 'bg-rose-100/50 dark:bg-rose-900/20 text-rose-700 dark:text-rose-400';
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300';
      }}

      function uniqueSorted(values) {{
        const s = new Set();
        for (const v of values) {{
          const t = String(v || '').trim();
          if (!t) continue;
          s.add(t);
        }}
        const out = Array.from(s);
        out.sort((a, b) => a.localeCompare(b));
        return out;
      }}

      function createSelect(id, label, values) {{
        const wrapper = document.createElement('div');
        wrapper.className = 'relative';
        wrapper.id = `filter-wrapper-${{id}}`;

        const select = document.createElement('select');
        select.id = `filter-${{id}}`;
        select.className = 'appearance-none bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-700 rounded-xl text-xs font-bold px-5 py-3 pr-10 text-slate-700 dark:text-slate-300 focus:ring-primary focus:border-primary cursor-pointer transition-all';

        const any = document.createElement('option');
        any.value = '';
        any.textContent = `${{label}}: ALL`;
        select.appendChild(any);

        for (const v of values) {{
          const opt = document.createElement('option');
          opt.value = v;
          opt.textContent = v;
          select.appendChild(opt);
        }}

        const icon = document.createElement('span');
        icon.className = 'material-symbols-outlined absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none text-[18px]';
        icon.textContent = 'expand_more';

        wrapper.appendChild(select);
        wrapper.appendChild(icon);
        return wrapper;
      }}

      const raw = document.getElementById('records-data').textContent || '[]';
      const records = JSON.parse(raw);

      const htmlEl = document.documentElement;
      const themeIcon = document.getElementById('theme-icon');
      function setTheme(mode) {{
        if (mode === 'dark') {{
          htmlEl.classList.add('dark');
          themeIcon.textContent = 'dark_mode';
        }} else {{
          htmlEl.classList.remove('dark');
          themeIcon.textContent = 'light_mode';
        }}
        localStorage.setItem('pb-theme', mode);
      }}
      const storedTheme = localStorage.getItem('pb-theme');
      if (storedTheme === 'dark' || storedTheme === 'light') {{
        setTheme(storedTheme);
      }} else {{
        setTheme(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      }}
      document.getElementById('theme-toggle').addEventListener('click', function() {{
        setTheme(htmlEl.classList.contains('dark') ? 'light' : 'dark');
      }});

      const tableBody = document.getElementById('table-body');
      const gridCards = document.getElementById('grid-cards');
      const resultsTotal = document.getElementById('results-total');
      const resultsRange = document.getElementById('results-range');
      const pageButtons = document.getElementById('page-buttons');
      const pagePrev = document.getElementById('page-prev');
      const pageNext = document.getElementById('page-next');
      const searchEl = document.getElementById('search');
      const pageSizeEl = document.getElementById('page-size');
      const viewTable = document.getElementById('view-table');
      const viewGrid = document.getElementById('view-grid');
      const tableView = document.getElementById('table-view');
      const gridView = document.getElementById('grid-view');
      const filtersHost = document.getElementById('filters');

      const state = {{
        query: '',
        page: 1,
        pageSize: Number(pageSizeEl.value || 25),
        view: localStorage.getItem('pb-view') || 'table',
        filters: {{
          baseUrl: '',
          tech: '',
          waf: '',
          status: '',
          server: '',
          contentType: '',
          payloadFamily: ''
        }}
      }};

      function applyView(next) {{
        state.view = next;
        localStorage.setItem('pb-view', next);
        if (next === 'grid') {{
          tableView.classList.add('hidden');
          gridView.classList.remove('hidden');
          viewGrid.className = 'flex items-center gap-2 px-4 py-2 rounded-lg bg-white dark:bg-slate-700 shadow-sm text-primary text-xs font-bold transition-all';
          viewTable.className = 'flex items-center gap-2 px-4 py-2 rounded-lg text-slate-500 dark:text-slate-400 text-xs font-bold hover:text-slate-700 dark:hover:text-slate-200 transition-all';
        }} else {{
          gridView.classList.add('hidden');
          tableView.classList.remove('hidden');
          viewTable.className = 'flex items-center gap-2 px-4 py-2 rounded-lg bg-white dark:bg-slate-700 shadow-sm text-primary text-xs font-bold transition-all';
          viewGrid.className = 'flex items-center gap-2 px-4 py-2 rounded-lg text-slate-500 dark:text-slate-400 text-xs font-bold hover:text-slate-700 dark:hover:text-slate-200 transition-all';
        }}
      }}

      viewTable.addEventListener('click', function() {{ applyView('table'); render(); }});
      viewGrid.addEventListener('click', function() {{ applyView('grid'); render(); }});
      applyView(state.view === 'grid' ? 'grid' : 'table');

      const allTech = uniqueSorted(records.flatMap(r => (r.tech || [])));
      const allWaf = uniqueSorted(records.flatMap(r => (r.waf || [])));
      const allStatus = Array.from(new Set(records.map(r => Number(r.status || 0)).filter(s => s > 0))).sort((a,b) => a-b).map(s => String(s));
      const allServer = uniqueSorted(records.map(r => r.server));
      const allContentType = uniqueSorted(records.map(r => r.content_type));
      const allBaseUrl = uniqueSorted(records.map(r => r.base_url));
      const allFamily = uniqueSorted(records.map(r => r.payload_family));

      function addFilter(id, label, values, transformDisplay) {{
        if (!values || values.length <= 1) return;
        const displayValues = transformDisplay ? values.map(transformDisplay) : values;
        const wrapper = createSelect(id, label, displayValues);
        const select = wrapper.querySelector('select');
        select.addEventListener('change', function() {{
          state.filters[id] = select.value;
          state.page = 1;
          render();
        }});
        filtersHost.appendChild(wrapper);
      }}

      addFilter('baseUrl', 'TARGET', allBaseUrl);
      addFilter('tech', 'TECH', allTech);
      addFilter('waf', 'WAF', allWaf);
      addFilter('status', 'STATUS', allStatus, function(v) {{ return `${{v}} ${{statusLabel(Number(v)).replace(String(v), '').trim()}}`.trim(); }});
      addFilter('server', 'SERVER', allServer);
      addFilter('contentType', 'CONTENT-TYPE', allContentType);
      addFilter('payloadFamily', 'PAYLOAD', allFamily);

      function norm(s) {{ return String(s || '').toLowerCase(); }}
      function includesAny(haystack, needle) {{
        if (!needle) return true;
        return norm(haystack).includes(needle);
      }}

      function recordMatchesFilters(r) {{
        const q = norm(state.query.trim());
        if (q) {{
          const tech = (r.tech || []).join(' ');
          const waf = (r.waf || []).join(' ');
          const combined = [
            r.base_url, r.url, r.payload_original, r.payload_mutated, r.payload_family,
            r.title, r.server, r.content_type, tech, waf, String(r.status || '')
          ].join(' ');
          if (!includesAny(combined, q)) return false;
        }}

        if (state.filters.baseUrl) {{
          if (String(r.base_url || '') !== state.filters.baseUrl) return false;
        }}
        if (state.filters.tech) {{
          const list = (r.tech || []).map(t => String(t));
          if (!list.includes(state.filters.tech)) return false;
        }}
        if (state.filters.waf) {{
          const list = (r.waf || []).map(w => String(w));
          if (!list.includes(state.filters.waf)) return false;
        }}
        if (state.filters.status) {{
          const code = Number(String(state.filters.status).split(' ')[0]);
          if (Number(r.status || 0) !== code) return false;
        }}
        if (state.filters.server) {{
          if (String(r.server || '') !== state.filters.server) return false;
        }}
        if (state.filters.contentType) {{
          if (String(r.content_type || '') !== state.filters.contentType) return false;
        }}
        if (state.filters.payloadFamily) {{
          if (String(r.payload_family || '') !== state.filters.payloadFamily) return false;
        }}

        return true;
      }}

      function renderTable(items) {{
        const rows = [];
        for (const r of items) {{
          const tech = (r.tech && r.tech.length) ? r.tech.join(', ') : 'UNKNOWN';
          const waf = (r.waf && r.waf.length) ? r.waf.join(', ') : 'NONE';
          const wafCell = waf === 'NONE'
            ? '<span class="text-slate-400 italic text-xs font-bold">NONE</span>'
            : `<span class="bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-400 px-3 py-1 rounded-lg text-xs font-bold border border-blue-100 dark:border-blue-900/30">${{escapeHtml(waf)}}</span>`;

          rows.push(
            `<tr class="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition-colors">
              <td class="px-6 py-5 text-sm font-semibold text-slate-900 dark:text-white break-all">
                <a class="text-primary hover:underline" href="${{escapeHtml(r.url)}}" target="_blank" rel="noreferrer">${{escapeHtml(r.url)}}</a>
              </td>
              <td class="px-6 py-5 text-sm font-mono text-primary font-bold break-all">${{escapeHtml(r.payload_mutated || '')}}</td>
              <td class="px-6 py-5"><span class="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-lg text-xs font-bold border border-slate-200 dark:border-slate-700">${{escapeHtml(tech.toUpperCase())}}</span></td>
              <td class="px-6 py-5">${{wafCell}}</td>
              <td class="px-6 py-5"><span class="${{statusClass(r.status)}} px-3 py-1 rounded-lg text-xs font-bold">${{escapeHtml(statusLabel(r.status))}}</span></td>
              <td class="px-6 py-5 text-sm font-medium text-slate-600 dark:text-slate-400">${{escapeHtml(r.title || '')}}</td>
              <td class="px-6 py-5 text-sm font-medium text-slate-600 dark:text-slate-400 whitespace-nowrap">${{escapeHtml(bytesHuman(r.size))}}</td>
              <td class="px-6 py-5 text-sm font-medium text-slate-600 dark:text-slate-400 break-all">${{escapeHtml(r.content_type || '')}}</td>
              <td class="px-6 py-5 text-sm font-bold text-slate-900 dark:text-white text-right">${{Number(r.words || 0)}}</td>
            </tr>`
          );
        }}
        tableBody.innerHTML = rows.join('');
      }}

      function renderGrid(items) {{
        const cards = [];
        for (const r of items) {{
          const tech = (r.tech && r.tech.length) ? r.tech.join(', ') : 'UNKNOWN';
          const waf = (r.waf && r.waf.length) ? r.waf.join(', ') : 'NONE';
          cards.push(
            `<div class="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-5 shadow-sm">
              <div class="flex items-start justify-between gap-4">
                <div class="flex flex-col gap-1 min-w-0">
                  <a class="text-primary font-bold hover:underline break-all" href="${{escapeHtml(r.url)}}" target="_blank" rel="noreferrer">${{escapeHtml(r.url)}}</a>
                  <div class="text-xs text-slate-500 dark:text-slate-400 font-medium break-all">${{escapeHtml(r.base_url || '')}}</div>
                </div>
                <span class="${{statusClass(r.status)}} px-3 py-1 rounded-lg text-xs font-bold whitespace-nowrap">${{escapeHtml(statusLabel(r.status))}}</span>
              </div>
              <div class="mt-4 flex flex-col gap-2">
                <div class="text-sm font-mono text-primary font-bold break-all">${{escapeHtml(r.payload_mutated || '')}}</div>
                <div class="text-sm text-slate-700 dark:text-slate-300 font-medium">${{escapeHtml(r.title || '')}}</div>
              </div>
              <div class="mt-4 flex flex-wrap gap-2">
                <span class="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-lg text-xs font-bold border border-slate-200 dark:border-slate-700">${{escapeHtml(tech.toUpperCase())}}</span>
                <span class="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-lg text-xs font-bold border border-slate-200 dark:border-slate-700">${{escapeHtml(waf.toUpperCase())}}</span>
                <span class="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-lg text-xs font-bold border border-slate-200 dark:border-slate-700">${{escapeHtml(bytesHuman(r.size))}}</span>
                <span class="bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 px-3 py-1 rounded-lg text-xs font-bold border border-slate-200 dark:border-slate-700">${{escapeHtml(r.content_type || '')}}</span>
              </div>
            </div>`
          );
        }}
        gridCards.innerHTML = cards.join('');
      }}

      function formatWithCommas(n) {{
        const s = String(Number(n || 0));
        return s.replace(/\B(?=(\d{{3}})+(?!\d))/g, ",");
      }}

      function buildPageButtons(page, pageCount) {{
        const buttons = [];
        const maxButtons = 7;

        function btn(p, active) {{
          const cls = active
            ? 'flex items-center justify-center size-9 rounded-lg bg-primary text-white font-display text-xs'
            : 'flex items-center justify-center size-9 rounded-lg hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 transition-colors font-bold text-xs border border-slate-200 dark:border-slate-700';
          return `<button data-page="${{p}}" class="${{cls}}" type="button">${{p}}</button>`;
        }}

        if (pageCount <= maxButtons) {{
          for (let p = 1; p <= pageCount; p++) buttons.push(btn(p, p === page));
          return buttons.join('');
        }}

        const left = Math.max(1, page - 2);
        const right = Math.min(pageCount, page + 2);

        buttons.push(btn(1, page === 1));
        if (left > 2) buttons.push('<div class="flex items-center justify-center size-9 text-slate-400 font-bold">…</div>');
        for (let p = left; p <= right; p++) {{
          if (p === 1 || p === pageCount) continue;
          buttons.push(btn(p, p === page));
        }}
        if (right < pageCount - 1) buttons.push('<div class="flex items-center justify-center size-9 text-slate-400 font-bold">…</div>');
        buttons.push(btn(pageCount, page === pageCount));

        return buttons.join('');
      }}

      function render() {{
        const filtered = records.filter(recordMatchesFilters);
        const total = filtered.length;

        state.pageSize = Number(pageSizeEl.value || 25);
        const pageCount = Math.max(1, Math.ceil(total / state.pageSize));
        state.page = Math.min(Math.max(1, state.page), pageCount);

        const startIdx = (state.page - 1) * state.pageSize;
        const endIdx = Math.min(total, startIdx + state.pageSize);
        const slice = filtered.slice(startIdx, endIdx);

        resultsTotal.textContent = `${{formatWithCommas(total)}} TOTAL RESULTS`;
        resultsRange.textContent = total === 0 ? 'Showing 0-0' : `Showing ${{startIdx + 1}}-${{endIdx}} of ${{formatWithCommas(total)}}`;

        pagePrev.disabled = state.page <= 1;
        pageNext.disabled = state.page >= pageCount;
        pagePrev.classList.toggle('opacity-50', pagePrev.disabled);
        pageNext.classList.toggle('opacity-50', pageNext.disabled);

        pageButtons.innerHTML = buildPageButtons(state.page, pageCount);
        for (const el of pageButtons.querySelectorAll('button[data-page]')) {{
          el.addEventListener('click', function() {{
            state.page = Number(el.getAttribute('data-page') || 1);
            render();
          }});
        }}

        if (state.view === 'grid') {{
          renderGrid(slice);
        }} else {{
          renderTable(slice);
        }}
      }}

      pagePrev.addEventListener('click', function() {{
        if (state.page > 1) {{
          state.page -= 1;
          render();
        }}
      }});
      pageNext.addEventListener('click', function() {{
        state.page += 1;
        render();
      }});

      pageSizeEl.addEventListener('change', function() {{
        state.page = 1;
        render();
      }});

      let searchTimer = null;
      searchEl.addEventListener('input', function() {{
        clearTimeout(searchTimer);
        searchTimer = setTimeout(function() {{
          state.query = searchEl.value || '';
          state.page = 1;
          render();
        }}, 80);
      }});

      render();
    }})();
  </script>
</body>
</html>"####,
    );

    html.into_bytes()
}
