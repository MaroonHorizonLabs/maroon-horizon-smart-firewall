/* Scanner UI logic (migrated from inline <script> for WP.org compliance) */
(function(){
    'use strict';

    const data = (window.sfaisScannerData && typeof window.sfaisScannerData === 'object') ? window.sfaisScannerData : {};
    const ajaxurl = window.ajaxurl || data.ajaxurl || '';
    const nonce = data.nonce || '';
    const LAST_CORE    = (typeof data.lastCore !== 'undefined') ? data.lastCore : null;
    const LAST_CONTENT = (typeof data.lastContent !== 'undefined') ? data.lastContent : null;
const isPro = !!data.isPro;

    /* --------------------------
       🧩 QUARANTINE MANAGEMENT
       (always visible, empty state supported)
       -------------------------- */

    const clearNode = (node) => {
      if (!node) return;
      while (node.firstChild) node.removeChild(node.firstChild);
    };

    const makeNotice = (type, text, subText) => {
      const wrap = document.createElement('div');
      wrap.className = `notice notice-${type}`;
      wrap.style.margin = '0';

      const p = document.createElement('p');
      p.style.margin = '8px 0';
      p.textContent = String(text || '');

      if (subText) {
        const span = document.createElement('span');
        span.style.color = 'var(--mh-muted, #666)';
        span.textContent = ' ' + String(subText);
        p.appendChild(span);
      }

      wrap.appendChild(p);
      return wrap;
    };

    const renderQuarantineEmpty = () => {
      const box  = document.getElementById('sfais-quarantine-results');
      const card = document.getElementById('sfais-quarantine-card');
      if (!box || !card) return;

      card.style.display = 'block';
      clearNode(box);

      box.appendChild(
        makeNotice(
          'info',
          'No files are currently quarantined.',
          'Quarantined items appear here after you move a file to quarantine from scan results.'
        )
      );
    };

    const renderQuarantine = (data) => {
      const box  = document.getElementById('sfais-quarantine-results');
      const card = document.getElementById('sfais-quarantine-card');
      if (!box || !card) return;

      card.style.display = 'block';

      const items = (data && Array.isArray(data.items)) ? data.items : [];
      if (!items.length) {
        renderQuarantineEmpty();
        return;
      }

      clearNode(box);

      const wrap = document.createElement('div');
      wrap.className = 'sfais-table-wrap';

      const table = document.createElement('table');
      table.className = 'widefat';

      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      ['Original File', 'Reason', 'Date', 'Action'].forEach((label) => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);

      const tbody = document.createElement('tbody');

      items.forEach((item) => {
        const q = String((item && item.quarantine) ? item.quarantine : '');
        const orig = String((item && item.original) ? item.original : '');
        const reason = String((item && item.reason) ? item.reason : '');
        const date = String((item && item.date) ? item.date : '');

        const tr = document.createElement('tr');
        tr.dataset.file = q;

        const tdFile = document.createElement('td');
        tdFile.setAttribute('data-label','Original File');
        const code = document.createElement('code');
        code.textContent = orig;
        tdFile.appendChild(code);

        const tdReason = document.createElement('td');
        tdReason.setAttribute('data-label','Reason');
        tdReason.textContent = reason || '';

        const tdDate = document.createElement('td');
        tdDate.setAttribute('data-label','Date');
        tdDate.textContent = date || '';

        const tdAction = document.createElement('td');
        tdAction.style.textAlign = 'right';
        tdAction.setAttribute('data-label','Action');

        const btnRestore = document.createElement('button');
        btnRestore.type = 'button';
        btnRestore.className = 'button';
        btnRestore.textContent = '♻️ Restore';
        btnRestore.dataset.act = 'restore';
        btnRestore.dataset.file = q;

        const btnRemove = document.createElement('button');
        btnRemove.type = 'button';
        btnRemove.className = 'button';
        btnRemove.style.marginLeft = '6px';
        btnRemove.textContent = '🗑️ Delete from Quarantine';
        btnRemove.dataset.act = 'remove';
        btnRemove.dataset.file = q;

        const actWrap = document.createElement('div');
        actWrap.className = 'sfais-actions';
        actWrap.appendChild(btnRestore);
        actWrap.appendChild(btnRemove);
        tdAction.appendChild(actWrap);

        tr.appendChild(tdFile);
        tr.appendChild(tdReason);
        tr.appendChild(tdDate);
        tr.appendChild(tdAction);

        tbody.appendChild(tr);
      });

      table.appendChild(thead);
      table.appendChild(tbody);
      wrap.appendChild(table);
      box.appendChild(wrap);

      box.querySelectorAll('button[data-act]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const act = btn.dataset.act;
          const file = btn.dataset.file;

          btn.disabled = true;
          const originalText = btn.textContent;
          btn.textContent = '...';

          const action = (act === 'restore') ? 'sfais_quarantine_restore' : 'sfais_quarantine_remove';

          const form = new URLSearchParams();
          form.append('action', action);
          form.append('file', file || '');
          form.append('nonce', nonce);

          fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
            .then((r) => r.json())
            .then((d) => {
              if (d && d.success) {
                loadQuarantine(true);
                // Restore affects the scan surface; refresh content report display is handled by next scan.
              } else {
                window.alert((d && d.data && d.data.message) ? d.data.message : 'Action failed.');
              }
            })
            .catch(() => window.alert('Network error.'))
            .finally(() => {
              btn.disabled = false;
              btn.textContent = originalText;
            });
        });
      });
    };


    const loadQuarantine = (forceRefresh = false) => {
      if (forceRefresh) {
        renderQuarantineEmpty();
      }

      const form = new URLSearchParams();
      form.append('action', 'sfais_quarantine_list');
      form.append('nonce', nonce);

      fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
        .then((r) => r.json())
        .then((d) => {
          if (d && d.success && d.data) {
            renderQuarantine(d.data);
          } else {
            renderQuarantineEmpty();
          }
        })
        .catch(() => renderQuarantineEmpty());
    };

    loadQuarantine();

    /* --------------------------
       🙈 IGNORED FILES (1.8.13)
       Small list with an Un-ignore button per file. The server drops entries whose file no longer exists.
       -------------------------- */

    const renderIgnored = (list) => {
      const box = document.getElementById('sfais-ignored-results');
      const countEl = document.getElementById('sfais-ignored-count');
      if (!box) return;

      const items = Array.isArray(list) ? list : [];
      if (countEl) countEl.textContent = String(items.length);
      clearNode(box);

      if (!items.length) {
        box.appendChild(makeNotice('info', 'No files are ignored.'));
        return;
      }

      const wrap = document.createElement('div');
      wrap.className = 'sfais-table-wrap';
      wrap.style.maxHeight = '320px';
      wrap.style.overflowY = 'auto';

      const table = document.createElement('table');
      table.className = 'widefat';

      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      ['File', 'Ignored on', 'Action'].forEach((label) => {
        const th = document.createElement('th');
        th.textContent = label;
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);

      const tbody = document.createElement('tbody');

      items.forEach((it) => {
        const f = String((it && it.file) ? it.file : '');
        if (!f) return;

        const tr = document.createElement('tr');

        const tdFile = document.createElement('td');
        tdFile.setAttribute('data-label', 'File');
        const code = document.createElement('code');
        code.textContent = f;
        tdFile.appendChild(code);
        if (it && it.missing) {
          tdFile.appendChild(document.createTextNode(' (missing file)'));
        }

        const tdTime = document.createElement('td');
        tdTime.setAttribute('data-label', 'Ignored on');
        tdTime.textContent = String((it && it.time) ? it.time : '');

        const tdAct = document.createElement('td');
        tdAct.style.textAlign = 'right';
        tdAct.setAttribute('data-label', 'Action');

        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'button';
        btn.textContent = 'Un-ignore';
        btn.addEventListener('click', () => {
          btn.disabled = true;
          const form = new URLSearchParams();
          form.append('action', 'sfais_scanner_unignore');
          form.append('file', f);
          form.append('nonce', nonce);

          fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
            .then((r) => r.json())
            .then((d) => {
              if (d && d.success) {
                tr.remove();
                const left = tbody.querySelectorAll('tr').length;
                if (countEl) countEl.textContent = String(left);
                if (!left) renderIgnored([]);
              } else {
                window.alert((d && d.data && d.data.message) ? d.data.message : 'Action failed.');
                btn.disabled = false;
              }
            })
            .catch(() => { window.alert('Network error.'); btn.disabled = false; });
        });
        tdAct.appendChild(btn);

        tr.appendChild(tdFile);
        tr.appendChild(tdTime);
        tr.appendChild(tdAct);
        tbody.appendChild(tr);
      });

      table.appendChild(thead);
      table.appendChild(tbody);
      wrap.appendChild(table);
      box.appendChild(wrap);
    };

    const loadIgnored = () => {
      const box = document.getElementById('sfais-ignored-results');
      if (!box) return;

      const form = new URLSearchParams();
      form.append('action', 'sfais_scanner_ignored_list');
      form.append('nonce', nonce);

      fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
        .then((r) => r.json())
        .then((d) => {
          if (d && d.success && d.data) {
            renderIgnored(d.data.items);
          } else {
            clearNode(box);
            box.appendChild(makeNotice('error', 'Could not load the ignored files.'));
          }
        })
        .catch(() => {
          clearNode(box);
          box.appendChild(makeNotice('error', 'Could not load the ignored files.'));
        });
    };

    loadIgnored();

    /* --------------------------
       🧠 EXISTING SCANNER LOGIC
       -------------------------- */

    const makeStatusBadge = (status) => {
      const span = document.createElement('span');
      span.className = 'sfais-badge info';

      const map = {
        clean:     { cls: 'ok',   text: 'Clean' },
        modified:  { cls: 'warn', text: 'Modified' },
        missing:   { cls: 'crit', text: 'Missing' },
        suspicious:{ cls: 'crit', text: 'Suspicious' },
        ignored:   { cls: 'info', text: 'Ignored' },
        unknown:   { cls: 'info', text: 'Unknown' }
      };

      const it = map[status] || map.unknown;
      span.className = `sfais-badge ${it.cls}`;
      span.textContent = it.text;
      return span;
    };

    const renderNoticeInBox = (box, type, message) => {
      if (!box) return;
      clearNode(box);
      box.appendChild(makeNotice(type, message));
    };

    const renderReport = (targetId, report) => {
      const box = document.getElementById(targetId);
      if (!box) return;

      const isCore = report && report.type === 'core';
      const time = (report && report.timestamp) ? report.timestamp : new Date().toLocaleString();
      const summary = (report && report.summary && typeof report.summary === 'object') ? report.summary : {};
      const items = (report && Array.isArray(report.items)) ? report.items : [];

      clearNode(box);

      const outer = document.createElement('div');
      outer.className = 'sfais-card';
      outer.style.marginTop = '10px';
      if (isCore) outer.classList.add('sfais-core-report');

      // Minimal styling for core-bulk selection UX (scoped).
      if (isCore && !document.getElementById('sfais-core-bulk-style')) {
        const st = document.createElement('style');
        st.id = 'sfais-core-bulk-style';
        st.textContent = `
          .sfais-core-report td[data-label="Select"],
          .sfais-core-report th:first-child { width: 1%; }
          .sfais-core-report td[data-label="Select"] { vertical-align: middle; }
          .sfais-core-report tr.sfais-row-selected { background: var(--mh-infobg, #f6fbff); }
          .sfais-core-report .sfais-actions { display: flex; justify-content: flex-end; gap: 6px; flex-wrap: wrap; }
        `;
        document.head.appendChild(st);
      }

      const h4 = document.createElement('h4');
      h4.style.margin = '0 0 6px';
      h4.textContent = `Results — ${isCore ? 'Core Integrity' : 'Content Scan'}`;
      outer.appendChild(h4);

      // Summary metrics
      const summaryWrap = document.createElement('div');
      summaryWrap.className = 'sfais-summary';

      Object.entries(summary).forEach(([k, v]) => {
        const div = document.createElement('div');
        let cls = 'info';
        if (['clean'].includes(k)) cls = 'ok';
        if (['modified', 'suspicious'].includes(k)) cls = 'warn';
        if (['missing', 'unknown'].includes(k)) cls = 'crit';
        div.className = `metric ${cls}`;
        div.textContent = `${k}: ${v}`;
        summaryWrap.appendChild(div);
      });

      outer.appendChild(summaryWrap);

      const meta = document.createElement('div');
      meta.style.fontSize = '12px';
      meta.style.color = 'var(--mh-muted, #666)';
      meta.style.marginBottom = '6px';

      const strong = document.createElement('strong');
      strong.textContent = 'Scan Time:';
      meta.appendChild(strong);
      meta.appendChild(document.createTextNode(' ' + time));
      outer.appendChild(meta);

      // Only render problematic items
      const bad = items.filter((it) => ['modified', 'missing', 'suspicious', 'unknown'].includes(it.status));

      if (!bad.length) {
        const p = document.createElement('p');
        p.style.color = 'var(--mh-ok, #2e7d32)';
        p.style.fontWeight = '600';
        p.textContent = '✅ No issues found. All files appear safe.';
        outer.appendChild(p);

        box.appendChild(outer);
        return;
      }
      // Bulk actions (Core Integrity only)
      let bulkUi = null;
      let bulkSelectAll = null;
      let bulkBtnSelected = null;
      let bulkBtnAll = null;
      let bulkMsg = null;

      if (isCore) {
        bulkUi = document.createElement('div');
        bulkUi.className = 'sfais-bulk-actions';
        bulkUi.style.display = 'flex';
        bulkUi.style.flexWrap = 'wrap';
        bulkUi.style.alignItems = 'center';
        bulkUi.style.justifyContent = 'space-between';
        bulkUi.style.gap = '8px';
        bulkUi.style.padding = '8px 10px';
        bulkUi.style.margin = '10px 0';
        bulkUi.style.border = '1px solid #e5e5e5';
        bulkUi.style.borderRadius = '6px';
        bulkUi.style.background = 'var(--mh-card, #fff)';

        const left = document.createElement('div');
        left.style.display = 'flex';
        left.style.alignItems = 'center';
        left.style.gap = '8px';

        bulkSelectAll = document.createElement('input');
        bulkSelectAll.type = 'checkbox';
        bulkSelectAll.id = 'sfais-core-select-all-' + String(targetId || 'core');

        const selLbl = document.createElement('label');
        selLbl.setAttribute('for', bulkSelectAll.id);
        selLbl.style.cursor = 'pointer';
        selLbl.textContent = 'Select all';

        left.appendChild(bulkSelectAll);
        left.appendChild(selLbl);

        const right = document.createElement('div');
        right.style.display = 'flex';
        right.style.alignItems = 'center';
        right.style.gap = '8px';
        right.style.flexWrap = 'wrap';

        bulkBtnSelected = document.createElement('button');
        bulkBtnSelected.type = 'button';
        bulkBtnSelected.className = 'button';
        bulkBtnSelected.disabled = true;
        bulkBtnSelected.textContent = '🙈 Ignore Selected';

        bulkBtnAll = document.createElement('button');
        bulkBtnAll.type = 'button';
        bulkBtnAll.className = 'button button-secondary';
        bulkBtnAll.textContent = '🙈 Ignore All';

        bulkMsg = document.createElement('span');
        bulkMsg.style.fontSize = '12px';
        bulkMsg.style.color = 'var(--mh-muted, #666)';
        bulkMsg.textContent = '';

        right.appendChild(bulkBtnSelected);
        right.appendChild(bulkBtnAll);
        right.appendChild(bulkMsg);

        bulkUi.appendChild(left);
        bulkUi.appendChild(right);
        outer.appendChild(bulkUi);
      }

      const tableWrap = document.createElement('div');
      tableWrap.className = 'sfais-table-wrap';

      const table = document.createElement('table');
      table.className = 'widefat';

      const thead = document.createElement('thead');
      const hr = document.createElement('tr');
      const headers = isCore ? ['Select', 'File', 'Status', 'Reason', 'Action'] : ['File', 'Status', 'Reason', 'Action'];
      headers.forEach((label) => {
        const th = document.createElement('th');
        th.textContent = label;
        hr.appendChild(th);
      });
      thead.appendChild(hr);

      const tbody = document.createElement('tbody');

      const actionToAjax = { move: 'sfais_quarantine_move', delete: 'sfais_quarantine_delete', ignore: 'sfais_quarantine_ignore' };
      const actionLabels = { move: '📦 Move to Quarantine', delete: '🗑️ Delete Original File', ignore: '🙈 Ignore' };

      bad.forEach((it) => {
        const f = String(it.file || '');
        const st = String(it.status || 'unknown');
        const rs = String(it.reason || '');

        const tr = document.createElement('tr');
        tr.dataset.file = f;

        if (isCore) {
          const tdSel = document.createElement('td');
          tdSel.style.width = '1%';
          tdSel.setAttribute('data-label','Select');

          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.className = 'sfais-row-select';
          cb.value = f;
          cb.setAttribute('aria-label', 'Select ' + f);

          tdSel.appendChild(cb);
          tr.appendChild(tdSel);
        }

        const tdFile = document.createElement('td');
        tdFile.style.width = '50%';
        tdFile.setAttribute('data-label','File');
        const code = document.createElement('code');
        code.textContent = f;
        tdFile.appendChild(code);

        const tdStatus = document.createElement('td');
        tdStatus.style.width = '15%';
        tdStatus.setAttribute('data-label','Status');
        tdStatus.appendChild(makeStatusBadge(st));

        const tdReason = document.createElement('td');
        tdReason.style.width = '25%';
        tdReason.setAttribute('data-label','Reason');
        tdReason.textContent = rs;

        const tdAct = document.createElement('td');
        tdAct.style.width = '10%';
        tdAct.setAttribute('data-label','Action');

        const actWrap = document.createElement('div');
        actWrap.className = 'sfais-actions';

        const actions = isCore ? ['ignore'] : ['move', 'delete', 'ignore'];

        actions.forEach((act) => {
          const b = document.createElement('button');
          b.type = 'button';
          b.className = 'button';
          b.dataset.act = act;
          b.dataset.file = f;
          b.textContent = actionLabels[act] || act;
          b.addEventListener('click', (e) => {
            e.preventDefault();

            if (act === 'delete') {
              const ok = window.confirm('Delete the ORIGINAL file from your site?\n\nThis is a dangerous action and cannot be undone.\n\nClick OK to delete, or Cancel to stop.');
              if (!ok) return;
            }

            b.disabled = true;
            const originalText = b.textContent;
            b.textContent = '...';

            const form = new URLSearchParams();
            form.append('action', actionToAjax[act]);
            form.append('file', f);
            form.append('nonce', nonce);

            fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
              .then((r) => r.json())
              .then((d) => {
                if (d && d.success) {
                  tr.style.opacity = '0';
                  setTimeout(() => tr.remove(), 300);
                  loadQuarantine(true);
                  if (act === 'ignore') loadIgnored();   // 1.8.13
                } else {
                  window.alert((d && d.data && d.data.message) ? d.data.message : 'Action failed.');
                }
              })
              .catch(() => window.alert('Network error.'))
              .finally(() => {
                b.disabled = false;
                b.textContent = originalText;
              });
          });

          actWrap.appendChild(b);
        });

        tdAct.appendChild(actWrap);

        tr.appendChild(tdFile);
        tr.appendChild(tdStatus);
        tr.appendChild(tdReason);
        tr.appendChild(tdAct);

        tbody.appendChild(tr);
      });

      table.appendChild(thead);
      table.appendChild(tbody);
      tableWrap.appendChild(table);
      // Wire up bulk selection + bulk ignore (Core Integrity only)
      if (isCore && bulkUi) {
        const escAttr = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\"');

        const updateSelectedState = () => {
          const boxes = table.querySelectorAll('input.sfais-row-select');
          const checked = Array.from(boxes).filter((cb) => cb.checked);
          const total = boxes.length;

          if (bulkBtnSelected) bulkBtnSelected.disabled = checked.length === 0;
          if (bulkSelectAll) {
            bulkSelectAll.checked = (total > 0 && checked.length === total);
            bulkSelectAll.indeterminate = (checked.length > 0 && checked.length < total);
          }
          if (bulkMsg) bulkMsg.textContent = checked.length ? `${checked.length} selected` : '';
        };

        const setAll = (state) => {
          table.querySelectorAll('input.sfais-row-select').forEach((cb) => {
            cb.checked = !!state;
            const tr = cb.closest('tr');
            if (tr) tr.classList.toggle('sfais-row-selected', cb.checked);
          });
          updateSelectedState();
        };

        if (bulkSelectAll) {
          bulkSelectAll.addEventListener('change', () => setAll(bulkSelectAll.checked));
        }

        table.querySelectorAll('input.sfais-row-select').forEach((cb) => {
          cb.addEventListener('change', () => {
            const tr = cb.closest('tr');
            if (tr) tr.classList.toggle('sfais-row-selected', cb.checked);
            updateSelectedState();
          });
        });

        const doBulkIgnore = (files) => {
          const clean = (Array.isArray(files) ? files : []).map((x) => String(x || '')).filter(Boolean);
          if (!clean.length) return;

          if (bulkBtnSelected) bulkBtnSelected.disabled = true;
          if (bulkBtnAll) bulkBtnAll.disabled = true;
          if (bulkMsg) bulkMsg.textContent = `Ignoring ${clean.length}...`;

          const form = new URLSearchParams();
          form.append('action', 'sfais_quarantine_ignore_bulk');
          form.append('nonce', nonce);
          form.append('files', JSON.stringify(clean));

          fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
            .then((r) => r.json())
            .then((d) => {
              const ok = d && d.success && d.data;
              const ignoredCount = ok ? (parseInt(d.data.ignored || 0, 10) || 0) : 0;
              const failedCount = ok ? (Array.isArray(d.data.failed) ? d.data.failed.length : 0) : 0;

              if (!ok || ignoredCount <= 0) {
                const msg = (d && d.data && d.data.message) ? d.data.message : 'Bulk ignore failed.';
                if (bulkMsg) bulkMsg.textContent = msg;
                return;
              }

              loadIgnored();   // 1.8.13

              // Remove ignored rows from the current table.
              clean.forEach((f) => {
                const row = table.querySelector(`tr[data-file="${escAttr(f)}"]`);
                if (row) row.remove();
              });

              // Reset selection UI.
              if (bulkSelectAll) bulkSelectAll.checked = false;

              // If no rows remain, show the "all clear" message.
              const remaining = table.querySelectorAll('tbody tr').length;
              if (remaining === 0) {
                if (bulkUi) bulkUi.remove();
                if (tableWrap) tableWrap.remove();

                const p = document.createElement('p');
                p.style.color = 'var(--mh-ok, #2e7d32)';
                p.style.fontWeight = '600';
                p.textContent = '✅ All listed issues were ignored. Run the scan again if you want to re-validate.';
                outer.appendChild(p);

                return;
              }

              if (bulkMsg) {
                bulkMsg.textContent = failedCount ? `Ignored ${ignoredCount}. Failed ${failedCount}.` : `Ignored ${ignoredCount}.`;
              }
              updateSelectedState();
            })
            .catch(() => {
              if (bulkMsg) bulkMsg.textContent = 'Network error.';
            })
            .finally(() => {
              if (bulkBtnAll) bulkBtnAll.disabled = false;
              updateSelectedState();
            });
        };

        if (bulkBtnAll) {
          bulkBtnAll.addEventListener('click', () => {
            const ok = window.confirm('Ignore ALL files listed in these results?\n\nIgnored files will not appear again unless they change.');
            if (!ok) return;
            doBulkIgnore(bad.map((it) => it.file));
          });
        }

        if (bulkBtnSelected) {
          bulkBtnSelected.addEventListener('click', () => {
            const selected = Array.from(table.querySelectorAll('input.sfais-row-select'))
              .filter((cb) => cb.checked)
              .map((cb) => cb.value);

            if (!selected.length) return;

            const ok = window.confirm(`Ignore ${selected.length} selected file(s)?\n\nIgnored files will not appear again unless they change.`);
            if (!ok) return;

            doBulkIgnore(selected);
          });
        }

        // Initial state
        updateSelectedState();
      }
      outer.appendChild(tableWrap);
      box.appendChild(outer);
    };

    const runScan = (type) => {
      const btn = (type === 'core') ? document.getElementById('sfais-scan-core') : document.getElementById('sfais-scan-uploads');
      const box = (type === 'core') ? document.getElementById('sfais-core-results') : document.getElementById('sfais-content-results');
      if (!btn || !box) return;

      btn.disabled = true;
      const orig = btn.textContent;
      btn.textContent = 'Scanning...';

      const form = new URLSearchParams();
      // 1.8.13: content scan only - the core scan runs as an async job (the old sfais_scan_core endpoint was removed).
      form.append('action', 'sfais_scan_uploads');
      form.append('nonce', nonce);

      fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
        .then((r) => r.json())
        .then((d) => {
          if (d && d.success && d.data && d.data.report) {
            renderReport((type === 'core') ? 'sfais-core-results' : 'sfais-content-results', d.data.report);
          } else {
            const msg = (d && d.data && d.data.message) ? d.data.message : 'Scan failed.';
            renderNoticeInBox(box, 'error', msg);
          }
        })
        .catch(() => renderNoticeInBox(box, 'error', 'Network error.'))
        .finally(() => {
          btn.disabled = false;
          btn.textContent = orig;
        });
    };




    // 🧠 Render Deep Scan report (global renderer; used by async completion + page-load restore)
        // 🧠 Render Deep Scan report (rich UI, same logic as email)
        const renderAiDeepReport = (report)=>{
          const aiDeepResults = document.getElementById('sfais-ai-deep-results');
          const lastDeepEl    = document.getElementById('sfais-ai-last-deep');
          if (!aiDeepResults) return;

          const items   = (report && Array.isArray(report.items)) ? report.items : [];
          const summary = (report && report.summary && typeof report.summary === 'object') ? report.summary : {};
          const meta    = (report && report.meta && typeof report.meta === 'object') ? report.meta : {};

          const engineTotal = (typeof summary.total === 'number') ? summary.total : items.length;

          let susCnt = 0, cleanCnt = 0, ignoredCnt = 0, unknownCnt = 0;

          const hasAllSummaryCounts =
            Object.prototype.hasOwnProperty.call(summary, 'suspicious') &&
            Object.prototype.hasOwnProperty.call(summary, 'clean') &&
            Object.prototype.hasOwnProperty.call(summary, 'ignored') &&
            Object.prototype.hasOwnProperty.call(summary, 'unknown');

          if (hasAllSummaryCounts) {
            susCnt     = parseInt(summary.suspicious, 10) || 0;
            cleanCnt   = parseInt(summary.clean, 10)      || 0;
            ignoredCnt = parseInt(summary.ignored, 10)    || 0;
            unknownCnt = parseInt(summary.unknown, 10)    || 0;
          } else {
            items.forEach((it) => {
              switch (it.status) {
                case 'suspicious': susCnt++; break;
                case 'clean':      cleanCnt++; break;
                case 'ignored':    ignoredCnt++; break;
                case 'unknown':    unknownCnt++; break;
              }
            });
          }

          const reportedTotal = susCnt + cleanCnt + ignoredCnt + unknownCnt;
          const otherFiles    = (engineTotal > reportedTotal) ? (engineTotal - reportedTotal) : 0;

          const time = (report && report.timestamp) ? report.timestamp : new Date().toLocaleString();

          // 1.8.13: a failed automatic Deep Scan stores an empty report with meta.status = 'error'. It is not "clean": say so.
          if (meta.status === 'error') {
            if (lastDeepEl) lastDeepEl.textContent = time + ' (did not finish)';
            clearNode(aiDeepResults);
            const errCard = document.createElement('div');
            errCard.className = 'sfais-card';
            errCard.style.marginTop = '10px';
            const errTitle = document.createElement('h4');
            errTitle.style.margin = '0 0 4px';
            errTitle.textContent = 'Deep Scan Results';
            errCard.appendChild(errTitle);
            const why = meta.message ? String(meta.message).replace(/[.\s]+$/, '') : '';
            errCard.appendChild(makeNotice('warning', `The last automatic Deep Scan did not finish (${why ? why + ', ' : ''}${time}).`));
            aiDeepResults.appendChild(errCard);
            return;
          }

          if (lastDeepEl) lastDeepEl.textContent = time;

          const durationMs = (typeof meta.duration_ms !== 'undefined' && meta.duration_ms !== null) ? parseInt(meta.duration_ms, 10) : null;
          const durationSec = (durationMs && !isNaN(durationMs)) ? (durationMs / 1000).toFixed(1) : null;

          const suspiciousItems = items.filter((it) => it.status === 'suspicious');

          clearNode(aiDeepResults);

          const outer = document.createElement('div');
          outer.className = 'sfais-card';
          outer.style.marginTop = '10px';

          const title = document.createElement('h4');
          title.style.margin = '0 0 4px';
          title.textContent = 'Deep Scan Results';
          outer.appendChild(title);

          // Status badge
          const badgeWrap = document.createElement('div');
          badgeWrap.style.margin = '2px 0 6px';
          const statusBadge = document.createElement('span');
          statusBadge.className = `sfais-badge ${susCnt > 0 ? 'crit' : 'ok'}`;
          statusBadge.textContent = (susCnt > 0) ? 'Suspicious files detected' : 'No suspicious files detected';
          badgeWrap.appendChild(statusBadge);
          outer.appendChild(badgeWrap);

          // Metrics (engine)
          const engineMetrics = document.createElement('div');
          engineMetrics.className = 'sfais-summary';
          engineMetrics.style.marginTop = '4px';

          const metricBox = (key, label, value, helpKey, cls = 'info') => {
            const box = document.createElement('div');
            box.className = `metric ${cls}`;

            const lbl = document.createElement('div');
            lbl.className = 'sfais-metric-label';
            lbl.appendChild(document.createTextNode(label));

            if (helpKey) {
              const helpBtn = document.createElement('button');
              helpBtn.type = 'button';
              helpBtn.className = 'sfais-metric-help';
              helpBtn.dataset.helpKey = helpKey;
              helpBtn.setAttribute('aria-label', `What does '${label}' mean?`);
              helpBtn.textContent = '?';
              lbl.appendChild(helpBtn);
            }

            const strong = document.createElement('strong');
            strong.textContent = String(value);

            box.appendChild(lbl);
            box.appendChild(strong);
            return box;
          };

          engineMetrics.appendChild(metricBox('ai_total', 'Total scanned (scan engine)', engineTotal, 'ai_total', 'info'));
          engineMetrics.appendChild(metricBox('ai_reported', 'Files in this report', reportedTotal, 'ai_reported', 'info'));
          if (otherFiles > 0) {
            engineMetrics.appendChild(metricBox('ai_other', 'Other scanned files', otherFiles, 'ai_other', 'info'));
          }
          outer.appendChild(engineMetrics);

          // Metrics (detection)
          const detectionMetrics = document.createElement('div');
          detectionMetrics.className = 'sfais-summary';
          detectionMetrics.style.marginTop = '4px';

          detectionMetrics.appendChild(metricBox('ai_suspicious', 'Suspicious', susCnt, 'ai_suspicious', 'crit'));
          detectionMetrics.appendChild(metricBox('ai_clean', 'Clean', cleanCnt, 'ai_clean', 'ok'));
          detectionMetrics.appendChild(metricBox('ai_ignored', 'Ignored', ignoredCnt, 'ai_ignored', 'info'));
          detectionMetrics.appendChild(metricBox('ai_unreadable', 'Unreadable', unknownCnt, 'ai_unreadable', 'warn'));

          outer.appendChild(detectionMetrics);

          // Meta line
          const metaLine = document.createElement('div');
          metaLine.style.fontSize = '12px';
          metaLine.style.color = 'var(--mh-muted, #666)';
          metaLine.style.margin = '4px 0 8px';

          const s1 = document.createElement('strong');
          s1.textContent = 'Scan time:';
          metaLine.appendChild(s1);
          metaLine.appendChild(document.createTextNode(' ' + time));

          if (durationMs && !isNaN(durationMs)) {
            metaLine.appendChild(document.createTextNode(' · '));
            const s2 = document.createElement('strong');
            s2.textContent = 'Duration:';
            metaLine.appendChild(s2);
            metaLine.appendChild(document.createTextNode(` ${durationMs} ms${durationSec ? ' (~' + durationSec + ' s)' : ''}`));
          }

          outer.appendChild(metaLine);

          // Suspicious table or clean message
          if (susCnt > 0 && suspiciousItems.length) {
            const h = document.createElement('h4');
            h.style.margin = '10px 0 4px';
            h.textContent = `Suspicious files (${susCnt})`;
            outer.appendChild(h);

            const p = document.createElement('p');
            p.style.margin = '0 0 6px';
            p.style.fontSize = '12px';
            p.style.color = 'var(--mh-muted, #666)';
            p.textContent = 'These files were flagged as high risk by the malware signatures and/or dangerous-function detection. Review them carefully and quarantine or remove anything you do not recognise.';
            outer.appendChild(p);

            const tableWrap = document.createElement('div');
            tableWrap.className = 'sfais-table-wrap';

            const table = document.createElement('table');
            table.className = 'widefat';

            const thead = document.createElement('thead');
            const trh = document.createElement('tr');
            ['File', 'Risk', 'Reason & metadata', 'Action'].forEach((label) => {
              const th = document.createElement('th');
              th.textContent = label;
              trh.appendChild(th);
            });
            thead.appendChild(trh);

            const tbody = document.createElement('tbody');

            const actionToAjax = { move: 'sfais_quarantine_move', delete: 'sfais_quarantine_delete', ignore: 'sfais_quarantine_ignore' };
            const actionLabels = { move: '📦 Quarantine', delete: '🗑️ Delete Original File', ignore: '🙈 Ignore' };

            suspiciousItems.forEach((it) => {
              const f = String(it.file || '');
              const rs = String(it.reason || '');

              const tr = document.createElement('tr');

              const tdFile = document.createElement('td');
              tdFile.style.width = '45%';
              const code = document.createElement('code');
              code.textContent = f;
              tdFile.appendChild(code);

              const tdAi = document.createElement('td');
              tdAi.style.width = '15%';
              const aiScore = (typeof it.ai_score !== 'undefined' && it.ai_score !== null) ? parseInt(it.ai_score, 10) : null;
              const aiSpan = document.createElement('span');
              if (aiScore !== null && !isNaN(aiScore)) {
                aiSpan.className = 'sfais-badge crit';
                aiSpan.textContent = `Risk score: ${aiScore}/100`;
              } else {
                aiSpan.className = 'sfais-badge info';
                aiSpan.textContent = 'Risk: n/a';
              }
              tdAi.appendChild(aiSpan);

              const tdReason = document.createElement('td');
              tdReason.style.width = '30%';
              tdReason.appendChild(document.createTextNode(rs));

              const metaParts = [];

              const hash = it.hash ? String(it.hash) : '';
              const entropy = (typeof it.entropy !== 'undefined' && it.entropy !== null) ? it.entropy : null;
              const category = it.category ? String(it.category) : '';
              const duration = (typeof it.duration_ms !== 'undefined' && it.duration_ms !== null) ? String(it.duration_ms) : '';

              if (hash) metaParts.push({ k: 'Hash', v: hash, code: true });
              if (entropy !== null) metaParts.push({ k: 'Entropy', v: (typeof entropy === 'number') ? entropy.toFixed(2) : String(entropy), code: false });
              if (category) metaParts.push({ k: 'Category', v: category, code: false });
              if (duration) metaParts.push({ k: 'Scan time', v: `${duration} ms`, code: false });

              if (metaParts.length) {
                const metaLine = document.createElement('div');
                metaLine.className = 'sfais-meta-line';

                metaParts.forEach((part, idx) => {
                  if (idx > 0) metaLine.appendChild(document.createTextNode(' · '));
                  metaLine.appendChild(document.createTextNode(`${part.k}: `));
                  if (part.code) {
                    const c = document.createElement('code');
                    c.textContent = part.v;
                    metaLine.appendChild(c);
                  } else {
                    metaLine.appendChild(document.createTextNode(part.v));
                  }
                });

                tdReason.appendChild(metaLine);
              }

              const tdAct = document.createElement('td');
              tdAct.style.width = '10%';
        tdAct.setAttribute('data-label','Action');

              const actWrap = document.createElement('div');
              actWrap.className = 'sfais-actions';

              ['move', 'delete', 'ignore'].forEach((act) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'button';
                b.dataset.act = act;
                b.dataset.file = f;
                b.textContent = actionLabels[act] || act;

                b.addEventListener('click', (e) => {
                  e.preventDefault();

                  if (act === 'delete') {
                    const ok = window.confirm('Delete the ORIGINAL file from your site?\n\nThis is a dangerous action and cannot be undone.\n\nClick OK to delete, or Cancel to stop.');
                    if (!ok) return;
                  }

                  b.disabled = true;
                  const originalText = b.textContent;
                  b.textContent = '...';

                  const form = new URLSearchParams();
                  form.append('action', actionToAjax[act]);
                  form.append('file', f);
                  form.append('nonce', nonce);

                  fetch(ajaxurl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: form })
                    .then((r) => r.json())
                    .then((d) => {
                      if (d && d.success) {
                        tr.style.opacity = '0';
                        setTimeout(() => tr.remove(), 300);
                        loadQuarantine(true);
                        if (act === 'ignore') loadIgnored();   // 1.8.13
                      } else {
                        window.alert((d && d.data && d.data.message) ? d.data.message : 'Action failed.');
                      }
                    })
                    .catch(() => window.alert('Network error.'))
                    .finally(() => {
                      b.disabled = false;
                      b.textContent = originalText;
                    });
                });

                actWrap.appendChild(b);
              });

              tdAct.appendChild(actWrap);

              tr.appendChild(tdFile);
              tr.appendChild(tdAi);
              tr.appendChild(tdReason);
              tr.appendChild(tdAct);

              tbody.appendChild(tr);
            });

            table.appendChild(thead);
            table.appendChild(tbody);
            tableWrap.appendChild(table);
            outer.appendChild(tableWrap);
          } else {
            const p = document.createElement('p');
            p.style.fontSize = '12px';
            p.style.color = 'var(--mh-muted, #666)';
            p.style.marginTop = '8px';
            p.style.maxWidth = '640px';
            p.appendChild(document.createTextNode('All scanned PHP files, JavaScript under uploads and relevant '));
            const c = document.createElement('code');
            c.textContent = '.htaccess';
            p.appendChild(c);
            p.appendChild(document.createTextNode(' rules appear clean based on the current malware signatures and local heuristics.'));
            outer.appendChild(p);
          }

          aiDeepResults.appendChild(outer);

          initMetricHelp(aiDeepResults);

        };

        

    // ✅ Async scan runner (real progress + cancel)
    // NOTE: Some third-party plugins/themes incorrectly echo output during admin-ajax requests.
    // This parser tolerates "mixed" responses by extracting the first JSON object/array.
    const sfaisTryParseJson = (text) => {
      if (typeof text !== 'string') return null;
      const t = text.trim();
      if (!t) return null;

      try { return JSON.parse(t); } catch (e) {}

      const firstObj = t.indexOf('{');
      const lastObj  = t.lastIndexOf('}');
      if (firstObj !== -1 && lastObj !== -1 && lastObj > firstObj) {
        const slice = t.slice(firstObj, lastObj + 1);
        try { return JSON.parse(slice); } catch (e) {}
      }

      const firstArr = t.indexOf('[');
      const lastArr  = t.lastIndexOf(']');
      if (firstArr !== -1 && lastArr !== -1 && lastArr > firstArr) {
        const slice = t.slice(firstArr, lastArr + 1);
        try { return JSON.parse(slice); } catch (e) {}
      }

      return null;
    };

    const sfaisPostAjax = async (payload) => {
      const res = await fetch(ajaxurl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
        body: new URLSearchParams(payload)
      });

      const text = await res.text();
      const json = sfaisTryParseJson(text);
      if (!json) {
        throw new Error('Server returned an unexpected response.');
      }
      return json;
    };

    const sfaisActiveJobs = {};

    // Polling interval (ms). Higher values reduce admin-ajax load and prevent mobile throttling artifacts.
    const BASE_POLL = 900;


    const sfaisStartAsyncScan = async ({ kind, startAction, tickAction, cancelAction, recoverAction, buttonEl, boxEl, onDone }) => {
      if (!buttonEl || !boxEl) return;

      // Cancel any existing job of same kind (best effort).
      if (sfaisActiveJobs[kind] && sfaisActiveJobs[kind].job_id) {
        try {
          await sfaisPostAjax({
            action: cancelAction,
            nonce: nonce,
            job_id: sfaisActiveJobs[kind].job_id
          });
        } catch (e) {}
        if (sfaisActiveJobs[kind].timer) {
          clearTimeout(sfaisActiveJobs[kind].timer);
        }
      }

      const originalText = buttonEl.textContent;
      buttonEl.disabled = true;

      // Progress UI (only while scanning, no persistent UI changes).
      boxEl.innerHTML = '';
      const wrap = document.createElement('div');
      wrap.style.display = 'flex';
      wrap.style.alignItems = 'center';
      wrap.style.gap = '10px';
      wrap.style.marginTop = '8px';

      wrap.innerHTML = `
        <div style="flex:1;position:relative;height:16px;background:var(--mh-track, #e5e7eb);border-radius:10px;overflow:hidden;">
          <div class="sfais-progress-fill" style="height:100%;width:0%;background:var(--mh-grad, #00c0ff);transition:width 120ms linear;"></div>
          <div class="sfais-progress-pct" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;color:var(--mh-head, #111827);">0%</div>
        </div>
        <button type="button" class="button button-secondary sfais-progress-cancel">Cancel</button>
      `;
      boxEl.appendChild(wrap);

      const fillEl = wrap.querySelector('.sfais-progress-fill');
      const pctEl  = wrap.querySelector('.sfais-progress-pct');
      const cancelBtn = wrap.querySelector('.sfais-progress-cancel');

      let cancelled = false;
      let lastProgress = 0;
      let errorCount = 0;
      let recovered = false;
      const setPct = (p) => {
        const pct = Math.max(0, Math.min(100, parseInt(p, 10) || 0));
        lastProgress = pct;
        if (fillEl) fillEl.style.width = pct + '%';
        if (pctEl) pctEl.textContent = pct + '%';
      };

      let jobId = null;

      cancelBtn.addEventListener('click', async () => {
        if (!jobId) return;
        cancelled = true;
        cancelBtn.disabled = true;
        cancelBtn.textContent = 'Cancelling...';
        try {
          await sfaisPostAjax({ action: cancelAction, nonce: nonce, job_id: jobId });
        } catch (e) {}
      });

      try {
        const start = await sfaisPostAjax({ action: startAction, nonce: nonce });
        if (!start || !start.success || !start.data || !start.data.job_id) {
          throw new Error((start && start.data && start.data.message) ? start.data.message : 'Could not start scan.');
        }

        jobId = start.data.job_id;
        sfaisActiveJobs[kind] = { job_id: jobId, timer: null };

        const poll = async () => {
          if (cancelled) {
            // Keep polling briefly so backend can persist cancelled state.
          }
          try {
            const tick = await sfaisPostAjax({ action: tickAction, nonce: nonce, job_id: jobId });

            if (!tick || !tick.success || !tick.data) {
              throw new Error((tick && tick.data && tick.data.message) ? tick.data.message : 'Scan failed.');
            }

            const d = tick.data;
            setPct(d.progress);

            if (d.status === 'done') {
              const finish = (rep) => {
                buttonEl.disabled = false;
                buttonEl.textContent = originalText;
                delete sfaisActiveJobs[kind];

                if (typeof onDone === 'function' && rep) {
                  try { onDone(rep); } catch (e) {}
                } else {
                  boxEl.innerHTML = '<p class="sfais-muted">Scan completed.</p>';
                }
              };

              if (d.report) {
                finish(d.report);
                return;
              }

              if (recoverAction) {
                try {
                  const rep = await sfaisPostAjax({ action: recoverAction, nonce: nonce });
                  if (rep && rep.success && rep.data && rep.data.report) {
                    setPct(100);
                    finish(rep.data.report);
                    return;
                  }
                } catch (e) {}
              }

              finish(null);
              return;
            }

            if (d.status === 'cancelled') {
              buttonEl.disabled = false;
              buttonEl.textContent = originalText;
              boxEl.innerHTML = '<p class="sfais-muted">Scan cancelled.</p>';
              delete sfaisActiveJobs[kind];
              return;
            }

            // Continue polling
            sfaisActiveJobs[kind].timer = setTimeout(poll, BASE_POLL);
          } catch (e) {
            errorCount++;

            // Retry transient failures (common on sites with many plugins / noisy admin-ajax output).
            if (!cancelled && errorCount <= 4) {
              const delay = Math.min(2500, BASE_POLL + (300 * errorCount));
              if (sfaisActiveJobs[kind]) {
                sfaisActiveJobs[kind].timer = setTimeout(poll, delay);
              } else {
                setTimeout(poll, delay);
              }
              return;
            }

            // Recovery: if the scan likely finished, load the persisted report (prevents "refresh to see results").
            if (!recovered && recoverAction && lastProgress >= 95) {
              recovered = true;
              try {
                const rep = await sfaisPostAjax({ action: recoverAction, nonce: nonce });
                if (rep && rep.success && rep.data && rep.data.report) {
                  setPct(100);
                  buttonEl.disabled = false;
                  buttonEl.textContent = originalText;
                  delete sfaisActiveJobs[kind];
                  if (typeof onDone === 'function') {
                    try { onDone(rep.data.report); } catch (e2) {}
                  }
                  return;
                }
              } catch (e3) {}
            }

            buttonEl.disabled = false;
            buttonEl.textContent = originalText;
            boxEl.innerHTML = '<p class="sfais-muted">Network error.</p>';
            delete sfaisActiveJobs[kind];
          }
        };

        poll();
      } catch (e) {
        buttonEl.disabled = false;
        buttonEl.textContent = originalText;
        boxEl.innerHTML = '<p class="sfais-muted">Network error.</p>';
        delete sfaisActiveJobs[kind];
      }
    };

    const runCoreScanAsync = () => {
      const btn = document.getElementById('sfais-scan-core');
      const box = document.getElementById('sfais-core-results');
      sfaisStartAsyncScan({
        kind: 'core',
        startAction: 'sfais_scan_core_start',
        tickAction: 'sfais_scan_core_tick',
        cancelAction: 'sfais_scan_core_cancel',
        buttonEl: btn,
        boxEl: box,
        onDone: (report) => renderReport('sfais-core-results', report)
      });
    };
    // Bind buttons
    const scanCoreBtn = document.getElementById('sfais-scan-core');
    if (scanCoreBtn) {
      scanCoreBtn.addEventListener('click', (e) => { e.preventDefault(); runCoreScanAsync(); });
    }
    const scanContentBtn = document.getElementById('sfais-scan-uploads');
    if (scanContentBtn) {
      scanContentBtn.addEventListener('click', (e) => { e.preventDefault(); runScan('content'); });
    }

    // Restore last reports
    if (LAST_CORE && LAST_CORE.type === 'core') renderReport('sfais-core-results', LAST_CORE);
    if (LAST_CONTENT && LAST_CONTENT.type === 'content') renderReport('sfais-content-results', LAST_CONTENT);
})();
