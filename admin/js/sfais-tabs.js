document.addEventListener('DOMContentLoaded', () => {
  const container = document.querySelector('.sfais-wrap');
  if (!container) return;

  const tabs = container.querySelectorAll('.sfais-tabs a');
  const contents = container.querySelectorAll('.sfais-tab-content');
  if (!tabs.length || !contents.length) return;

  const defaultTab = container.getAttribute('data-default-tab') || 'dashboard';
  let currentTab = defaultTab;

  // i18n helper (falls back to English if wp.i18n isn't loaded)
  const __sfais = (text) => {
    try {
      return (window.wp && wp.i18n && typeof wp.i18n.__ === 'function')
        ? wp.i18n.__(String(text || ''), 'maroon-horizon-smart-firewall')
        : String(text || '');
    } catch (e) {
      return String(text || '');
    }
  };


  function activateTab(id) {
    currentTab = id;

    tabs.forEach(t => t.classList.remove('active'));
    contents.forEach(c => c.classList.remove('active'));

    tabs.forEach(t => {
      const tabId =
        t.dataset.tab ||
        (t.getAttribute('href') ? t.getAttribute('href').substring(1) : '');
      if (tabId === id) {
        t.classList.add('active');
      }
    });

    const section = document.getElementById(id);
    if (section) section.classList.add('active');
  }

  activateTab(defaultTab);

  tabs.forEach(tab => {
    tab.addEventListener('click', e => {
      e.preventDefault();
      const target =
        tab.dataset.tab ||
        (tab.getAttribute('href') ? tab.getAttribute('href').substring(1) : 'dashboard');
      activateTab(target);
    });
  });

  // 1.8.8: the header line shows the SAME score as the Dashboard. The header is rendered before the Dashboard runs its fresh
  // check (it read the previous stored score), so it takes the fresh values on load and on every live update.
  function syncHeaderScore() {
    const head = document.getElementById('mhsf-header-score');
    const scoreEl = document.getElementById('sfais-rating-score');
    const labelEl = document.getElementById('sfais-rating-label');
    if (!head || !scoreEl) return;
    const score = (scoreEl.textContent || '').trim();
    const label = labelEl ? (labelEl.textContent || '').replace(/^\s*·\s*/, '').trim() : '';
    if (score === '') return;
    head.textContent = __sfais('Security score') + ' ' + score + '/100' + (label ? ' · ' + label : '');
  }
  syncHeaderScore();

  function updateRatingUI(payload) {
    if (!payload || !payload.rating) return;

    const gradeEl = document.getElementById('sfais-rating-grade');
    const scoreEl = document.getElementById('sfais-rating-score');
    const labelEl = document.getElementById('sfais-rating-label');
    const summaryEl = document.getElementById('sfais-rating-summary');
    const lastCheckedEl = document.getElementById('sfais-last-checked');

    const r = payload.rating;

    if (gradeEl && typeof r.grade === 'string') {
      gradeEl.className = gradeEl.className
        .split(' ')
        .filter(c => !c.startsWith('grade-'))
        .join(' ')
        .trim();

      gradeEl.classList.add(`grade-${r.grade_class || 'na'}`);
      gradeEl.textContent = r.grade;
    }

    if (scoreEl && typeof r.score === 'number') {
      scoreEl.textContent = String(r.score);
      const arc = document.getElementById('mhsf-score-arc');   // 1.8.7 score ring
      if (arc) arc.setAttribute('stroke-dasharray', (Math.max(0, Math.min(100, r.score)) / 100 * 389.6).toFixed(1) + ' 390');
    }

    if (labelEl && typeof r.label === 'string') {
      labelEl.textContent = `· ${r.label}`;
    }
    syncHeaderScore();

    if (summaryEl) {
      const s = (typeof r.summary === 'string') ? r.summary : '';
      if (s) {
        summaryEl.style.display = '';
        summaryEl.textContent = s;
      } else {
        summaryEl.style.display = 'none';
        summaryEl.textContent = '';
      }
    }

    if (lastCheckedEl && typeof payload.last_checked_text === 'string') {
      lastCheckedEl.textContent = payload.last_checked_text;
    }
  }

  // 1.8.13: all tabs are on one page - after a change on another tab the server sends the Dashboard freshly rendered
  // (score ring, check rows, recommended fixes, "x of 10 patches on", activity), so nothing waits for a page reload.
  // The HTML is the plugin's own escaped server output for this admin; listeners are delegated on the container.
  function refreshDashboard(payload, keepFocusFlag) {
    const dash = document.getElementById('dashboard');
    if (dash && payload && typeof payload.dashboard_html === 'string' && payload.dashboard_html !== '') {
      dash.innerHTML = payload.dashboard_html;
      if (keepFocusFlag) {
        const again = dash.querySelector(`form[data-flag="${keepFocusFlag}"] button[type="submit"]`);
        if (again) again.focus();
      }
    }
    updateRatingUI(payload);
  }

  // Track which submit button was clicked (needed for patch apply/revert)
  container.addEventListener('click', e => {
    const btn = e.target;
    if (!(btn instanceof HTMLElement)) return;

    const form = btn.closest('form');
    if (!form) return;

    if (form.classList.contains('sfais-patch-form')) {
      const actionVal = btn.getAttribute('value') || '';
      form.dataset.clickedAction = actionVal; // "apply" or "revert"
    }
  });

  function showPatchesNotice(type, msg, form) {
    // 1.8.6: the result goes right under the clicked patch's button (one result at a time); the top box is the fallback.
    let box = null;
    if (form instanceof HTMLFormElement) {
      document.querySelectorAll('.sfais-patch-result').forEach(el => { if (el.previousElementSibling !== form) el.remove(); });
      box = form.nextElementSibling;
      if (!box || !box.classList.contains('sfais-patch-result')) {
        box = document.createElement('div');
        box.className = 'sfais-patch-result';
        box.style.margin = '10px 0 0';
        box.setAttribute('role', 'status');
        box.setAttribute('aria-live', 'polite');
        form.insertAdjacentElement('afterend', box);
      }
      const top = document.getElementById('sfais-patches-notice');
      if (top) top.textContent = '';
    } else {
      box = document.getElementById('sfais-patches-notice');
    }
    if (!box) return;

    const safeMsg = (typeof msg === 'string') ? msg : '';
    const cls = (type === 'success')
      ? 'notice notice-success inline'
      : 'notice notice-error inline';

    // Avoid innerHTML to prevent stored/reflected XSS via dynamic error strings.
    box.textContent = '';

    const notice = document.createElement('div');
    notice.className = cls;

    const p = document.createElement('p');
    // 1.8.6: server messages may contain <code>..</code> - render ONLY that tag (as text nodes, no innerHTML), strip any other tag.
    safeMsg.split(/(<code>[\s\S]*?<\/code>)/i).forEach(part => {
      const m = /^<code>([\s\S]*?)<\/code>$/i.exec(part);
      if (m) {
        const c = document.createElement('code');
        c.textContent = m[1].replace(/<[^>]*>/g, '');
        p.appendChild(c);
      } else if (part) {
        // 1.8.17: <br> stays a line break ('core files.<br>Changed: 1' showed as 'core files.Changed: 1')
        part.split(/<br\s*\/?>/i).forEach((line, i) => {
          if (i > 0) p.appendChild(document.createElement('br'));
          if (line) p.appendChild(document.createTextNode(line.replace(/<[^>]*>/g, '')));
        });
      }
    });

    notice.appendChild(p);
    box.appendChild(notice);
    if (form instanceof HTMLFormElement && typeof box.scrollIntoView === 'function') {
      box.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  container.addEventListener('submit', e => {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    // ----------------------------
    // AJAX: Dashboard manual flags
    // ----------------------------
    if (form.classList.contains('sfais-manual-flag-form')) {
      e.preventDefault();

      const flag = form.getAttribute('data-flag') || '';
      if (!flag) return;

      if (typeof ajaxurl === 'undefined') {
        console.error('ajaxurl is not defined.');
        return;
      }

      const btn = form.querySelector('button[type="submit"]');
      const originalText = btn ? btn.textContent : '';

      if (btn) {
        btn.disabled = true;
        btn.textContent = __sfais('Working...');
      }

      const fd = new FormData(form);
      fd.append('action', 'sfais_toggle_manual_flag');
      fd.append('flag', flag);

      fetch(ajaxurl, {
        method: 'POST',
        credentials: 'same-origin',
        body: fd
      })
        .then(r => r.json())
        .then(json => {
          if (!json || !json.success) {
            const msg = (json && json.data && json.data.message) ? json.data.message : __sfais('Request failed.');
            alert(msg);
            return;
          }

          const data = json.data || {};

          if (btn && typeof data.next_label === 'string') {
            btn.textContent = data.next_label;
          }

          if (data.post_key && typeof data.next_action === 'string') {
            const hidden = form.querySelector(`input[name="${data.post_key}"]`);
            if (hidden) hidden.value = data.next_action;
          }

          const tr = form.closest('tr');
          if (tr) {
            const statusCell = tr.querySelector('.sfais-status-cell');
            const valueCell = tr.querySelector('.sfais-value-cell code');
            const msgSpan = tr.querySelector('.sfais-msg-cell .sfais-msg-text');

            if (statusCell && typeof data.badge_html === 'string') {
              statusCell.innerHTML = data.badge_html;
            }
            if (valueCell && typeof data.value === 'string') {
              valueCell.textContent = data.value;
            }
            if (msgSpan && typeof data.message === 'string') {
              msgSpan.textContent = data.message;
            }
          }

          refreshDashboard(data, flag);
        })
        .catch(err => {
          console.error(err);
          alert(__sfais('Network error. Please try again.'));
        })
        .finally(() => {
          if (btn) btn.disabled = false;
          if (btn && btn.textContent === __sfais('Working...')) btn.textContent = originalText;
        });

      return;
    }

    // ----------------------------
    // AJAX: Security Patches (no refresh)
    // ----------------------------
    if (form.classList.contains('sfais-patch-form')) {
      e.preventDefault();

      if (typeof ajaxurl === 'undefined') {
        console.error('ajaxurl is not defined.');
        return;
      }

      const patch = form.getAttribute('data-patch') || (form.querySelector('input[name="sfais_patch"]')?.value || '');
      const clickedAction = form.dataset.clickedAction || (form.querySelector('button[name="sfais_patch_action"]')?.value || '');
      const nonceField = form.querySelector('input[name="sfais_patch_nonce"]');

      if (!patch || !clickedAction || !nonceField) {
        showPatchesNotice('error', __sfais('Patch request is missing required data.'));
        return;
      }

      const btn = form.querySelector('button[name="sfais_patch_action"]');
      const statusEl = form.querySelector('[data-status]');
      const spinner = form.querySelector('[data-spinner]');

      const originalBtnText = btn ? btn.textContent : '';
      const originalBtnClass = btn ? btn.className : '';

      if (btn) btn.disabled = true;
      if (spinner) spinner.style.display = '';

      const fd = new FormData(form);
      fd.append('action', 'sfais_toggle_patch');
      fd.append('patch', patch);
      fd.append('action_type', clickedAction);

      fetch(ajaxurl, {
        method: 'POST',
        credentials: 'same-origin',
        body: fd
      })
        .then(r => r.json())
        .then(json => {
          if (!json) {
            showPatchesNotice('error', __sfais('Request failed.'), form);
            return;
          }

          // WP sends { success: true/false, data: {...} }
          const ok = !!json.success;
          const data = json.data || {};
          const msg = (typeof data.message === 'string') ? data.message : (ok ? __sfais('Done.') : __sfais('Request failed.'));

          showPatchesNotice(ok ? 'success' : 'error', msg, form);
          refreshDashboard(data);
          // 1.8.17: "Apply again" worked (or the patch was switched off) - the "writable again" state is gone
          if (ok) {
            form.querySelectorAll('.mhsf-reapply').forEach(el => el.remove());
            if (statusEl) statusEl.classList.remove('is-drift');
          }

          // Update UI if server provided it
          const ui = data.ui || null;
          if (ui && btn && statusEl) {
            if (typeof ui.button_label === 'string') btn.textContent = ui.button_label;
            if (typeof ui.button_class === 'string') btn.className = ui.button_class;

            // Next click should send the opposite action
            if (typeof ui.next_action === 'string') {
              btn.value = ui.next_action;
              form.dataset.clickedAction = ui.next_action;
            }

            if (typeof ui.status_text === 'string') statusEl.textContent = ui.status_text;
            if (typeof ui.status_color === 'string') statusEl.style.color = ui.status_color;
            // 1.8.7: patches are drawn as switches - keep the class and say the new state
            if (form.closest('.mhsf-patch-card')) {
              const on = (ui.next_action === 'revert');
              btn.classList.add('mhsf-switch');
              btn.classList.remove('button', 'button-primary', 'button-secondary');
              btn.setAttribute('aria-checked', on ? 'true' : 'false');
              statusEl.classList.toggle('is-on', on);
              statusEl.style.color = '';
            }
            // 1.8.13: a Pro patch removed without a licence can't be switched on again here - the card locks
            if (ui.locked && ui.next_action === 'apply') {
              const card = form.closest('.mhsf-patch-card');
              const note = card ? card.querySelector('.mhsf-lapsed-note') : null;
              if (note) note.remove();
              btn.remove();
            }
          }
        })
        .catch(err => {
          console.error(err);
          showPatchesNotice('error', __sfais('Network error. Please try again.'), form);
          if (btn) {
            btn.textContent = originalBtnText;
            btn.className = originalBtnClass;
          }
        })
        .finally(() => {
          if (spinner) spinner.style.display = 'none';
          if (btn) btn.disabled = false;
        });

      return;
    }

    // Default behavior: preserve current tab on regular form submits
    let hidden = form.querySelector('input[name="sfais_tab"]');
    if (!hidden) {
      hidden = document.createElement('input');
      hidden.type = 'hidden';
      hidden.name = 'sfais_tab';
      form.appendChild(hidden);
    }
    hidden.value = currentTab;
  });
});
