(function(){
'use strict';

  // 1.8.13: the country-blocker code (country preview, labels, pills) is removed - no screen has those elements.

document.addEventListener('DOMContentLoaded', function() {
    const ajaxurl = window.ajaxurl || (window.sfaisIpBlockerData && window.sfaisIpBlockerData.ajaxurl) || '';
  const noticeBox = document.getElementById('sfais-ipb-notice');
  const htLockNonce = (window.sfaisIpBlockerData && window.sfaisIpBlockerData.htLockNonce) ? String(window.sfaisIpBlockerData.htLockNonce) : '';

  // 1.8.9: the result appears right under the button/row that was used (one result at a time); the top box is
  // only the fallback. Text only - never raw HTML.
  function showNotice(ok, msg, anchor) {
    const safe = (typeof msg === 'string') ? msg : '';
    document.querySelectorAll('.sfais-ipb-result').forEach(el => el.remove());
    if (noticeBox) noticeBox.textContent = '';

    const box = document.createElement('div');
    box.className = 'sfais-ipb-result';
    box.setAttribute('role', 'status');
    box.setAttribute('aria-live', 'polite');
    const wrap = document.createElement('div');
    wrap.className = ok ? 'notice notice-success inline' : 'notice notice-error inline';
    const p = document.createElement('p');
    p.textContent = safe;
    wrap.appendChild(p);
    box.appendChild(wrap);

    if (anchor instanceof Element && anchor.isConnected) {
      anchor.insertAdjacentElement('afterend', box);
    } else if (noticeBox) {
      noticeBox.appendChild(box);
    }
    return box;
  }

  // One POST helper for every IP Blocker action: always answers JSON or a clear reason.
  function post(body) {
    return fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: body })
      .then(r => r.text().then(t => {
        let j = null;
        try { j = JSON.parse(t); } catch (e) { j = null; }
        if (j && typeof j === 'object') return j;
        throw new Error(r.ok ? 'bad-answer' : ('http-' + r.status));
      }));
  }

  function failText(err) {
    const code = /^http-(\d+)$/.exec((err && err.message) || '');
    if (code) {
      return 'Your server answered with an error (HTTP ' + code[1] + ') instead of a result, so this change may not have been saved. Reload the page to see the current state.';
    }
    if (err && err.message === 'bad-answer') {
      return 'Your server sent an unexpected answer, so this change may not have been saved. Reload the page to see the current state.';
    }
    return 'Your browser could not reach the server. Check your internet connection and try again.';
  }

  function ensureEmptyState() {
    const list = document.getElementById('sfais-ip-list');
    if (!list) return;

    const cards = list.querySelectorAll('.sfais-ip-card');
    const emptyMsg = list.querySelector('.sfais-empty-ip-msg');

    if (cards.length > 0) {
      if (emptyMsg) emptyMsg.remove();
    } else {
      if (!emptyMsg) {
        list.insertAdjacentHTML('beforeend', '<p class="sfais-muted sfais-empty-ip-msg" style="margin:6px 0 0;">No IPs blocked yet.</p>');
      }
    }
  }

  function updateCount() {
    const list = document.getElementById('sfais-ip-list');
    const count = document.getElementById('sfais-ip-count');
    if (!list || !count) return;
    const rows = Array.from(list.querySelectorAll('.sfais-ip-card'));
    const visible = rows.filter(r => r.style.display !== 'none').length;
    count.textContent = visible + ' shown';
  }

  // Initial state (important for AJAX-added/removed items)
  ensureEmptyState();

  // -----------------------------
  // .htaccess toggle (already AJAX)
  // -----------------------------
  const htBtn = document.querySelector('.sfais-htaccess-toggle');
  const status = document.getElementById('sfais-htaccess-status');

  if (htBtn) {
    htBtn.addEventListener('click', function(e) {
      e.preventDefault();
      htBtn.disabled = true;
      const original = htBtn.textContent;
      htBtn.textContent = 'Processing...';

      const fdLock = new FormData();
      fdLock.append('action', 'sfais_toggle_htaccess_lock');
      fdLock.append('nonce', htLockNonce);
      post(fdLock)

.then(res => {
  // wp_send_json_success/wp_send_json_error returns { success: bool, data: {...} }
  if (res && res.success) {
    const data = res.data || {};
    const locked = !!data.locked;
    const perm = (typeof data.perm === 'string' && data.perm) ? data.perm : '';

    if (locked) {
      htBtn.textContent = '🔓 Unlock .htaccess';
      htBtn.style.background = '#607d8b';
      if (status) {
        status.textContent = 'Current: Locked (read-only)' + (perm ? ' — Perm: ' + perm : '');
        status.style.color = 'var(--mh-crit, #c62828)';
      }
    } else {
      htBtn.textContent = '🔒 Lock .htaccess';
      htBtn.style.background = '#43a047';
      if (status) {
        status.textContent = 'Current: Unlocked (writable)' + (perm ? ' — Perm: ' + perm : '');
        status.style.color = 'var(--mh-ok, #2e7d32)';
      }
    }

    // 1.8.9: the sentence above the list and the row statuses can change with the lock state.
    const summary = document.querySelector('#sfais-ip-summary span:last-child');
    if (summary && typeof data.summary === 'string' && data.summary) summary.textContent = data.summary;
    const ipList = document.getElementById('sfais-ip-list');
    if (ipList && typeof data.list_html === 'string' && data.list_html) {
      ipList.innerHTML = data.list_html;
      const q = document.getElementById('sfais-ip-search');
      if (q && q.value) q.dispatchEvent(new Event('input'));
      ensureEmptyState();
      updateCount();
    }
    showNotice(true, data.message || 'Done.', status || htBtn);
  } else {
    const msg = (res && res.data && res.data.message) ? res.data.message : ((res && res.message) ? res.message : 'Action failed.');
    showNotice(false, msg, status || htBtn);
    htBtn.textContent = original;
  }
})
      .catch(err => {
        showNotice(false, failText(err), status || htBtn);
        htBtn.textContent = original;
      })
      .finally(() => {
        htBtn.disabled = false;
      });
    });
  }

  // -----------------------------
  // Manual block IP (AJAX)
  // -----------------------------
  const blockForm = document.getElementById('sfais-block-ip-form');
  if (blockForm) {
    blockForm.addEventListener('submit', function(e) {
      e.preventDefault();

      const btn = blockForm.querySelector('button[name="sfais_block_ip"]');
      const original = btn ? btn.textContent : '';

      if (btn) { btn.disabled = true; btn.textContent = 'Working...'; }

      const fd = new FormData(blockForm);
      fd.append('action', 'sfais_block_ip_ajax');

      post(fd)
      .then(json => {
        if (!json || !json.success) {
          const msg = (json && json.data && json.data.message) ? json.data.message : 'Request failed.';
          showNotice(false, msg, blockForm);
          return;
        }

        const data = json.data || {};

        // Prepend/replace card in list (server returns correct chip state)
        const list = document.getElementById('sfais-ip-list');
        if (list && typeof data.card_html === 'string') {
          const ip = data.ip || '';
          if (ip) {
            const existing = list.querySelector(`.sfais-ip-card[data-ip="${CSS.escape(ip)}"]`);
            if (existing) {
              existing.outerHTML = data.card_html;
            } else {
              list.insertAdjacentHTML('afterbegin', data.card_html);
            }
          } else {
            list.insertAdjacentHTML('afterbegin', data.card_html);
          }

          // Clear input for UX
          const ipInput = blockForm.querySelector('input[name="sfais_ip"]');
          if (ipInput) ipInput.value = '';
        }

        ensureEmptyState();
        updateCount();
        showNotice(true, data.message || 'Done.', blockForm);
      })
      .catch(err => showNotice(false, failText(err), blockForm))
      .finally(() => {
        if (btn) { btn.disabled = false; btn.textContent = original; }
      });
    });
  }

  // -----------------------------
  // Unblock IP (AJAX, delegated)
  // -----------------------------
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (!form.classList.contains('sfais-ip-remove-form')) return;

    e.preventDefault();

    const btn = form.querySelector('button[type="submit"], button');
    if (btn) { btn.disabled = true; btn.classList.add('is-busy'); }

    const fd = new FormData(form);
    fd.append('action', 'sfais_unblock_ip_ajax');

    const rowOf = () => form.isConnected ? form.closest('.sfais-ip-card') : null;

    post(fd)
    .then(json => {
      if (!json || !json.success) {
        const msg = (json && json.data && json.data.message) ? json.data.message : 'Request failed.';
        showNotice(false, msg, rowOf());
        return;
      }

      const data = json.data || {};
      const ip = data.ip || '';
      const card = ip ? document.querySelector(`.sfais-ip-card[data-ip="${CSS.escape(ip)}"]`) : rowOf();

      if (data.still_blocked && card && typeof data.card_html === 'string') {
        // Must remain listed (e.g. the server rule is still in a locked .htaccess): result under the row.
        card.insertAdjacentHTML('afterend', data.card_html);
        const fresh = card.nextElementSibling;
        card.remove();
        // 1.8.13: still blocked = the unblock did not fully work, so it is not shown as a success.
        showNotice(false, data.message || 'Done.', fresh);
      } else if (card) {
        // The row is gone: the result takes its place for a few seconds.
        const box = showNotice(true, data.message || 'Done.', card);
        card.remove();
        setTimeout(() => { if (box && box.isConnected) box.remove(); ensureEmptyState(); }, 8000);
      } else {
        showNotice(true, data.message || 'Done.', null);
      }

      ensureEmptyState();
      updateCount();
    })
    .catch(err => showNotice(false, failText(err), rowOf()))
    .finally(() => {
      if (btn) { btn.disabled = false; btn.classList.remove('is-busy'); }
    });
  });

  // -----------------------------
  // Search (unchanged behavior)
  // -----------------------------
  const search=document.getElementById('sfais-ip-search');
  const list=document.getElementById('sfais-ip-list');
  const count=document.getElementById('sfais-ip-count');

  if(search && list){
    const rows = () => Array.from(list.querySelectorAll('.sfais-ip-card'));
    const updateCountLive=()=>{ const visible=rows().filter(r=>r.style.display!=='none').length; if(count) count.textContent=visible+' shown'; };

    search.addEventListener('input',()=>{
      const q = search.value.trim().toLowerCase();
      rows().forEach(r=>{
        const ip=(r.getAttribute('data-ip')||'').toLowerCase();
        r.style.display = ip.includes(q) ? '' : 'none';
      });
      updateCountLive();
    });

    updateCountLive();
  }
});
})();
