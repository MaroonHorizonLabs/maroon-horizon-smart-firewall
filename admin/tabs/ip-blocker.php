<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
call_user_func( static function () {
    // 1.8.13: the one global instance (a second "new SFAIS_Functions()" registered every hook again), as the Dashboard does.
    $functions = ( isset( $GLOBALS['sfais_functions'] ) && $GLOBALS['sfais_functions'] instanceof SFAIS_Functions ? $GLOBALS['sfais_functions'] : new SFAIS_Functions() );
    $server = $functions->detect_server_type();
    $ht = ABSPATH . '.htaccess';
    $entitled = false;
    $threat_feed_pro_file = '';
    $mhsf_threat_feed_runtime = false;
    /* -------------------------------
       MANUAL IP BLOCK / UNBLOCK
       (Keep POST handlers as fallback if JS is disabled)
    --------------------------------*/
    if ( isset( $_POST['sfais_block_ip'] ) && !empty( $_POST['sfais_ip'] ) ) {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Unauthorized action.', 'maroon-horizon-smart-firewall' ) );
        }
        $nonce = ( isset( $_POST['sfais_block_ip_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_block_ip_nonce'] ) ) : '' );
        if ( empty( $nonce ) || !wp_verify_nonce( $nonce, 'sfais_block_ip_action' ) ) {
            wp_die( esc_html__( 'Security check failed. Please refresh the page and try again.', 'maroon-horizon-smart-firewall' ) );
        }
        $ip_raw = sanitize_text_field( wp_unslash( $_POST['sfais_ip'] ) );
        $result = $functions->block_ip( $ip_raw );
        $msg = ( is_array( $result ) && isset( $result['message'] ) ? (string) $result['message'] : '' );
        if ( $msg === '' ) {
            $msg = esc_html__( 'Request completed.', 'maroon-horizon-smart-firewall' );
        }
        $notice_class = ( is_array( $result ) && isset( $result['status'] ) && !$result['status'] ? 'notice-error' : 'notice-success' );
        echo '<div class="notice ' . esc_attr( $notice_class ) . ' is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
        echo "\n";
    }
    if ( isset( $_POST['sfais_unblock_ip'] ) && !empty( $_POST['sfais_unblock_ip'] ) ) {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Unauthorized action.', 'maroon-horizon-smart-firewall' ) );
        }
        $nonce = ( isset( $_POST['sfais_unblock_ip_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_unblock_ip_nonce'] ) ) : '' );
        if ( empty( $nonce ) || !wp_verify_nonce( $nonce, 'sfais_unblock_ip_action' ) ) {
            wp_die( esc_html__( 'Security check failed. Please refresh and try again.', 'maroon-horizon-smart-firewall' ) );
        }
        $ip_to_unblock = sanitize_text_field( wp_unslash( $_POST['sfais_unblock_ip'] ) );
        $result = $functions->unblock_ip( $ip_to_unblock );
        $msg = ( is_array( $result ) && isset( $result['message'] ) ? (string) $result['message'] : '' );
        if ( $msg === '' ) {
            $msg = esc_html__( 'Request completed.', 'maroon-horizon-smart-firewall' );
        }
        $notice_class = ( is_array( $result ) && isset( $result['status'] ) && !$result['status'] ? 'notice-error' : 'notice-success' );
        echo '<div class="notice ' . esc_attr( $notice_class ) . ' is-dismissible"><p>' . esc_html( $msg ) . '</p></div>';
        echo "\n";
    }
    /* -------------------------------
       LOAD DATA
    --------------------------------*/
    // 1.8.12: a server rule written by an older version gets its Cloudflare line (once, checked write).
    $functions->upgrade_htaccess_block();
    $blocked_items = array_unique( (array) $functions->get_blocked_ips(), SORT_REGULAR );
    $ht_lock_nonce = wp_create_nonce( 'sfais_htaccess_lock_action' );
    ?>


<h2>IP Blocker</h2>
<p class="sfais-kicker" style="max-width:700px;color:var(--mh-muted,#555);margin-top:6px;">
    <?php 
    esc_html_e( 'Manage blocked IPs and protect critical files.', 'maroon-horizon-smart-firewall' );
    ?>
</p>

<!-- Fallback notice box (results normally appear right under the button that was used) -->
<div id="sfais-ipb-notice" style="margin:10px 0 0;"></div>

<!-- MANUAL BLOCKED IP OVERVIEW (Manual + Overview together) -->
<div class="sfais-card" id="sfais-ip-overview-card">
  <h3 style="display:flex;align-items:center;gap:8px;">
    <span class="dashicons dashicons-visibility" style="color:#1976d2;font-size:20px;"></span>
    Manually Blocked IPs Overview
  </h3>

  <!-- Manual IP Blocking (moved inside overview) -->
  <div style="margin-top:10px;">
    <h4 style="display:flex;align-items:center;gap:8px;margin:0 0 6px;">
      <span class="dashicons dashicons-admin-network" style="color:#ff9800;font-size:18px;"></span>
      Manual IP Blocking
    </h4>

    <form method="post" action="" id="sfais-block-ip-form" style="margin-top:8px;">
      <?php 
    $sfais_nonce_html = wp_nonce_field(
        'sfais_block_ip_action',
        'sfais_block_ip_nonce',
        true,
        false
    );
    echo wp_kses( $sfais_nonce_html, array(
        'input' => array(
            'type'  => true,
            'name'  => true,
            'value' => true,
            'id'    => true,
        ),
    ) );
    ?>
      <input type="hidden" name="sfais_active_tab" value="ip-blocker">
      <input type="text" name="sfais_ip" placeholder="Enter IP address" style="width:240px; margin-right:10px;">
      <button class="button button-primary" name="sfais_block_ip" type="submit">➕ Block IP</button>
    </form>

    <?php 
    // LiteSpeed is normalized to "apache" by detect_server_type().
    if ( $server === 'apache' && file_exists( $ht ) ) {
        // Robust state detection (ownership/ACLs can make SFAIS_FS::is_writable() misleading).
        $state = ( method_exists( $functions, 'get_htaccess_state' ) ? $functions->get_htaccess_state() : null );
        $writable = SFAIS_FS::is_writable( $ht );
        if ( is_array( $state ) && isset( $state['writable'] ) ) {
            $writable = (bool) $state['writable'];
            $perm = ( isset( $state['perm'] ) && $state['perm'] ? $state['perm'] : '' );
        } else {
            $perm = '';
        }
        $is_locked = !$writable;
        // Button semantics:
        // - "Lock" (secure action) should look positive/primary.
        // - "Unlock" should look neutral.
        $btn_label = ( $is_locked ? '🔓 Unlock .htaccess' : '🔒 Lock .htaccess' );
        $btn_color = ( $is_locked ? '#607d8b' : '#43a047' );
        echo '<div class="sfais-htaccess-box">';
        echo '<h4><span class="dashicons dashicons-lock"></span> .htaccess File Protection</h4>';
        echo '<button class="button sfais-htaccess-toggle" style="background:' . esc_attr( $btn_color ) . ';color:#fff;">' . esc_html( $btn_label ) . '</button>';
        $status_txt = 'Current: ' . (( $is_locked ? 'Locked (read-only)' : 'Unlocked (writable)' ));
        if ( $perm !== '' ) {
            $status_txt .= ' — Perm: ' . esc_html( $perm );
        }
        echo '<p id="sfais-htaccess-status" style="margin-top:8px;font-weight:600;color:' . esc_attr( ( $is_locked ? '#d32f2f' : '#2e7d32' ) ) . ';">' . esc_html( $status_txt ) . '</p>';
        // 1.8.13: what the lock really does (server rules keep working while locked; the lock only stops changes).
        echo '<p class="sfais-note">' . esc_html__( 'Locking makes .htaccess read-only, so plugins can\'t change it by accident. Existing server rules keep working while .htaccess is locked; unlock it only to add new server rules (Unblock works while it is locked).', 'maroon-horizon-smart-firewall' ) . '</p>';
        echo '</div>';
    }
    ?>
  </div>

  <p class="sfais-ip-summary" id="sfais-ip-summary"><span class="dashicons dashicons-info-outline" aria-hidden="true"></span><span><?php 
    echo esc_html( $functions->ip_protection_summary() );
    ?></span></p>

  <div class="sfais-ip-toolbar" style="margin-top:14px;">
    <input type="text" id="sfais-ip-search" placeholder="Search IPs…" aria-label="Search blocked IPs">
    <span id="sfais-ip-count" class="sfais-muted"></span>
  </div>

  <div id="sfais-ip-list">
  <?php 
    if ( !empty( $blocked_items ) ) {
        // 1.8.9: the same row builder as the AJAX answers (one .htaccess parser for the whole plugin).
        // 1.8.13: both lists read once; the status of each row comes from both.
        $sfais_ht_ips = (array) $functions->get_htaccess_ips();
        $sfais_db_ips = (array) $functions->get_db_ips();
        foreach ( $blocked_items as $ip ) {
            echo wp_kses( $functions->ip_card_html( (string) $ip, $sfais_ht_ips, $sfais_db_ips ), array(
                'div'    => array(
                    'class'   => true,
                    'data-ip' => true,
                ),
                'code'   => array(
                    'class' => true,
                ),
                'span'   => array(
                    'class'       => true,
                    'aria-hidden' => true,
                ),
                'form'   => array(
                    'method' => true,
                    'class'  => true,
                ),
                'input'  => array(
                    'type'  => true,
                    'name'  => true,
                    'value' => true,
                ),
                'button' => array(
                    'class'      => true,
                    'type'       => true,
                    'aria-label' => true,
                ),
            ) );
        }
    } else {
        echo '<p class="sfais-muted sfais-empty-ip-msg" style="margin:6px 0 0;">' . esc_html__( 'No IPs blocked yet.', 'maroon-horizon-smart-firewall' ) . '</p>';
    }
    ?>
  </div>
</div>

<!-- THREAT FEED UI -->

<?php 
    if ( !$mhsf_threat_feed_runtime ) {
        ?>

<?php 
        // Best-effort upgrade URL (Freemius).
        // Prefer the internal pricing page without forcing a billing cycle.
        $sfais_upgrade_url = '';
        if ( function_exists( 'mhsf_fs' ) ) {
            $fs = mhsf_fs();
            if ( is_object( $fs ) ) {
                $sfais_upgrade_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-pricing' );
            }
        }
        $sfais_has_upgrade = !empty( $sfais_upgrade_url );
        ?>
<div class="sfais-card sfais-pro-card" id="sfais-threat-feed-card-free">
  <div class="sfais-tf-head">
    <h3 style="display:flex;align-items:center;gap:8px;margin:0;">
      <span class="dashicons dashicons-chart-area" style="color:#0288d1;font-size:20px;"></span>
      Threat Feed
    </h3>

    <div class="sfais-badges">
      <span class="sfais-badge sfais-badge-pro">PRO Preview</span>
      <span class="sfais-badge sfais-badge-lock">Locked in FREE</span>
    </div>
  </div>

  <p style="max-width:680px;margin-top:8px;">
    Automatically block high-risk IP ranges detected worldwide - attackers, botnets, scanners and spam networks.
    Updated every day; works on every server.
  </p>

  <div class="sfais-tf-panel">
    <ul class="sfais-tf-meta" aria-label="Threat feed preview status">
      <li>
        <strong>Feed status:</strong>
        <span style="color:var(--mh-muted,#555);font-weight:700;">Preview (PRO only)</span>
      </li>

      <li>
        <strong>Last sync:</strong>
        <span class="sfais-skel sfais-skel-w-140" aria-hidden="true"></span>
        <span class="sfais-preview-muted" style="margin-left:6px;">Example</span>
      </li>

      <li>
        <strong>Feed file date:</strong>
        <span class="sfais-skel sfais-skel-w-220" aria-hidden="true"></span>
        <span class="sfais-preview-muted" style="margin-left:6px;">Example (UTC)</span>
      </li>

      <li>
        <strong>Firewall blocking:</strong>
        <span class="sfais-skel sfais-skel-w-320" aria-hidden="true"></span>
        <div class="sfais-preview-muted" style="margin-top:4px;">
          Typical coverage (PRO): <strong>90,000+</strong> high-risk networks • about <strong>15 million</strong> IPv4 addresses (changes daily)
        </div>
      </li>
    </ul>

    <p class="sfais-preview-muted" style="margin:6px 0 0;">
      <strong>Fast on every server:</strong> the whole feed is checked with a quick lookup - a fraction of a millisecond per visitor, no slow-server limits.
    </p>

    <div style="margin-top:10px;">
      <div class="sfais-autosync-pill sfais-autosync-off">
        <span class="sfais-dot"></span>
        <span>Automatic daily sync is available in PRO.</span>
      </div>
      <div class="sfais-preview-muted" style="margin-top:4px;">
        Next scheduled sync: <span class="sfais-skel sfais-skel-w-140" aria-hidden="true"></span>
      </div>
    </div>

    <div class="sfais-tf-controls" aria-label="Threat feed controls (PRO only)">
      <span class="sfais-tip-wrap" title="Available in PRO">
        <button class="button button-primary" disabled>🔁 Sync Threat Feed Now</button>
      </span>

      <span class="sfais-tip-wrap" title="Available in PRO">
        <button class="button" disabled>🗑 Remove all synced IPs</button>
      </span>

      <span class="sfais-tip-wrap" title="Available in PRO">
        <button class="button" disabled>⏹ Disable daily sync (threat feed + malware signatures)</button>
      </span>
    </div>

    <div class="sfais-tf-cta">
      <?php 
        if ( $sfais_has_upgrade ) {
            ?>
        <a class="button button-primary" href="<?php 
            echo esc_url( $sfais_upgrade_url );
            ?>">
          Upgrade to PRO to Enable Threat Feed
        </a>
      <?php 
        } else {
            ?>
        <button class="button button-primary" disabled title="Upgrade link is not available in this build.">
          Upgrade to PRO to Enable Threat Feed
        </button>
      <?php 
        }
        ?>

      <span class="sfais-cta-sub">
        PRO downloads the digitally signed feed every day and blocks these addresses in the firewall.
      </span>
    </div>

    <div class="sfais-preview-warning">
      <strong>Preview only:</strong> Threat Feed blocking is not active on this site in the FREE version.
    </div>
  </div>

  <p class="sfais-note" style="margin-top:8px;font-size:12px;">
    The feed is curated daily by Maroon Horizon AI, digitally signed and built on Maroon Horizon's own servers.
    Only licensed MH Smart Firewall PRO can use it.
  </p>
</div>

<?php 
    } else {
        ?>

<?php 
        require $threat_feed_pro_file;
        ?>

<?php 
    }
    ?>

<!-- JS: search + ALL IP Blocker actions via AJAX -->
<?php 
} );