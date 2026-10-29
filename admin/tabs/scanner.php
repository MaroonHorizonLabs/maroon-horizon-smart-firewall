<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
call_user_func( static function () {
    $nonce = wp_create_nonce( 'sfais_scanner_nonce' );
    /**
     * Load both last saved reports (core + content)
     */
    $last_core_report = ( function_exists( 'mhsf_is_playground' ) && mhsf_is_playground() ? false : get_option( 'sfais_last_core_report' ) );
    // 1.8.17
    $last_content_report = get_option( 'sfais_last_content_report' );
    # Dynamic location hints (do not assume default wp-content paths).
    $mhsf_uploads_info = wp_upload_dir( null, false );
    $mhsf_uploads_url_path = '';
    if ( is_array( $mhsf_uploads_info ) && !empty( $mhsf_uploads_info['baseurl'] ) ) {
        $mhsf_uploads_url_path = (string) wp_parse_url( (string) $mhsf_uploads_info['baseurl'], PHP_URL_PATH );
    }
    $mhsf_uploads_url_path = ( $mhsf_uploads_url_path ? trailingslashit( $mhsf_uploads_url_path ) : '' );
    $mhsf_uploads_code = ( $mhsf_uploads_url_path ? '<code>' . esc_html( $mhsf_uploads_url_path ) . '</code>' : '<code>' . esc_html__( 'uploads directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    $mhsf_themes_uri = ( function_exists( 'get_theme_root_uri' ) ? (string) get_theme_root_uri() : (string) content_url( '/themes' ) );
    $mhsf_themes_url_path = ( $mhsf_themes_uri ? (string) wp_parse_url( $mhsf_themes_uri, PHP_URL_PATH ) : '' );
    $mhsf_themes_url_path = ( $mhsf_themes_url_path ? trailingslashit( $mhsf_themes_url_path ) : '' );
    $mhsf_themes_code = ( $mhsf_themes_url_path ? '<code>' . esc_html( $mhsf_themes_url_path ) . '</code>' : '<code>' . esc_html__( 'themes directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    $mhsf_plugins_uri = (string) plugins_url( '/' );
    $mhsf_plugins_url_path = ( $mhsf_plugins_uri ? (string) wp_parse_url( $mhsf_plugins_uri, PHP_URL_PATH ) : '' );
    $mhsf_plugins_url_path = ( $mhsf_plugins_url_path ? trailingslashit( $mhsf_plugins_url_path ) : '' );
    $mhsf_plugins_code = ( $mhsf_plugins_url_path ? '<code>' . esc_html( $mhsf_plugins_url_path ) . '</code>' : '<code>' . esc_html__( 'plugins directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    $mhsf_content_uri = (string) content_url( '/' );
    $mhsf_content_url_path = ( $mhsf_content_uri ? (string) wp_parse_url( $mhsf_content_uri, PHP_URL_PATH ) : '' );
    $mhsf_content_url_path = ( $mhsf_content_url_path ? trailingslashit( $mhsf_content_url_path ) : '' );
    $mhsf_content_code = ( $mhsf_content_url_path ? '<code>' . esc_html( $mhsf_content_url_path ) . '</code>' : '<code>' . esc_html__( 'content directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    ?>
<!-- ✅ Scoped container -->
<div id="sfais-tab-scanner">

  <h2>Malware Scanner</h2>
  <p class="sfais-kicker" style="max-width:700px;color:var(--mh-muted,#555);margin-top:6px;">
    Detect suspicious code, modified core files, and potentially malicious files within your WordPress installation.
  </p>

  <!-- 1.8.6: calm, confident guidance (was a yellow warning) - facts: files are only changed by the user's own click -->
  <div class="sfais-safety-note sfais-safety-note--info" role="note" aria-label="<?php 
    echo esc_attr__( 'How the scanner works', 'maroon-horizon-smart-firewall' );
    ?>">
    <span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>
    <div class="sfais-safety-note__body">
      <strong><?php 
    echo esc_html__( 'You stay in control of every file.', 'maroon-horizon-smart-firewall' );
    ?></strong>
      <div class="sfais-safety-note__text">
        <?php 
    // 1.8.13: Quarantine wording matches what it does (private folder, renamed, restore refuses to overwrite a newer file)
    echo esc_html__( 'The scanner only reports what it finds - it never changes a file by itself. For each result you decide: Ignore keeps the file as it is, Quarantine moves it into the plugin\'s private folder (stored encoded, so it can\'t run or be opened) and you can restore it, and Delete removes it for good.', 'maroon-horizon-smart-firewall' );
    ?>
      </div>
      <div class="sfais-safety-note__text">
        <?php 
    echo esc_html__( 'Some results can be normal parts of WordPress, a plugin or a theme. If you are not sure about a file, choose Ignore and look into it first. As with any change to a live site, a recent backup (files and database) is good practice before you delete anything.', 'maroon-horizon-smart-firewall' );
    ?>
      </div>
    </div>
  </div>

  <?php 
    /* 1.8.15 (Vlad): the two cards side by side while empty; a pair with results (a table) goes full width, one below the other */
    ?>
  <div class="mhsf-pair">
  <!-- 🧩 Quarantine Management (always visible, empty state supported) -->
  <div class="sfais-card" id="sfais-quarantine-card">
    <h3 style="display:flex;align-items:center;gap:8px;">
      <span class="dashicons dashicons-shield" style="color:var(--mh-crit,#c62828);font-size:20px;"></span>
      Quarantine Management
    </h3>
    <p>View quarantined files detected by the malware scanner. You can restore or permanently delete them below. <span class="mhsf-muted"><?php 
    esc_html_e( 'Quarantined files are deleted automatically after 30 days.', 'maroon-horizon-smart-firewall' );
    ?></span></p>
    <div id="sfais-quarantine-results" style="margin-top:10px;">
      <div class="notice notice-info" style="margin:0;">
        <p style="margin:8px 0;">
          No files are currently quarantined.
          <span style="color:var(--mh-muted,#555);">Quarantined items appear here after you move a file to quarantine from scan results.</span>
        </p>
      </div>
    </div>
  </div>

  <!-- 1.8.13: Ignored files (FREE + PRO) - filled by sfais-scanner.js, Un-ignore per file -->
  <div class="sfais-card" id="sfais-ignored-card">
    <h3 style="display:flex;align-items:center;gap:8px;">
      <span class="dashicons dashicons-hidden" style="color:var(--mh-muted,#555);font-size:20px;"></span>
      <span><?php 
    echo esc_html__( 'Ignored files', 'maroon-horizon-smart-firewall' );
    ?> (<span id="sfais-ignored-count">0</span>)</span>
    </h3>
    <p><?php 
    echo esc_html__( 'Ignored files are skipped by the scans while they stay unchanged. Un-ignore a file to have it checked again.', 'maroon-horizon-smart-firewall' );
    ?></p>
    <div id="sfais-ignored-results" style="margin-top:10px;"></div>
  </div>
  </div>

  <div class="mhsf-pair">
  <!-- CORE FILE INTEGRITY (FREE + PRO) -->
  <div class="sfais-card" id="sfais-core-scan-card">
    <h3 style="display:flex;align-items:center;gap:8px;">
      <span class="dashicons dashicons-search" style="color:#1976d2;font-size:20px;"></span>
      Quick File Integrity Check
    </h3>
    <?php 
    if ( function_exists( 'mhsf_is_playground' ) && mhsf_is_playground() ) {
        /* 1.8.17: Live Preview - one sentence, no count, no list */
        ?>
    <p class="sfais-safety-note sfais-safety-note--info"><?php 
        esc_html_e( 'This check is off in the WordPress Playground preview, because Playground runs a shortened copy of WordPress - on a real site it compares every core file with the official WordPress.org files.', 'maroon-horizon-smart-firewall' );
        ?></p>
    <?php 
    } else {
        ?>
    <p>
      Validates WordPress core files (wp-admin/, wp-includes/, and key root core files) against official WordPress.org checksums for your current WordPress version and locale, and reports modified or missing core files.
      <strong>Note: this check does not validate files under <?php 
        echo wp_kses( $mhsf_content_code, array(
            'code' => array(),
        ) );
        ?> (themes, plugins and uploads), including default/bundled themes. Use “Scan Uploads and Themes” for your content directory.</strong>
    </p>
    <button class="button button-primary" id="sfais-scan-core">🧩 Run Scan</button>
    <?php 
    }
    ?>
    <div id="sfais-core-results" style="margin-top:10px;"></div>
  </div>

  <!-- FREE SCANNER: CONTENT -->
  <div class="sfais-card" id="sfais-content-scan-card">
    <h3 style="display:flex;align-items:center;gap:8px;">
      <span class="dashicons dashicons-admin-site-alt3" style="color:#43a047;font-size:20px;"></span>
      Scan Uploads and Themes
    </h3>
    <p>
      Scans PHP files inside <?php 
    echo wp_kses( $mhsf_uploads_code, array(
        'code' => array(),
    ) );
    ?> and <?php 
    echo wp_kses( $mhsf_themes_code, array(
        'code' => array(),
    ) );
    ?> and flags code
      that matches common high-risk functions (for example <code>eval()</code>, <code>base64_decode()</code>,
      <code>gzinflate()</code>, <code>shell_exec()</code>, etc.). This <strong>scan uses only local pattern detection</strong>
      and <strong>does not download external signatures</strong>.
    </p>
    <?php 
    /* 1.8.13: was "Deep Scan" - the same name as the PRO Deep Scan */
    ?>
    <button class="button button-primary" id="sfais-scan-uploads">Scan Uploads &amp; Themes</button>
    <div id="sfais-content-results" style="margin-top:10px;"></div>
  </div>
  </div>

  <!-- PRO: Deep Scan with malware signatures (1.8.13: was "Real-Time Malware Detection" - nothing runs in real time) -->
  <?php 
    $mhsf_pro_runtime_rendered = false;
    ?>

  <?php 
    ?>

  <?php 
    if ( !$mhsf_pro_runtime_rendered ) {
        ?>

    <?php 
        // Best-effort upgrade URL (Freemius).
        // Prefer the internal pricing page *without* forcing a billing cycle (avoids edge cases in some setups).
        $sfais_upgrade_url = '';
        if ( function_exists( 'mhsf_fs' ) ) {
            $fs = mhsf_fs();
            if ( is_object( $fs ) ) {
                $sfais_upgrade_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-pricing' );
            }
        }
        $sfais_has_upgrade = !empty( $sfais_upgrade_url );
        ?>

    <!-- ✅ FREE: Deep Scan with malware signatures (PRO-style preview, locked) -->
    <div class="sfais-card sfais-pro-card" id="sfais-ai-model-card-free">

      <div class="sfais-tf-head">
        <h3 style="display:flex;align-items:center;gap:8px;margin:0;">
          <span class="dashicons dashicons-chart-pie" style="color:#9c27b0;font-size:20px;"></span>
          Deep Scan with malware signatures
        </h3>

        <div class="sfais-badges">
            <span class="sfais-pilltag sfais-pilltag-pro">PRO Preview</span>
            <span class="sfais-pilltag sfais-pilltag-lock">Locked in FREE</span>
        </div>

      </div>

      <p style="margin-top:8px;">
        Uses the daily Maroon Horizon malware signatures (reviewed by Maroon Horizon AI) to check PHP files in <?php 
        echo wp_kses( $mhsf_content_code, array(
            'code' => array(),
        ) );
        ?>.
        Suspicious files get a risk score from the signature matches, together with the classic pattern checks.
      </p>

      <div class="notice notice-warning" style="margin:10px 0 0;">
        <p style="margin:8px 0;">
          🔒 Available in PRO Version. This is a preview of the PRO interface. Upgrade to enable syncing, deep scans and reports.
        </p>
      </div>

      <div class="sfais-summary" style="margin-top:8px;opacity:.92;">
        <div class="metric info">
          Status:
          <span style="color:var(--mh-muted,#555);font-weight:700;">Locked</span>
        </div>
        <div class="metric info">
          Signatures:
          <span style="color:var(--mh-muted,#555);font-weight:700;">—</span>
        </div>
        <div class="metric info">
          Last sync:
          <span style="color:var(--mh-muted,#555);font-weight:700;">—</span>
        </div>
        <div class="metric info">
          Last deep scan:
          <span style="color:var(--mh-muted,#555);font-weight:700;">—</span>
        </div>
      </div>

      <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;opacity:.92;">
        <button class="button button-primary" disabled>🔒 Sync Malware Signatures Now</button>
        <span style="font-size:12px;color:var(--mh-muted,#555);">
          The malware signature list is used when you run the Deep Scan.
        </span>
      </div>

      <div style="margin-top:8px;font-size:12px;color:var(--mh-muted,#555);opacity:.92;">
        Upgrade to PRO to sync the malware signatures.
      </div>

      <hr style="margin:14px 0;border:none;border-top:1px solid #eee;">

      <h4 style="margin-top:0;display:flex;align-items:center;gap:6px;">
        <span class="dashicons dashicons-admin-site" style="color:#673ab7;"></span>
        Deep Scan
      </h4>
      <p style="margin-top:4px;font-size:13px;color:var(--mh-muted,#555);">
        Scans <?php 
        echo wp_kses( $mhsf_uploads_code, array(
            'code' => array(),
        ) );
        ?>, <?php 
        echo wp_kses( $mhsf_themes_code, array(
            'code' => array(),
        ) );
        ?>, and <?php 
        echo wp_kses( $mhsf_plugins_code, array(
            'code' => array(),
        ) );
        ?> (with smart exclusions for large cache directories),
        combining local dangerous-function detection with the Maroon Horizon malware signatures (reviewed daily by Maroon Horizon AI).
        It also checks <code>.htaccess</code> files in those locations and JavaScript files in <?php 
        echo wp_kses( $mhsf_uploads_code, array(
            'code' => array(),
        ) );
        ?> for
        known malicious patterns. Results are shown in a dedicated report with risk scores and extra metadata
        (hash, category, per-file scan time).
      </p>

      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;opacity:.92;">
        <button class="button button-primary" disabled>🔒 Run Deep Scan</button>
        <span style="font-size:12px;color:var(--mh-muted,#555);">
          Suspicious files are listed below with recommended actions.
        </span>
      </div>

      <!-- Locked preview results area -->
      <div style="margin-top:10px;">
        <div class="sfais-card" style="margin-top:10px;opacity:.92;">
          <h4 style="margin:0 0 4px;">Deep Scan Results</h4>

          <div class="notice notice-info" style="margin:8px 0 0;">
            <p style="margin:8px 0;">
              Run the Deep Scan in PRO to generate a report here.
            </p>
          </div>

          <div class="sfais-summary" style="margin-top:10px;">
            <div class="metric info">
              <div class="sfais-metric-label">Total scanned (scan engine)</div>
              <strong>—</strong>
            </div>
            <div class="metric info">
              <div class="sfais-metric-label">Files in this report</div>
              <strong>—</strong>
            </div>
            <div class="metric info">
              <div class="sfais-metric-label">Other scanned files</div>
              <strong>—</strong>
            </div>
          </div>

          <div class="sfais-summary" style="margin-top:4px;">
            <div class="metric crit">
              <div class="sfais-metric-label">Suspicious</div>
              <strong>—</strong>
            </div>
            <div class="metric ok">
              <div class="sfais-metric-label">Clean</div>
              <strong>—</strong>
            </div>
            <div class="metric info">
              <div class="sfais-metric-label">Ignored</div>
              <strong>—</strong>
            </div>
            <div class="metric warn">
              <div class="sfais-metric-label">Unreadable</div>
              <strong>—</strong>
            </div>
          </div>

          <div style="font-size:12px;color:var(--mh-muted,#555);margin:6px 0 0;">
            <strong>Scan time:</strong> — · <strong>Duration:</strong> —
          </div>
        </div>
      </div>

      <hr style="margin:14px 0;border:none;border-top:1px solid #eee;">

      <h4 style="margin-top:0;display:flex;align-items:center;gap:6px;">
        <span class="dashicons dashicons-schedule" style="color:#00796b;"></span>
        Automatic Deep Scan & Email Reports
      </h4>
      <p style="margin-top:4px;font-size:13px;color:var(--mh-muted,#555);max-width:640px;">
        Put the Deep Scan on autopilot. Choose how often the scan engine should rescan your plugins,
        themes and uploads and optionally receive email reports with suspicious files and risk scores.
        The first report is sent right after you save these settings; after that, emails are only sent when
        the scan finds something suspicious.
      </p>

      <div style="margin-top:4px;">
        <span class="sfais-pill sfais-pill-off">Automatic Deep Scan: Locked</span>
      </div>

      <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:6px;opacity:.85;">
        <label style="display:flex;align-items:center;gap:6px;">
          <input type="checkbox" disabled />
          <span>Enable automatic Deep Scan</span>
        </label>
        <label style="display:flex;align-items:center;gap:6px;">
          <span>Run every</span>
          <select disabled>
            <option>5 hours</option>
            <option>12 hours</option>
            <option>24 hours</option>
            <option>48 hours</option>
          </select>
        </label>
      </div>

      <div style="margin-top:8px;max-width:420px;opacity:.85;">
        <label style="display:block;font-size:12px;color:var(--mh-muted,#555);margin-bottom:2px;">
          Email address for deep scan reports (optional):
        </label>
        <input type="email"
               class="regular-text"
               style="width:100%;max-width:100%;"
               disabled
               placeholder="Available in PRO"
        />
      </div>

      <p style="margin-top:6px;font-size:11px;color:var(--mh-muted,#555);max-width:640px;">
        Upgrade to PRO to enable automatic scans and optional email reports.
      </p>

      <div style="margin-top:8px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;opacity:.92;">
        <button class="button" disabled>🔒 Save Deep Scan Settings</button>
        <span style="font-size:12px;color:var(--mh-muted,#555);">Locked in FREE version.</span>
      </div>

      <!-- ✅ Match Threat Feed card CTA pattern -->
      <div class="sfais-tf-cta">
        <?php 
        if ( $sfais_has_upgrade ) {
            ?>
          <a class="button button-primary" href="<?php 
            echo esc_url( $sfais_upgrade_url );
            ?>">
            Upgrade to PRO for the Deep Scan with malware signatures
          </a>
        <?php 
        } else {
            ?>
          <button class="button button-primary" disabled title="Upgrade link is not available in this build.">
            Upgrade to PRO for the Deep Scan with malware signatures
          </button>
        <?php 
        }
        ?>

        <span class="sfais-cta-sub">
          PRO adds the daily malware signatures, the Deep Scan and automatic e-mail reports.
        </span>
      </div>

    </div>

  <?php 
    }
    ?>
</div>

<?php 
} );