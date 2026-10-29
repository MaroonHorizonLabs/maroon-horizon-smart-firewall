<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
call_user_func( static function () {
    // Handle manual confirmation toggles (Backup & User Security).
    // These are simple admin-side flags that only affect dashboard scoring/status.
    if ( !empty( $_POST['sfais_backup_action'] ) ) {
        if ( isset( $_POST['sfais_backup_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['sfais_backup_nonce'] ) ), 'sfais_backup_flags' ) ) {
            if ( current_user_can( 'manage_options' ) ) {
                $action = sanitize_text_field( wp_unslash( $_POST['sfais_backup_action'] ) );
                switch ( $action ) {
                    case 'backup_found_set':
                        update_option( 'sfais_backup_manual_found', 1 );
                        break;
                    case 'backup_found_clear':
                        delete_option( 'sfais_backup_manual_found' );
                        break;
                    case 'backup_age_set':
                        update_option( 'sfais_backup_manual_age_ok', 1 );
                        break;
                    case 'backup_age_clear':
                        delete_option( 'sfais_backup_manual_age_ok' );
                        break;
                }
            }
        }
    }
    if ( !empty( $_POST['sfais_usersec_action'] ) ) {
        if ( isset( $_POST['sfais_usersec_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['sfais_usersec_nonce'] ) ), 'sfais_usersec_flags' ) ) {
            if ( current_user_can( 'manage_options' ) ) {
                $action = sanitize_text_field( wp_unslash( $_POST['sfais_usersec_action'] ) );
                switch ( $action ) {
                    case 'strong_passwords_set':
                        update_option( 'sfais_manual_strong_passwords', 1 );
                        break;
                    case 'strong_passwords_clear':
                        delete_option( 'sfais_manual_strong_passwords' );
                        break;
                    case 'two_factor_set':
                        update_option( 'sfais_manual_2fa_enabled', 1 );
                        break;
                    case 'two_factor_clear':
                        delete_option( 'sfais_manual_2fa_enabled' );
                        break;
                }
            }
        }
    }
    $functions = ( isset( $GLOBALS['sfais_functions'] ) && $GLOBALS['sfais_functions'] instanceof SFAIS_Functions ? $GLOBALS['sfais_functions'] : new SFAIS_Functions() );
    $quick = $functions->run_quick_check();
    // Normalise structure
    $sections = ( isset( $quick['sections'] ) && is_array( $quick['sections'] ) ? $quick['sections'] : [] );
    $rating = ( isset( $quick['rating'] ) && is_array( $quick['rating'] ) ? $quick['rating'] : [
        'grade'   => 'N/A',
        'score'   => 0,
        'label'   => 'No data',
        'summary' => 'Not enough information to calculate a rating yet.',
    ] );
    $timestamp = ( !empty( $quick['timestamp'] ) ? (int) $quick['timestamp'] : (int) get_option( 'sfais_last_quick_check', 0 ) );
    $last_checked_text = ( $timestamp ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp ) : __( 'Not run yet', 'maroon-horizon-smart-firewall' ) );
    // Manual confirmation flags (used for dashboard buttons).
    $manual_backup_found = (bool) get_option( 'sfais_backup_manual_found', false );
    $manual_backup_age_ok = (bool) get_option( 'sfais_backup_manual_age_ok', false );
    $manual_strong_passwords = (bool) get_option( 'sfais_manual_strong_passwords', false );
    $manual_2fa_enabled = (bool) get_option( 'sfais_manual_2fa_enabled', false );
    ?>

<?php 
    // 1.8.7 overview (Vlad: A+B redesign) - only data the plugin already has: last check, scans, syncs, patches, blocks.
    $mhsf_dt = static function ( $local_mysql ) {
        $ts = ( $local_mysql ? strtotime( (string) $local_mysql ) : 0 );
        return ( $ts ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) : '' );
    };
    $mhsf_utc_ts = static function ( $iso ) {
        $ts = ( $iso ? strtotime( (string) $iso ) : 0 );
        return ( $ts ? (int) $ts : 0 );
    };
    $mhsf_cloud = ( class_exists( 'MHSF_Pro_Cloud' ) ? MHSF_Pro_Cloud::get_instance() : null );
    $mhsf_feed = ( $mhsf_cloud ? (array) $mhsf_cloud->get_meta( 'threat-feed' ) : array() );
    $mhsf_sigs = ( $mhsf_cloud ? (array) $mhsf_cloud->get_meta( 'malware-signatures' ) : array() );
    $mhsf_licensed = defined( 'SFAIS_IS_PRO' ) && SFAIS_IS_PRO;
    // 1.8.13: licensed and synced are two different things
    $mhsf_pro = $mhsf_licensed && !empty( $mhsf_feed['last_sync'] );
    // 1.8.13: counts only while the data file is really there (a missing file blocks nothing)
    $mhsf_next = ( $mhsf_cloud && function_exists( 'wp_next_scheduled' ) ? wp_next_scheduled( MHSF_Pro_Cloud::CRON_HOOK ) : false );
    // 1.8.13: "Healthy / Up to date" only when the last update worked and is recent (MHSF_Pro_Cloud::health())
    $mhsf_health = static function ( $asset ) use($mhsf_cloud) {
        return ( $mhsf_cloud && method_exists( $mhsf_cloud, 'health' ) ? (array) $mhsf_cloud->health( $asset ) : array(
            'state' => 'healthy',
        ) );
    };
    $mhsf_feed_h = ( $mhsf_pro ? $mhsf_health( 'threat-feed' ) : array() );
    $mhsf_sigs_h = ( $mhsf_pro ? $mhsf_health( 'malware-signatures' ) : array() );
    $mhsf_when = static function ( $ts ) {
        return ( $ts ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $ts ) : '' );
    };
    $mhsf_core = ( function_exists( 'mhsf_is_playground' ) && mhsf_is_playground() ? false : get_option( 'sfais_last_core_report' ) );
    // 1.8.17: no core comparison in Playground
    $mhsf_cont = get_option( 'sfais_last_content_report' );
    $mhsf_patch_opts = array(
        'sfais_patch_versioninfo',
        'sfais_patch_dirlisting',
        'sfais_patch_xmlrpc',
        'sfais_patch_filemods',
        'sfais_patch_permissions'
    );
    $mhsf_patches_on = 0;
    foreach ( $mhsf_patch_opts as $mhsf_o ) {
        $mhsf_patches_on += ( get_option( $mhsf_o ) ? 1 : 0 );
    }
    $mhsf_blocked = 0;
    if ( class_exists( 'SFAIS_IP_Manager' ) ) {
        $mhsf_ipm = new SFAIS_IP_Manager();
        $mhsf_blocked = ( method_exists( $mhsf_ipm, 'get_blocked_ips' ) ? count( (array) $mhsf_ipm->get_blocked_ips() ) : 0 );
    }
    // what to improve: warnings / critical items of the check below (first 4)
    $mhsf_fixes = array();
    foreach ( $sections as $mhsf_s ) {
        foreach ( ( isset( $mhsf_s['items'] ) ? (array) $mhsf_s['items'] : array() ) as $mhsf_i ) {
            if ( isset( $mhsf_i['status'] ) && in_array( $mhsf_i['status'], array('warn', 'crit'), true ) ) {
                $mhsf_fixes[] = $mhsf_i;
            }
        }
    }
    usort( $mhsf_fixes, static function ( $a, $b ) {
        return ('crit' === $b['status']) <=> ('crit' === $a['status']);
    } );
    // 1.8.13: critical first
    $mhsf_fix_count = count( $mhsf_fixes );
    $mhsf_patchable = array(
        'Hide WordPress Version Info',
        'Directory Browsing',
        'wp-config.php Writable',
        'File Editing in Admin'
    );
    $mhsf_fix_by_patch = false;
    foreach ( array_slice( $mhsf_fixes, 0, 4 ) as $mhsf_i ) {
        $mhsf_fix_by_patch = $mhsf_fix_by_patch || in_array( (string) ($mhsf_i['label'] ?? ''), $mhsf_patchable, true );
    }
    // recent activity, newest first (times the plugin already stores)
    // 1.8.15: Recent activity = the activity log (newest 200 events, mhsf-activity.php) - it showed only the last check + 2 scans + syncs
    $mhsf_acts = array();
    foreach ( ( function_exists( 'mhsf_activity_get' ) ? mhsf_activity_get() : array() ) as $mhsf_e ) {
        if ( !empty( $mhsf_e['t'] ) && isset( $mhsf_e['text'] ) ) {
            $mhsf_acts[] = array((int) $mhsf_e['t'], (string) $mhsf_e['text']);
        }
    }
    $grade = strtoupper( $rating['grade'] ?? 'N/A' );
    $score = ( isset( $rating['score'] ) ? (int) $rating['score'] : 0 );
    $label = $rating['label'] ?? 'No data';
    $summary = $rating['summary'] ?? '';
    $grade_class = preg_replace( '/[^a-z]/', '', strtolower( $grade ) );
    $mhsf_arc = round( max( 0, min( 100, $score ) ) / 100 * 389.6, 1 );
    $mhsf_ip_url = admin_url( 'admin.php?page=sfais-ip-blocker' );
    $mhsf_sc_url = admin_url( 'admin.php?page=sfais-scanner' );
    $mhsf_pa_url = admin_url( 'admin.php?page=sfais-patches' );
    ?>

<div class="mhsf-overview">
  <section class="sfais-card sfais-quick-card" aria-label="<?php 
    esc_attr_e( 'Security score', 'maroon-horizon-smart-firewall' );
    ?>">
    <div class="mhsf-score">
      <svg width="116" height="116" viewBox="0 0 150 150" role="img" aria-label="<?php 
    echo esc_attr( sprintf( 
        /* translators: %d: score */
        __( 'Security score %d of 100', 'maroon-horizon-smart-firewall' ),
        $score
     ) );
    ?>">
        <defs><linearGradient id="mhsf-score-grad" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#5fb4ff"></stop><stop offset=".5" stop-color="#c58be0"></stop><stop offset="1" stop-color="#ff6f8e"></stop></linearGradient></defs>
        <circle cx="75" cy="75" r="62" fill="none" stroke="var(--mh-track)" stroke-width="13"></circle>
        <circle id="mhsf-score-arc" cx="75" cy="75" r="62" fill="none" stroke="url(#mhsf-score-grad)" stroke-width="13" stroke-linecap="round" stroke-dasharray="<?php 
    echo esc_attr( $mhsf_arc );
    ?> 390" transform="rotate(-90 75 75)"></circle>
        <text x="75" y="86" text-anchor="middle" font-size="42" font-weight="800" fill="var(--mh-head)" style="font-family: inherit;"><tspan id="sfais-rating-score"><?php 
    echo esc_html( $score );
    ?></tspan></text>
      </svg>
      <div>
        <p id="sfais-status-line" class="sfais-status-line mhsf-muted" style="margin:0 0 4px;font-size:12px;"><?php 
    esc_html_e( 'Status: Checked', 'maroon-horizon-smart-firewall' );
    ?> <span class="status good">✅</span></p><?php 
    // 1.8.13: the check above already ran when the page opened - no pretend "Running automatic scan..."
    ?>
        <strong style="font-size:16px;color:var(--mh-head);display:flex;align-items:center;gap:8px;">
          <span id="sfais-rating-grade" class="sfais-rating-badge grade-<?php 
    echo esc_attr( $grade_class );
    ?>" style="width:28px;height:28px;font-size:14px;line-height:28px;margin:0;"><?php 
    echo esc_html( $grade );
    ?></span>
          <span><?php 
    esc_html_e( 'Security score', 'maroon-horizon-smart-firewall' );
    ?> <span id="sfais-rating-label" class="sfais-rating-label">· <?php 
    echo esc_html( $label );
    ?></span></span>
        </strong>
        <div id="sfais-rating-summary" class="sfais-rating-summary mhsf-muted" style="margin:6px 0 10px;font-size:13px;<?php 
    echo ( $summary ? '' : 'display:none;' );
    ?>"><?php 
    echo esc_html( $summary );
    ?></div>
        <div class="mhsf-muted" style="font-size:12.5px;margin-bottom:10px;"><?php 
    esc_html_e( 'Last checked:', 'maroon-horizon-smart-firewall' );
    ?> <strong id="sfais-last-checked"><?php 
    echo esc_html( $last_checked_text );
    ?></strong></div>
        <form method="post" action="">
          <input type="hidden" name="sfais_active_tab" value="dashboard">
          <button class="button" name="sfais_run_quick_check"><?php 
    esc_html_e( 'Run check again', 'maroon-horizon-smart-firewall' );
    ?></button>
        </form>
      </div>
    </div>
  </section>

  <section class="sfais-card" aria-label="<?php 
    esc_attr_e( 'Threat Feed', 'maroon-horizon-smart-firewall' );
    ?>">
    <div class="mhsf-lbl"><?php 
    esc_html_e( 'Threat Feed', 'maroon-horizon-smart-firewall' );
    ?></div>
    <?php 
    if ( $mhsf_pro ) {
        ?>
      <?php 
        if ( false === ($mhsf_feed_h['active'] ?? true) ) {
            ?>
      <div class="mhsf-big"><?php 
            esc_html_e( 'Not active', 'maroon-horizon-smart-firewall' );
            ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
            esc_html_e( 'No Threat Feed data is loaded, so the feed blocks nothing right now.', 'maroon-horizon-smart-firewall' );
            ?></div>
      <?php 
        } else {
            ?>
      <div class="mhsf-big"><?php 
            echo esc_html( sprintf( 
                /* translators: %s: networks */
                __( '%s networks', 'maroon-horizon-smart-firewall' ),
                number_format_i18n( (int) ($mhsf_feed['counts']['networks'] ?? 0) )
             ) );
            ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
            echo esc_html( sprintf( 
                /* translators: %s: addresses */
                __( '%s IPv4 addresses blocked', 'maroon-horizon-smart-firewall' ),
                number_format_i18n( (int) ($mhsf_feed['counts']['ips_v4'] ?? 0) )
             ) );
            ?></div>
      <?php 
        }
        ?>
      <?php 
        if ( in_array( $mhsf_feed_h['state'] ?? '', array('stale', 'error'), true ) ) {
            ?>
      <div class="mhsf-warnline"><?php 
            echo esc_html( (string) ($mhsf_feed_h['message'] ?? '') );
            ?></div>
      <?php 
        } else {
            ?>
      <div class="mhsf-okline"><?php 
            echo esc_html( sprintf( 
                /* translators: 1: last sync, 2: next sync */
                __( 'Healthy · synced %1$s%2$s', 'maroon-horizon-smart-firewall' ),
                $mhsf_when( $mhsf_utc_ts( $mhsf_feed['last_sync'] ) ),
                ( $mhsf_next ? ' · ' . sprintf( 
                    /* translators: %s: time */
                    __( 'next %s', 'maroon-horizon-smart-firewall' ),
                    $mhsf_when( (int) $mhsf_next )
                 ) : '' )
             ) );
            ?></div>
      <?php 
        }
        ?>
    <?php 
    } elseif ( $mhsf_licensed ) {
        ?>
      <div class="mhsf-big"><?php 
        esc_html_e( 'PRO active', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
        esc_html_e( 'The first Threat Feed download has not run yet.', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-warnline"><a href="<?php 
        echo esc_url( $mhsf_ip_url );
        ?>"><?php 
        esc_html_e( 'Sync it now in the IP Blocker', 'maroon-horizon-smart-firewall' );
        ?></a></div>
    <?php 
    } else {
        ?>
      <div class="mhsf-big"><?php 
        esc_html_e( '90,000+ networks', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
        esc_html_e( 'about 15 million high-risk IPv4 addresses, updated daily', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-warnline"><a href="<?php 
        echo esc_url( $mhsf_ip_url );
        ?>"><?php 
        esc_html_e( 'Available in PRO - see the preview', 'maroon-horizon-smart-firewall' );
        ?></a></div>
    <?php 
    }
    ?>
  </section>

  <section class="sfais-card" aria-label="<?php 
    esc_attr_e( 'Malware signatures', 'maroon-horizon-smart-firewall' );
    ?>">
    <div class="mhsf-lbl"><?php 
    esc_html_e( 'Malware signatures', 'maroon-horizon-smart-firewall' );
    ?></div>
    <?php 
    if ( $mhsf_pro && !empty( $mhsf_sigs['last_sync'] ) ) {
        ?>
      <?php 
        if ( false === ($mhsf_sigs_h['active'] ?? true) ) {
            ?>
      <div class="mhsf-big"><?php 
            esc_html_e( 'Not loaded', 'maroon-horizon-smart-firewall' );
            ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
            esc_html_e( 'The signature file is missing - the Deep Scan uses only its local checks until the next sync.', 'maroon-horizon-smart-firewall' );
            ?></div>
      <?php 
        } else {
            ?>
      <div class="mhsf-big"><?php 
            echo esc_html( number_format_i18n( (int) ($mhsf_sigs['counts']['signatures'] ?? 0) ) );
            ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
            esc_html_e( 'reviewed daily by Maroon Horizon AI', 'maroon-horizon-smart-firewall' );
            ?></div>
      <?php 
        }
        ?>
      <?php 
        if ( in_array( $mhsf_sigs_h['state'] ?? '', array('stale', 'error'), true ) ) {
            ?>
      <div class="mhsf-warnline"><?php 
            echo esc_html( (string) ($mhsf_sigs_h['message'] ?? '') );
            ?></div>
      <?php 
        } else {
            ?>
      <div class="mhsf-okline"><?php 
            echo esc_html( sprintf( 
                /* translators: %s: date and time */
                __( 'Up to date · %s', 'maroon-horizon-smart-firewall' ),
                $mhsf_when( $mhsf_utc_ts( $mhsf_sigs['last_sync'] ) )
             ) );
            ?></div>
      <?php 
        }
        ?>
    <?php 
    } elseif ( $mhsf_licensed ) {
        ?>
      <div class="mhsf-big"><?php 
        esc_html_e( 'PRO active', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
        esc_html_e( 'The malware signatures arrive with the first daily sync.', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-warnline"><a href="<?php 
        echo esc_url( $mhsf_sc_url );
        ?>"><?php 
        esc_html_e( 'Open the scanner', 'maroon-horizon-smart-firewall' );
        ?></a></div>
    <?php 
    } else {
        ?>
      <div class="mhsf-big"><?php 
        esc_html_e( 'Local checks', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-muted" style="font-size:13.5px;"><?php 
        esc_html_e( 'The free scanner checks high-risk PHP functions on this server. PRO adds 11,000+ daily signatures.', 'maroon-horizon-smart-firewall' );
        ?></div>
      <div class="mhsf-warnline"><a href="<?php 
        echo esc_url( $mhsf_sc_url );
        ?>"><?php 
        esc_html_e( 'Open the scanner', 'maroon-horizon-smart-firewall' );
        ?></a></div>
    <?php 
    }
    ?>
  </section>
</div>

<div class="mhsf-shields">
  <div class="sfais-card mhsf-shield"><span class="mhsf-ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="3" y="5" width="18" height="14" rx="2"></rect><path d="M3 10h18M8 15h2M12 15h4"></path></svg></span><div><strong><?php 
    esc_html_e( 'Firewall', 'maroon-horizon-smart-firewall' );
    ?></strong><span class="mhsf-muted"><?php 
    echo esc_html( ( defined( 'MHSF_LOGIN_GUARD_OFF' ) && MHSF_LOGIN_GUARD_OFF ? __( 'Running · Login Guard off', 'maroon-horizon-smart-firewall' ) : sprintf( 
        /* translators: %d: blocked */
        _n(
            'Running · Login Guard on · %d blocked IP',
            'Running · Login Guard on · %d blocked IPs',
            $mhsf_blocked,
            'maroon-horizon-smart-firewall'
        ),
        $mhsf_blocked
     ) ) );
    ?></span></div></div>
  <div class="sfais-card mhsf-shield"><span class="mhsf-ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="6"></circle><path d="M20 20l-4.5-4.5"></path></svg></span><div><strong><?php 
    esc_html_e( 'Scanner', 'maroon-horizon-smart-firewall' );
    ?></strong><span class="mhsf-muted"><?php 
    // 1.8.13: core files AND the uploads/themes scan - "Clean" ignored suspicious uploads files before
    $mhsf_sus = ( is_array( $mhsf_cont ) && isset( $mhsf_cont['summary'] ) ? (int) (( (array) $mhsf_cont['summary'] )['suspicious'] ?? 0) : 0 );
    if ( is_array( $mhsf_core ) && isset( $mhsf_core['summary'] ) ) {
        $mhsf_cs = (array) $mhsf_core['summary'];
        $mhsf_ci = (int) ($mhsf_cs['modified'] ?? 0) + (int) ($mhsf_cs['missing'] ?? 0);
        if ( $mhsf_ci || $mhsf_sus ) {
            $mhsf_parts = array();
            if ( $mhsf_ci ) {
                $mhsf_parts[] = sprintf( 
                    /* translators: %d: issues */
                    _n(
                        '%d core file needs a look',
                        '%d core files need a look',
                        $mhsf_ci,
                        'maroon-horizon-smart-firewall'
                    ),
                    $mhsf_ci
                 );
            }
            if ( $mhsf_sus ) {
                $mhsf_parts[] = sprintf( 
                    /* translators: %d: files */
                    _n(
                        '%d suspicious file in uploads & themes',
                        '%d suspicious files in uploads & themes',
                        $mhsf_sus,
                        'maroon-horizon-smart-firewall'
                    ),
                    $mhsf_sus
                 );
            }
            echo esc_html( implode( ' · ', $mhsf_parts ) );
        } else {
            echo esc_html( sprintf( 
                /* translators: %s: files */
                __( 'Clean · %s core files checked', 'maroon-horizon-smart-firewall' ),
                number_format_i18n( (int) ($mhsf_cs['clean'] ?? 0) )
             ) );
        }
    } elseif ( $mhsf_sus ) {
        echo esc_html( sprintf( 
            /* translators: %d: files */
            _n(
                '%d suspicious file in uploads & themes',
                '%d suspicious files in uploads & themes',
                $mhsf_sus,
                'maroon-horizon-smart-firewall'
            ),
            $mhsf_sus
         ) );
    } else {
        esc_html_e( 'No scan yet', 'maroon-horizon-smart-firewall' );
    }
    ?></span></div></div>
  <div class="sfais-card mhsf-shield"><span class="mhsf-ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z"></path><path d="M9 12l2 2 4-4"></path></svg></span><div><strong><?php 
    esc_html_e( 'Hardening', 'maroon-horizon-smart-firewall' );
    ?></strong><span class="mhsf-muted"><?php 
    echo esc_html( sprintf( 
        /* translators: 1: on, 2: total */
        __( '%1$d of %2$d patches on', 'maroon-horizon-smart-firewall' ),
        $mhsf_patches_on,
        count( $mhsf_patch_opts )
     ) );
    ?></span></div></div>
  <div class="sfais-card mhsf-shield"><span class="mhsf-ico" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 12a8 8 0 0 1-14 5M4 12a8 8 0 0 1 14-5"></path><path d="M18 3v4h-4M6 21v-4h4"></path></svg></span><div><strong><?php 
    esc_html_e( 'Updates', 'maroon-horizon-smart-firewall' );
    ?></strong><span class="mhsf-muted"><?php 
    echo esc_html( ( $mhsf_licensed ? ( $mhsf_next ? __( 'Daily · digitally signed data', 'maroon-horizon-smart-firewall' ) : __( 'Daily sync is off · digitally signed data', 'maroon-horizon-smart-firewall' ) ) : __( 'Plugin updates in Dashboard → Updates', 'maroon-horizon-smart-firewall' ) ) );
    ?></span></div></div>
</div>

<div class="mhsf-two">
  <section class="sfais-card mhsf-span2" aria-label="<?php 
    esc_attr_e( 'Recommended fixes', 'maroon-horizon-smart-firewall' );
    ?>">
    <h3 style="margin:0 0 6px;"><?php 
    echo esc_html( ( $mhsf_fix_count ? sprintf( 
        /* translators: %d: count */
        _n(
            'Recommended fix · %d',
            'Recommended fixes · %d',
            $mhsf_fix_count,
            'maroon-horizon-smart-firewall'
        ),
        $mhsf_fix_count
     ) : __( 'Nothing to fix right now', 'maroon-horizon-smart-firewall' ) ) );
    ?></h3>
    <?php 
    foreach ( array_slice( $mhsf_fixes, 0, 4 ) as $mhsf_i ) {
        ?>
      <div class="mhsf-fix">
        <div><strong style="color:var(--mh-head);font-size:14px;"><?php 
        echo esc_html( (string) ($mhsf_i['label'] ?? '') );
        ?></strong><div class="mhsf-muted" style="font-size:12.5px;"><?php 
        echo esc_html( wp_trim_words( (string) ($mhsf_i['message'] ?? ''), 18 ) );
        ?></div></div>
        <span class="sfais-badge <?php 
        echo esc_attr( ( 'crit' === $mhsf_i['status'] ? 'crit' : 'warn' ) );
        ?>"><?php 
        echo esc_html( ( 'crit' === $mhsf_i['status'] ? __( 'Critical', 'maroon-horizon-smart-firewall' ) : __( 'Warning', 'maroon-horizon-smart-firewall' ) ) );
        ?></span>
      </div>
    <?php 
    }
    ?>
    <?php 
    if ( $mhsf_fix_count ) {
        ?>
      <p style="margin:12px 0 0;"><?php 
        if ( $mhsf_fix_by_patch ) {
            ?><a class="button" href="<?php 
            echo esc_url( $mhsf_pa_url );
            ?>"><?php 
            esc_html_e( 'Open Security Patches', 'maroon-horizon-smart-firewall' );
            ?></a> <?php 
        }
        ?><a href="#mhsf-details" style="margin-left:8px;"><?php 
        esc_html_e( 'See all checks', 'maroon-horizon-smart-firewall' );
        ?></a></p>
    <?php 
    }
    ?>
  </section>
  <section class="sfais-card" aria-label="<?php 
    esc_attr_e( 'Recent activity', 'maroon-horizon-smart-firewall' );
    ?>">
    <h3 style="margin:0 0 8px;"><?php 
    esc_html_e( 'Recent activity', 'maroon-horizon-smart-firewall' );
    if ( count( $mhsf_acts ) > 1 ) {
        ?> <span class="mhsf-muted" style="font-size:12px;font-weight:500;">· <?php 
        echo esc_html( sprintf( 
            /* translators: %d: entries */
            __( 'last %d', 'maroon-horizon-smart-firewall' ),
            count( $mhsf_acts )
         ) );
        ?></span><?php 
    }
    ?></h3>
    <?php 
    if ( !$mhsf_acts ) {
        ?>
      <p class="mhsf-muted" style="margin:0;"><?php 
        esc_html_e( 'Nothing yet - run a check or a scan.', 'maroon-horizon-smart-firewall' );
        ?></p>
    <?php 
    }
    ?>
    <div class="mhsf-acts" tabindex="0" aria-label="<?php 
    esc_attr_e( 'Recent activity list', 'maroon-horizon-smart-firewall' );
    ?>">
    <?php 
    foreach ( $mhsf_acts as $mhsf_a ) {
        ?>
      <div class="mhsf-act"><time datetime="<?php 
        echo esc_attr( gmdate( 'c', (int) $mhsf_a[0] ) );
        ?>"><?php 
        echo esc_html( wp_date( 'M j, ' . get_option( 'time_format' ), (int) $mhsf_a[0] ) );
        ?></time><span><?php 
        echo esc_html( $mhsf_a[1] );
        ?></span></div>
    <?php 
    }
    ?>
    </div>
  </section>
</div>

<h2 id="mhsf-details"><?php 
    esc_html_e( 'All security checks', 'maroon-horizon-smart-firewall' );
    ?></h2>
<p class="sfais-kicker" style="max-width:700px;margin-top:6px;"><?php 
    esc_html_e( 'Helps reduce automated attacks (bots, brute force, malicious IPs) and highlights common hardening gaps you can improve.', 'maroon-horizon-smart-firewall' );
    ?></p>

<?php 
    $status_badge = function ( $status ) {
        $map = [
            'ok'   => ['🟢', 'ok', 'OK'],
            'warn' => ['🟡', 'warn', 'Warning'],
            'crit' => ['🔴', 'crit', 'Critical'],
            'info' => ['🔵', 'info', 'Info'],
        ];
        $m = $map[$status] ?? $map['info'];
        return sprintf(
            '<span class="sfais-badge %1$s">%2$s %3$s</span>',
            esc_attr( $m[1] ),
            esc_html( $m[0] ),
            esc_html( $m[2] )
        );
    };
    $sfais_allowed_badge_html = array(
        'span' => array(
            'class' => true,
        ),
    );
    $sfais_allowed_controls_html = array(
        'form'   => array(
            'method'    => true,
            'action'    => true,
            'class'     => true,
            'data-flag' => true,
            'style'     => true,
        ),
        'input'  => array(
            'type'  => true,
            'name'  => true,
            'value' => true,
            'id'    => true,
        ),
        'button' => array(
            'type'  => true,
            'class' => true,
            'style' => true,
        ),
    );
    // Render sections with improved messages
    foreach ( $sections as $section ) {
        echo '<div class="sfais-card">';
        echo '<h3 class="sfais-section-title"><span class="dashicons dashicons-admin-generic" style="color:#0288d1;"></span> ' . esc_html( $section['title'] ) . '</h3>';
        echo '<table class="sfais-check-table"><tbody>';
        foreach ( $section['items'] as $item ) {
            $msg = $item['message'];
            $value_display = $item['value'];
            $badge_status = $item['status'];
            // ✅ Ensure rows always have a non-empty description (some environments can yield empty message strings).
            if ( true ) {
                if ( $msg === null ) {
                    $msg = '';
                }
                if ( $msg === '' ) {
                    if ( stripos( $item['label'], 'Strong Password Policy' ) !== false ) {
                        $msg = 'Enforce strong admin passwords to reduce account compromise risk. If you already enforce this via a security plugin/host policy, you can mark it as confirmed.';
                    } elseif ( stripos( $item['label'], 'Two-Factor Authentication (2FA)' ) !== false ) {
                        $msg = 'Two-factor authentication significantly reduces the risk of account takeovers. If you have 2FA enabled via a plugin or hosting provider, you can mark it as confirmed.';
                    } elseif ( stripos( $item['label'], 'Backup Found' ) !== false ) {
                        $msg = 'Backups protect you from data loss and malware incidents. Ensure backups run regularly and are stored off-site, then confirm once configured.';
                    } elseif ( stripos( $item['label'], 'Backup Age' ) !== false ) {
                        $msg = 'Backups should be recent. If you verify your last successful backup is within an acceptable window (e.g., 7 days), mark it as confirmed.';
                    }
                }
            }
            // 1.8.13: the old text overrides here ("your site files can't be modified", "attackers can't detect it") claimed too
            // much - the security check now writes the true text itself.
            // Extra controls for Backup + User Security sections
            $extra_controls = '';
            if ( isset( $section['title'] ) ) {
                // 🔁 Backup & Maintenance buttons
                if ( stripos( $section['title'], 'Backup & Maintenance' ) !== false ) {
                    // Backup Found row
                    if ( stripos( $item['label'], 'Backup Found' ) !== false ) {
                        $action = ( $manual_backup_found ? 'backup_found_clear' : 'backup_found_set' );
                        $label = ( $manual_backup_found ? '✖ Clear manual confirmation' : '✅ Mark as configured' );
                        ob_start();
                        wp_nonce_field( 'sfais_backup_flags', 'sfais_backup_nonce' );
                        $nonce_html = ob_get_clean();
                        $extra_controls .= '<form method="post" class="sfais-manual-flag-form" data-flag="backup_found" style="margin-top:6px;">' . $nonce_html . '<input type="hidden" name="sfais_backup_action" value="' . esc_attr( $action ) . '">' . '<input type="hidden" name="sfais_active_tab" value="dashboard">' . '<button type="submit" class="button button-secondary" style="margin-top:2px;">' . esc_html( $label ) . '</button>' . '</form>';
                    }
                    // Backup Age row
                    if ( stripos( $item['label'], 'Backup Age' ) !== false ) {
                        $action = ( $manual_backup_age_ok ? 'backup_age_clear' : 'backup_age_set' );
                        $label = ( $manual_backup_age_ok ? '✖ Clear manual confirmation' : '✅ Mark as recent' );
                        ob_start();
                        wp_nonce_field( 'sfais_backup_flags', 'sfais_backup_nonce' );
                        $nonce_html = ob_get_clean();
                        $extra_controls .= '<form method="post" class="sfais-manual-flag-form" data-flag="backup_age" style="margin-top:6px;">' . $nonce_html . '<input type="hidden" name="sfais_backup_action" value="' . esc_attr( $action ) . '">' . '<input type="hidden" name="sfais_active_tab" value="dashboard">' . '<button type="submit" class="button button-secondary" style="margin-top:2px;">' . esc_html( $label ) . '</button>' . '</form>';
                    }
                }
                // 🔐 User Security buttons (Strong Passwords & 2FA)
                if ( stripos( $section['title'], 'User Security' ) !== false ) {
                    // Strong Password Policy row
                    if ( stripos( $item['label'], 'Strong Password Policy' ) !== false ) {
                        $action = ( $manual_strong_passwords ? 'strong_passwords_clear' : 'strong_passwords_set' );
                        $label = ( $manual_strong_passwords ? '✖ Clear manual confirmation' : '✅ Mark as enforced' );
                        ob_start();
                        wp_nonce_field( 'sfais_usersec_flags', 'sfais_usersec_nonce' );
                        $nonce_html = ob_get_clean();
                        $extra_controls .= '<form method="post" class="sfais-manual-flag-form" data-flag="strong_passwords" style="margin-top:6px;">' . $nonce_html . '<input type="hidden" name="sfais_usersec_action" value="' . esc_attr( $action ) . '">' . '<input type="hidden" name="sfais_active_tab" value="dashboard">' . '<button type="submit" class="button button-secondary" style="margin-top:2px;">' . esc_html( $label ) . '</button>' . '</form>';
                    }
                    // Two-Factor Authentication (2FA) row
                    if ( stripos( $item['label'], 'Two-Factor Authentication (2FA)' ) !== false ) {
                        $action = ( $manual_2fa_enabled ? 'two_factor_clear' : 'two_factor_set' );
                        $label = ( $manual_2fa_enabled ? '✖ Clear manual confirmation' : '✅ Mark as enabled' );
                        ob_start();
                        wp_nonce_field( 'sfais_usersec_flags', 'sfais_usersec_nonce' );
                        $nonce_html = ob_get_clean();
                        $extra_controls .= '<form method="post" class="sfais-manual-flag-form" data-flag="two_factor" style="margin-top:6px;">' . $nonce_html . '<input type="hidden" name="sfais_usersec_action" value="' . esc_attr( $action ) . '">' . '<input type="hidden" name="sfais_active_tab" value="dashboard">' . '<button type="submit" class="button button-secondary" style="margin-top:2px;">' . esc_html( $label ) . '</button>' . '</form>';
                    }
                }
            }
            echo '<tr>';
            echo '<td class="sfais-label">' . esc_html( $item['label'] ) . '</td>';
            echo '<td class="sfais-status-cell">' . wp_kses( $status_badge( $badge_status ), $sfais_allowed_badge_html ) . '</td>';
            echo '<td class="sfais-value-cell"><code>' . esc_html( $value_display ) . '</code></td>';
            // ✅ Wrap message text so it can be updated via AJAX without re-rendering controls
            echo '<td class="sfais-msg-cell">';
            echo '<div class="sfais-submsg">';
            echo '<span class="sfais-msg-text">' . esc_html( $msg ) . '</span>';
            if ( !empty( $extra_controls ) ) {
                // The controls are internally generated, but are still sanitized via allowlist.
                echo wp_kses( $extra_controls, $sfais_allowed_controls_html );
            }
            echo '</div>';
            echo '</td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
    }
} );