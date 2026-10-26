<?php
if (!defined('ABSPATH')) exit;

/**
 * 🧠 Maroon Horizon Smart Firewall — Core Controller
 * Connects IP Manager, Patch Manager, Security Check, and Malware Scanner
 */
class SFAIS_Functions {

    private $ip_manager;
    private $patch_manager;
    private $security_check;
    private $login_guard;
    private $bot_protection;
    public function __construct() {
        $GLOBALS['sfais_functions'] = $this;

        $this->ip_manager     = new SFAIS_IP_Manager();
        $this->patch_manager  = new SFAIS_Patch_Manager();
        $this->security_check = new SFAIS_Security_Check();

        // Runtime hardening modules (FREE + PRO)
        if ( class_exists( 'SFAIS_Login_Guard' ) ) {
            $this->login_guard = new SFAIS_Login_Guard();
        }
        if ( class_exists( 'SFAIS_Bot_Protection' ) ) {
            $this->bot_protection = new SFAIS_Bot_Protection();
        }


        // Early runtime (FREE + PRO)
        add_action('plugins_loaded', [$this, 'php_firewall_check'], 0);

        // FREE runtime triggers (must remain functional in WP.org build)
        add_action('wp_ajax_sfais_toggle_htaccess_lock', [$this, 'ajax_toggle_htaccess_lock']);
        // ✅ AJAX: Dashboard manual confirmations (FREE + PRO)
        add_action('wp_ajax_sfais_toggle_manual_flag', [$this, 'ajax_toggle_manual_flag']);

        // ✅ AJAX - IP Blocker (NO REFRESH)
        add_action('wp_ajax_sfais_block_ip_ajax',               [$this, 'ajax_block_ip']);
        add_action('wp_ajax_sfais_unblock_ip_ajax',             [$this, 'ajax_unblock_ip']);

        // Runtime triggers that are part of the FREE feature-set must remain registered in WP.org builds.
        // Premium-only features are removed/relocated into /includes/pro (stripped from the WP.org FREE artifact).
        // Patches & hardening (FREE)
        add_action('init', [$this, 'bootstrap_patches'], 1);
        add_action('wp_ajax_sfais_toggle_patch', [$this, 'ajax_toggle_patch']);

        // Malware scanner & quarantine (FREE)
        // 1.8.13: legacy synchronous sfais_scan_core removed (UI uses the async core scan job only).
        add_action('wp_ajax_sfais_scan_core_start', [$this, 'ajax_scan_core_start']);
        add_action('wp_ajax_sfais_scan_core_tick',  [$this, 'ajax_scan_core_tick']);
        add_action('wp_ajax_sfais_scan_core_cancel',[$this, 'ajax_scan_core_cancel']);
        add_action('wp_ajax_sfais_scan_uploads',    [$this, 'ajax_scan_uploads']);
        add_action('wp_ajax_sfais_quarantine_move',   [$this, 'ajax_quarantine_move']);
        add_action('wp_ajax_sfais_quarantine_delete', [$this, 'ajax_quarantine_delete']);
        add_action('wp_ajax_sfais_quarantine_ignore', [$this, 'ajax_quarantine_ignore']);
        add_action('wp_ajax_sfais_quarantine_ignore_bulk', [$this, 'ajax_quarantine_ignore_bulk']);
        add_action('wp_ajax_sfais_quarantine_list',    [$this, 'ajax_quarantine_list']);
        add_action('wp_ajax_sfais_quarantine_restore', [$this, 'ajax_quarantine_restore']);
        add_action('wp_ajax_sfais_quarantine_remove',  [$this, 'ajax_quarantine_remove']);
        // 1.8.13: Ignored files list (Scanner tab) + Un-ignore
        add_action('wp_ajax_sfais_scanner_ignored_list', [$this, 'ajax_scanner_ignored_list']);
        add_action('wp_ajax_sfais_scanner_unignore',     [$this, 'ajax_scanner_unignore']);
    }

    /* ----------------------------------------------------------------
     * BOOTSTRAP / FIREWALL
     * ---------------------------------------------------------------- */
    public function bootstrap_patches() {
        $this->patch_manager->bootstrap_patches();
    }

    public function php_firewall_check() {
        $this->ip_manager->php_firewall_check();
    }

    /* ----------------------------------------------------------------
     * ✅ IP BLOCKER — AJAX HELPERS
     * ---------------------------------------------------------------- */
    private function sfais_notice_payload($status, $message) {
        return [
            'ok'      => (bool) $status,
            'message' => (string) $message,
        ];
    }


    /**
     * Sanitize and validate a relative file path coming from admin/AJAX.
     *
     * Defense-in-depth against path traversal and malformed inputs.
     * Returns an empty string when invalid.
     */
    private function sanitize_relpath( $rel ) : string {
        $rel = is_string( $rel ) ? $rel : (string) $rel;
        $rel = wp_normalize_path( $rel );

        // Strip any leading slashes to enforce a relative path.
        $rel = ltrim( $rel, '/\\' );

        if ( '' === $rel ) {
            return '';
        }

        // Disallow traversal segments.
        if ( false !== strpos( $rel, '..' ) ) {
            return '';
        }

        // Keep path reasonably short to avoid abuse.
        if ( strlen( $rel ) > 2048 ) {
            return '';
        }

        return $rel;
    }

    private function ip_is_in_htaccess($ip) {
        // 1.8.9: one parser for the whole plugin (IP manager); only rules the plugin manages count.
        return in_array( (string) $ip, (array) $this->ip_manager->get_htaccess_ips(), true );
    }

    /**
     * One blocked-IP row (used by the IP Blocker tab and the AJAX answers, so both always look the same).
     *
     * 1.8.13: the status comes from BOTH lists - the WordPress firewall list and the server rules in .htaccess - so a
     * row never claims "server + WordPress" for an address the WordPress firewall does not block (or the other way round).
     *
     * @param string     $ip     Canonical IP address.
     * @param array|null $ht_ips Server-rule IPs (pass when building many rows, so .htaccess is read once).
     * @param array|null $db_ips WordPress firewall IPs (same).
     */
    public function ip_card_html($ip, $ht_ips = null, $db_ips = null) {
        $ip     = (string) $ip;
        $in_ht  = is_array( $ht_ips ) ? in_array( $ip, $ht_ips, true ) : $this->ip_is_in_htaccess($ip);
        $in_db  = in_array( $ip, is_array( $db_ips ) ? $db_ips : (array) $this->ip_manager->get_db_ips(), true );
        $in_srv = $in_ht && $this->detect_server_type() === 'apache';   // a rule in .htaccess only works where the server reads it

        // 1.8.9 (Vlad option A): one status per IP - where it is blocked, and why when it is WordPress only.
        if ( $in_srv && $in_db ) {
            $chip = '<span class="sfais-ip-status is-both"><span class="dashicons dashicons-shield" aria-hidden="true"></span>'
                . esc_html__( 'Blocked: server + WordPress', 'maroon-horizon-smart-firewall' ) . '</span>';
        } elseif ( $in_db ) {
            $chip = '<span class="sfais-ip-status is-wp"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>'
                . esc_html__( 'Blocked: WordPress only', 'maroon-horizon-smart-firewall' ) . '</span>'
                . '<span class="sfais-ip-why">' . esc_html( $this->server_rule_missing_reason() ) . '</span>';
        } elseif ( $in_srv ) {
            // 1.8.13: only a server rule (e.g. an unblock could not change the locked .htaccess, or the rule was added by hand).
            $chip = '<span class="sfais-ip-status is-server"><span class="dashicons dashicons-shield-alt" aria-hidden="true"></span>'
                . esc_html__( 'Blocked: server only', 'maroon-horizon-smart-firewall' ) . '</span>'
                . '<span class="sfais-ip-why">' . esc_html__( 'Not in the WordPress firewall list - block it again to add it.', 'maroon-horizon-smart-firewall' ) . '</span>';
        } else {
            // 1.8.13: a rule in .htaccess on a server that does not read .htaccess blocks nothing.
            $chip = '<span class="sfais-ip-status is-none"><span class="dashicons dashicons-warning" aria-hidden="true"></span>'
                . esc_html__( 'Not blocked', 'maroon-horizon-smart-firewall' ) . '</span>'
                . '<span class="sfais-ip-why">' . esc_html__( 'Only listed in .htaccess, which this server does not use.', 'maroon-horizon-smart-firewall' ) . '</span>';
        }

        $nonce = wp_create_nonce('sfais_unblock_ip_action');

        $html  = '<div class="sfais-ip-card" data-ip="' . esc_attr($ip) . '">';
        $html .= '  <div class="sfais-ip-top">';
        $html .= '    <div class="sfais-ip-left"><code class="sfais-ip-code">' . esc_html($ip) . '</code> ' . $chip . '</div>';
        $html .= '    <form method="post" class="sfais-ip-remove-form">';
        $html .= '      <input type="hidden" name="sfais_unblock_ip_nonce" value="' . esc_attr($nonce) . '">';
        $html .= '      <input type="hidden" name="sfais_active_tab" value="ip-blocker">';
        $html .= '      <input type="hidden" name="sfais_unblock_ip" value="' . esc_attr($ip) . '">';
        /* translators: %s: IP address. */
        $html .= '      <button class="button sfais-ip-remove" type="submit" aria-label="' . esc_attr( sprintf( __( 'Unblock %s', 'maroon-horizon-smart-firewall' ), $ip ) ) . '"><span class="dashicons dashicons-trash" aria-hidden="true"></span><span>' . esc_html__( 'Unblock', 'maroon-horizon-smart-firewall' ) . '</span></button>';
        $html .= '    </form>';
        $html .= '  </div>';
        $html .= '</div>';

        return $html;
    }

    /**
     * Why an IP has no server rule (short, shown next to "Blocked: WordPress only").
     */
    private function server_rule_missing_reason() {
        $ht = ABSPATH . '.htaccess';
        if ( $this->detect_server_type() !== 'apache' ) {
            return __( 'This server does not use .htaccess.', 'maroon-horizon-smart-firewall' );
        }
        if ( ! file_exists( $ht ) ) {
            return __( 'No .htaccess file in the WordPress folder.', 'maroon-horizon-smart-firewall' );
        }
        if ( ! SFAIS_FS::is_writable( $ht ) ) {
            return __( '.htaccess is locked - unlock it to add the server rule.', 'maroon-horizon-smart-firewall' );
        }
        return __( 'The server rule could not be added to .htaccess.', 'maroon-horizon-smart-firewall' );
    }

    /**
     * One plain sentence above the blocked-IP list: how blocking works on THIS hosting.
     */
    public function ip_protection_summary() {
        // 1.8.12: behind Cloudflare the real visitor address is the one Cloudflare reports.
        $cf = $this->ip_manager->request_via_cloudflare()
            ? __( 'Your site is behind Cloudflare. Blocks use the visitor\'s real address that Cloudflare reports.', 'maroon-horizon-smart-firewall' ) . ' '
            : '';
        return $cf . $this->ip_server_summary();
    }

    private function ip_server_summary() {
        $soft = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
        if ( strpos( $soft, 'litespeed' ) !== false ) {
            $name = 'LiteSpeed';
        } elseif ( strpos( $soft, 'apache' ) !== false ) {
            $name = 'Apache';
        } elseif ( strpos( $soft, 'nginx' ) !== false ) {
            $name = 'Nginx';
        } else {
            $name = '';
        }

        $ht = ABSPATH . '.htaccess';
        // 1.8.13: the WordPress firewall runs only when WordPress itself serves the request - said plainly.
        if ( $this->detect_server_type() !== 'apache' ) {
            if ( $name === '' ) {
                return __( 'Your server does not use .htaccess, so blocked IPs are stopped by the WordPress firewall on every page WordPress serves (not on cached pages or static files).', 'maroon-horizon-smart-firewall' );
            }
            /* translators: %s: web server name, e.g. Nginx. */
            return sprintf( __( 'Your server (%s) does not use .htaccess, so blocked IPs are stopped by the WordPress firewall on every page WordPress serves (not on cached pages or static files).', 'maroon-horizon-smart-firewall' ), $name );
        }
        if ( ! file_exists( $ht ) ) {
            /* translators: %s: web server name, e.g. Apache. */
            return sprintf( __( 'Your server (%s) can use .htaccess, but WordPress has none yet, so blocked IPs are stopped by the WordPress firewall on every page WordPress serves (not on cached pages or static files).', 'maroon-horizon-smart-firewall' ), $name );
        }
        if ( ! SFAIS_FS::is_writable( $ht ) ) {
            /* translators: %s: web server name, e.g. Apache. */
            return sprintf( __( 'On your server (%s) blocked IPs are stopped before WordPress loads (.htaccess) and again by the WordPress firewall. .htaccess is locked now, so new blocks use the WordPress firewall until you unlock it.', 'maroon-horizon-smart-firewall' ), $name );
        }
        /* translators: %s: web server name, e.g. Apache. */
        return sprintf( __( 'On your server (%s) blocked IPs are stopped before WordPress loads (.htaccess) and again by the WordPress firewall.', 'maroon-horizon-smart-firewall' ), $name );
    }

    /**
     * All blocked-IP rows (sent back after a lock/unlock, when the statuses can change).
     */
    public function ip_list_html() {
        $html = '';
        // 1.8.13: both lists read once for all rows.
        $ht_ips = (array) $this->get_htaccess_ips();
        $db_ips = (array) $this->ip_manager->get_db_ips();
        foreach ( array_unique( (array) $this->get_blocked_ips(), SORT_REGULAR ) as $ip ) {
            $html .= $this->ip_card_html( (string) $ip, $ht_ips, $db_ips );
        }
        return $html;
    }

    /* ----------------------------------------------------------------
     * ✅ IP BLOCKER — AJAX ENDPOINTS
     * ---------------------------------------------------------------- */
    public function ajax_block_ip() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        }

        $nonce = isset( $_POST['sfais_block_ip_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_block_ip_nonce'] ) ) : '';
        if (!$nonce || !wp_verify_nonce($nonce, 'sfais_block_ip_action')) {
            wp_send_json_error(['message' => __( 'Security check failed. Please refresh the page and try again.', 'maroon-horizon-smart-firewall')]);
        }

        $ip_raw = isset( $_POST['sfais_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_ip'] ) ) : '';

        if ($ip_raw === '') {
            wp_send_json_error(['message' => __( 'Missing IP address.', 'maroon-horizon-smart-firewall')]);
        }

        $result = $this->block_ip($ip_raw);

        
        // If validation failed (e.g., invalid IP), do NOT return success or generate a card.
        if ( ! is_array( $result ) || empty( $result['status'] ) ) {
            $msg = is_array( $result ) && isset( $result['message'] ) ? (string) $result['message'] : __( 'Request failed.', 'maroon-horizon-smart-firewall');
            wp_send_json_error( [ 'message' => $msg ] );
        }
$stored_ip = isset( $result['ip'] ) ? (string) $result['ip'] : $ip_raw;

        $card_html = $this->ip_card_html($stored_ip);

        wp_send_json_success([
            'message'   => $result['message'] ?? __( 'Done.', 'maroon-horizon-smart-firewall'),
            'ip'        => $stored_ip,
            'card_html' => $card_html,
            'total'     => count((array) $this->get_blocked_ips()),
        ]);
    }

    public function ajax_unblock_ip() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        }

        $nonce = isset( $_POST['sfais_unblock_ip_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_unblock_ip_nonce'] ) ) : '';
        if (!$nonce || !wp_verify_nonce($nonce, 'sfais_unblock_ip_action')) {
            wp_send_json_error(['message' => __( 'Security check failed. Please refresh and try again.', 'maroon-horizon-smart-firewall')]);
        }

        $ip = sanitize_text_field( wp_unslash( $_POST['sfais_unblock_ip'] ?? '' ) );
        if ($ip === '') {
            wp_send_json_error(['message' => __( 'Missing IP.', 'maroon-horizon-smart-firewall')]);
        }

        $res = $this->unblock_ip($ip);

        
        // If validation failed (e.g., invalid IP), return an error.
        if ( ! is_array( $res ) || empty( $res['status'] ) ) {
            $msg = is_array( $res ) && isset( $res['message'] ) ? (string) $res['message'] : __( 'Request failed.', 'maroon-horizon-smart-firewall');
            wp_send_json_error( [ 'message' => $msg ] );
        }
// 1.8.13: the canonical address the IP manager worked with (the row's data-ip uses the same form).
        $ip  = isset( $res['ip'] ) ? (string) $res['ip'] : $ip;
        $all = (array) $this->get_blocked_ips();
        $still_blocked = in_array($ip, $all, true);

        $payload = [
            'message'       => $res['message'] ?? __( 'Done.', 'maroon-horizon-smart-firewall'),
            'ip'            => $ip,
            'still_blocked' => $still_blocked,
            'total'         => count($all),
        ];

        if ($still_blocked) {
            $payload['card_html'] = $this->ip_card_html($ip);
        }

        wp_send_json_success($payload);
    }

    /* ----------------------------------------------------------------
     * ✅ .htaccess STATE HELPERS
     * ---------------------------------------------------------------- */

    /**
     * Returns a robust .htaccess state snapshot.
     *
     * We intentionally prefer "effective writability" over raw permission bits,
     * because ownership/ACLs can cause SFAIS_FS::is_writable() to be misleading.
     */
    public function get_htaccess_state() {
        $ht = ABSPATH . '.htaccess';

        $state = [
            'path'     => $ht,
            'exists'   => file_exists($ht),
            'readable' => false,
            'writable' => false,
            'locked'   => true,
            'perm'     => '',
        ];

        if (!$state['exists']) {
            return $state;
        }

        clearstatcache(true, $ht);

        $state['readable'] = is_readable($ht);

        // Prefer wp_is_writable when available (it has edge-case handling).
        $w = function_exists('wp_is_writable') ? wp_is_writable($ht) : SFAIS_FS::is_writable($ht);

        $state['writable'] = (bool) $w;
        $state['locked']   = ! $state['writable'];

        $perms = (file_exists($ht) && is_readable($ht)) ? fileperms($ht) : false;
        if ($perms !== false) {
            $state['perm'] = substr(sprintf('%o', $perms), -4);
        }

        return $state;
    }

    public function ajax_toggle_htaccess_lock() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        }

        // Nonce check (required).
        $nonce_ok = check_ajax_referer( 'sfais_htaccess_lock_action', 'nonce', false );
        if ( ! $nonce_ok ) {
            wp_send_json_error( [ 'message' => __( 'Security check failed. Please refresh and try again.', 'maroon-horizon-smart-firewall' ) ] );
        }

        $state = $this->get_htaccess_state();
        if (empty($state['exists'])) {
            wp_send_json_error([
                'message' => __( '.htaccess not found. This feature is only available on Apache or LiteSpeed servers.', 'maroon-horizon-smart-firewall')
            ]);
        }

        $ht = $state['path'];

        // Decide desired permission based on effective writability (not just chmod bits).
        $was_writable = !empty($state['writable']);
        $new_perm     = $was_writable ? 0444 : 0644;

        // Apply permission change.
        $result = SFAIS_FS::chmod($ht, $new_perm);
        if (!$result) {
            wp_send_json_error(['message' => __( 'Permission change failed. Try manual method via FTP.', 'maroon-horizon-smart-firewall')]);
        }

        // Re-check actual effective state.
        $after = $this->get_htaccess_state();
        $locked = !empty($after['locked']);

        // If we attempted to unlock but PHP still cannot write, be explicit.
        if ($new_perm === 0644 && $locked) {
            $perm = $after['perm'] ? ('perm ' . (string) $after['perm']) : '';
            $msg  = __( 'The permission bits were updated, but WordPress still cannot write to .htaccess. This usually means file ownership or server ACLs prevent PHP from writing.', 'maroon-horizon-smart-firewall');

            if ($perm) {
                /* translators: %s: current permission string, e.g. 'perm 0644'. */
                $msg .= ' ' . sprintf( __( 'Current permissions: %s', 'maroon-horizon-smart-firewall'), sanitize_text_field( (string) $perm ) );
            }

            wp_send_json_error([
                'message' => $msg,
            ]);
        }

        if (!$locked) {
            $this->ip_manager->resync_htaccess_if_unlocked();
        }

        wp_send_json_success([
            'locked'    => $locked,
            'perm'      => $after['perm'],
            'summary'   => $this->ip_protection_summary(),
            'list_html' => $this->ip_list_html(),
            'message' => $locked
                ? __( '.htaccess locked (read-only).', 'maroon-horizon-smart-firewall')
                : __( '.htaccess unlocked (writable).', 'maroon-horizon-smart-firewall')
        ]);
    }


    /* ----------------------------------------------------------------
     * SECURITY PATCHES AJAX (NO REFRESH)
     * ---------------------------------------------------------------- */
    public function ajax_toggle_patch() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall' ) ] );
        }

        $nonce = isset( $_POST['sfais_patch_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_patch_nonce'] ) ) : '';
        if ( ! $nonce || ! wp_verify_nonce( $nonce, 'sfais_patch_action_verify' ) ) {
            wp_send_json_error( [ 'message' => __( 'Security check failed. Please refresh the page and try again.', 'maroon-horizon-smart-firewall' ) ] );
        }

        $patch       = sanitize_text_field( wp_unslash( $_POST['patch'] ?? ( $_POST['sfais_patch'] ?? '' ) ) );
        $action_type = sanitize_text_field( wp_unslash( $_POST['action_type'] ?? ( $_POST['sfais_patch_action'] ?? '' ) ) );

        if ( '' === $patch || '' === $action_type ) {
            wp_send_json_error( [ 'message' => __( 'Missing patch/action.', 'maroon-horizon-smart-firewall' ) ] );
        }

        // FREE build: only FREE patches are executable in the WP.org artifact.
        $map = [
            'versioninfo' => 'sfais_patch_versioninfo',
            'dirlisting'  => 'sfais_patch_dirlisting',
            'xmlrpc'      => 'sfais_patch_xmlrpc',
            'filemods'    => 'sfais_patch_filemods',
            'permissions' => 'sfais_patch_permissions',
        ];

        if ( ! isset( $map[ $patch ] ) ) {
            /* translators: %s: patch identifier. */
            $message_template = __( 'Unknown patch: %s', 'maroon-horizon-smart-firewall' );
            $message          = sprintf( $message_template, sanitize_key( (string) $patch ) );
            wp_send_json_error( [ 'message' => $message ] );
        }

        if ( ! in_array( $action_type, [ 'apply', 'revert' ], true ) ) {
            wp_send_json_error( [ 'message' => __( 'Invalid action.', 'maroon-horizon-smart-firewall' ) ] );
        }

        try {
            $res = $this->patch_manager->toggle( $patch, $action_type );
        } catch ( \Throwable $e ) {
            // Always return JSON to avoid the UI showing "Network error" on fatals.
            $safe_message = __( 'Patch operation failed due to a server error. Please check error logs and try again.', 'maroon-horizon-smart-firewall' );
            wp_send_json_error( [ 'message' => $safe_message ] );
        }

        $opt_key = $map[ $patch ];
        $active  = (bool) get_option( $opt_key );

        $ui = [
            'active'       => $active,
            'status_text'  => $active ? __( 'Active', 'maroon-horizon-smart-firewall' ) : __( 'Inactive', 'maroon-horizon-smart-firewall' ),
            'status_color' => $active ? '#2e7d32' : '#d32f2f',
            'button_class' => $active ? 'button button-secondary' : 'button button-primary',
            'button_label' => $active ? __( '🔄 Revert Patch', 'maroon-horizon-smart-firewall' ) : __( '🛡️ Apply Patch', 'maroon-horizon-smart-firewall' ),
            'next_action'  => $active ? 'revert' : 'apply',
        ];

        $ok  = is_array( $res ) && ! empty( $res['status'] );
        $msg = is_array( $res ) && isset( $res['message'] ) ? (string) $res['message'] : '';

        // 1.8.13: the Dashboard (score, header, check rows) is redrawn from this answer - no page reload needed.
        $dash = class_exists( 'SFAIS_Admin_UI' ) ? SFAIS_Admin_UI::dashboard_refresh_payload() : [];

        if ( $ok ) {
            wp_send_json_success( array_merge( $dash, [
                'message' => $msg,
                'ui'      => $ui,
            ] ) );
        }

        wp_send_json_error( array_merge( $dash, [
            'message' => ( $msg !== '' ? $msg : __( 'Patch operation failed.', 'maroon-horizon-smart-firewall' ) ),
            'ui'      => $ui,
        ] ) );
    }
    /* ----------------------------------------------------------------
     * ✅ DASHBOARD MANUAL FLAGS — AJAX
     * ---------------------------------------------------------------- */


    /* ----------------------------------------------------------------
     * MALWARE SCANNER AJAX HANDLERS
     * ---------------------------------------------------------------- */
    /* ----------------------------------------------------------------
     * ✅ Async Scan Jobs (Progress + Cancel)
     * ---------------------------------------------------------------- */

    private function sfais_scan_jobs_dir() : string {
        $dir = function_exists( 'mhsf_get_data_dir' ) ? mhsf_get_data_dir( 'reports/scan-jobs' ) : '';
        if ( is_wp_error( $dir ) || '' === $dir ) {
            return '';
        }
        return rtrim( wp_normalize_path( (string) $dir ), '/\\' );
    }

    private function sfais_scan_job_paths( string $job_id ) : array {
        $job_id = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $job_id );
        $dir    = $this->sfais_scan_jobs_dir();
        if ( '' === $dir ) {
            return [
                'job'  => '',
                'list' => '',
            ];
        }
        return [
            'job'  => $dir . '/' . $job_id . '.json',
            'list' => $dir . '/' . $job_id . '.list',
        ];
    }

    private function sfais_scan_job_read( string $job_id ) {
        $paths = $this->sfais_scan_job_paths( $job_id );
        if ( empty( $paths['job'] ) ) {
            return false;
        }
        $raw   = SFAIS_FS::read( $paths['job'] );
        if ( ! is_string( $raw ) || $raw === '' ) {
            return false;
        }
        $data = json_decode( $raw, true );
        if ( ! is_array( $data ) ) {
            return false;
        }
        $data['_paths'] = $paths;
        return $data;
    }

    private function sfais_scan_job_write( string $job_id, array $data ) : bool {
        $paths = $this->sfais_scan_job_paths( $job_id );
        if ( empty( $paths['job'] ) ) {
            return false;
        }
if ( isset( $data['_paths'] ) ) {
            unset( $data['_paths'] );
        }

        // JSON encode with tolerant flags to avoid "Network error" on edge-case filenames.
        $opts = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        if ( defined( 'JSON_PARTIAL_OUTPUT_ON_ERROR' ) ) {
            $opts |= JSON_PARTIAL_OUTPUT_ON_ERROR;
        }

        $json = wp_json_encode( $data, $opts );
        if ( ! is_string( $json ) ) {
            $json = json_encode( $data, $opts );
        }
        if ( ! is_string( $json ) ) {
            return false;
        }

        // Atomic-ish write: write to temp then move in place.
        $tmp = $paths['job'] . '.tmp';
        if ( ! SFAIS_FS::write( $tmp, $json ) ) {
            return false;
        }
        if ( ! SFAIS_FS::move( $tmp, $paths['job'], true ) ) {
            // Fallback (some FS backends don't support move/rename reliably).
            return SFAIS_FS::write( $paths['job'], $json );
        }

        return true;
    }

    private function sfais_scan_job_read_list_lines( string $list_path ) : array {
        $raw = SFAIS_FS::read( $list_path );
        if ( ! is_string( $raw ) || $raw === '' ) {
            return [];
        }
        $lines = preg_split( "/\r\n|\n|\r/", $raw );
        if ( ! is_array( $lines ) ) {
            return [];
        }
        // Remove trailing empty lines.
        while ( $lines && end( $lines ) === '' ) {
            array_pop( $lines );
        }
        return $lines;
    }



    /* ----------------------------------------------------------------
     * ✅ Scan-job housekeeping (retention + cleanup)
     * ---------------------------------------------------------------- */

    /**
     * Best-effort pruning of scan-job artifacts.
     *
     * This is a hard safety cap to ensure scan-job artifacts stored under the plugin folder inside the uploads directory (wp_upload_dir())
     * cannot grow without bound (e.g., interrupted requests, fatal errors, or abandoned jobs).
     */
    private function sfais_prune_scan_jobs_dir(){
        $dir = $this->sfais_scan_jobs_dir();
        if ( ! is_dir( $dir ) ) {
            return;
        }

        $now      = time();
        $max_age  = 2 * DAY_IN_SECONDS; // keep at most 48h of abandoned artifacts
        $keep_max = 5;                  // hard cap: keep only the newest 5 jobs per type (core + ai)

        $jobs = [
            'core' => [],
            'ai'   => [],
        ];

        try {
            foreach ( new DirectoryIterator( $dir ) as $f ) {
                if ( ! $f->isFile() ) {
                    continue;
                }

                $name = $f->getFilename();

                // Only touch our own job artifacts. 1.8.15: also <job>.json.tmp (left by an interrupted write).
                if ( ! preg_match( '/^(sfais_(core|ai)_[a-z0-9\-]+)\.(json|list|json\.tmp|tmp)$/i', $name, $m ) ) {
                    continue;
                }

                $job_id = $m[1];
                $type   = strtolower( $m[2] );
                $path   = $f->getPathname();
                $mtime  = (int) $f->getMTime();

                if ( ! isset( $jobs[ $type ][ $job_id ] ) ) {
                    $jobs[ $type ][ $job_id ] = [
                        'mtime' => $mtime,
                        'paths' => [],
                    ];
                }

                $jobs[ $type ][ $job_id ]['paths'][] = $path;
                if ( $mtime > (int) $jobs[ $type ][ $job_id ]['mtime'] ) {
                    $jobs[ $type ][ $job_id ]['mtime'] = $mtime;
                }
            }
        } catch ( Exception $e ) {
            // Silent: pruning is best-effort.
            return;
        }

        foreach ( [ 'core', 'ai' ] as $type ) {
            if ( empty( $jobs[ $type ] ) ) {
                continue;
            }

            // Age-based pruning (stale jobs).
            foreach ( $jobs[ $type ] as $job_id => $meta ) {
                $mtime = (int) ( $meta['mtime'] ?? 0 );
                if ( $mtime > 0 && ( $now - $mtime ) > $max_age ) {
                    foreach ( (array) ( $meta['paths'] ?? [] ) as $p ) {
                        SFAIS_FS::delete( $p );
                    }
                    unset( $jobs[ $type ][ $job_id ] );
                }
            }

            if ( count( $jobs[ $type ] ) <= $keep_max ) {
                continue;
            }

            // Sort jobs by newest mtime first.
            uasort( $jobs[ $type ], static function( $a, $b ) {
                return ( (int) ( $b['mtime'] ?? 0 ) <=> (int) ( $a['mtime'] ?? 0 ) );
            } );

            $i = 0;
            foreach ( $jobs[ $type ] as $job_id => $meta ) {
                $i++;
                if ( $i <= $keep_max ) {
                    continue;
                }
                foreach ( (array) ( $meta['paths'] ?? [] ) as $p ) {
                    SFAIS_FS::delete( $p );
                }
            }
        }
    }

    public function ajax_scan_core_start() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall') ] );
        }
        check_ajax_referer( 'sfais_scanner_nonce', 'nonce' );

        // Core checksums retrieval (version + locale aware).
        $ver    = get_bloginfo( 'version' );
        $locale = get_locale();
        $checksums = null;

        if ( function_exists( 'wp_get_core_checksums' ) ) {
            $checksums = wp_get_core_checksums( $ver, $locale );
        } else {
            $update_inc = ABSPATH . 'wp-admin/includes/update.php';
            if ( file_exists( $update_inc ) && is_readable( $update_inc ) ) {
                require_once $update_inc;
                if ( function_exists( 'wp_get_core_checksums' ) ) {
                    $checksums = wp_get_core_checksums( $ver, $locale );
                }
            }
        }

        if ( ! is_array( $checksums ) || empty( $checksums ) ) {
            // Direct API fallback.
            $api = add_query_arg(
                [
                    'version' => $ver,
                    'locale'  => $locale,
                ],
                'https://api.wordpress.org/core/checksums/1.0/'
            );
            $resp = wp_remote_get( $api, [ 'timeout' => 15 ] );
            if ( is_wp_error( $resp ) ) {
                wp_send_json_error( [ 'message' => __( 'Could not fetch WordPress core checksums.', 'maroon-horizon-smart-firewall') ] );
            }
            $body = wp_remote_retrieve_body( $resp );
            $json = json_decode( $body, true );
            if ( is_array( $json ) && isset( $json['checksums'] ) && is_array( $json['checksums'] ) ) {
                $checksums = $json['checksums'];
            }
        }

        if ( ! is_array( $checksums ) || empty( $checksums ) ) {
            wp_send_json_error( [ 'message' => __( 'Could not fetch WordPress core checksums.', 'maroon-horizon-smart-firewall') ] );
        }

        $dir = $this->sfais_scan_jobs_dir();
        SFAIS_FS::mkdir_p( $dir );

        // Defensive: prevent unbounded growth of scan-job artifacts.
        $this->sfais_prune_scan_jobs_dir();

        $job_id = 'sfais_core_' . str_replace( '-', '', (string) wp_generate_uuid4() );
        $paths  = $this->sfais_scan_job_paths( $job_id );

        $lines = [];
        foreach ( $checksums as $rel => $md5 ) {
            $rel = ltrim( (string) $rel, '/\\' );
            // wp-content/ is not core: its bundled extras (Akismet, Hello Dolly, default themes) may be deleted on purpose (1.8.4).
            // 1.8.5: same for WordPress's documentation / sample files - deleting readme.html is common hardening (it shows the version).
            if ( $rel === '' || 0 === strpos( $rel, 'wp-content/' ) || in_array( $rel, array( 'readme.html', 'license.txt', 'wp-config-sample.php' ), true ) ) {
                continue;
            }
            $lines[] = $rel . "\t" . (string) $md5;
        }
        $total = count( $lines );
        if ( $total < 1 ) {
            wp_send_json_error( [ 'message' => __( 'No core files to scan.', 'maroon-horizon-smart-firewall') ] );
        }

        if ( ! SFAIS_FS::write( $paths['list'], implode( "\n", $lines ) . "\n" ) ) {
            wp_send_json_error( [ 'message' => __( 'Could not initialize scan job.', 'maroon-horizon-smart-firewall') ] );
        }

        $job = [
            'id'         => $job_id,
            'type'       => 'core',
            'status'     => 'running',
            'cursor'     => 0,
            'processed'  => 0,
            'total'      => $total,
            'started_at' => microtime( true ),
            'cancel'     => false,
            'counts'     => [
                'clean'    => 0,
                'modified' => 0,
                'missing'  => 0,
                'unknown'  => 0,
                'ignored'  => 0,   // 1.8.13
            ],
            // Store only non-clean items (UI only renders problematic rows).
            'items'      => [],
        ];

        if ( ! $this->sfais_scan_job_write( $job_id, $job ) ) {
            wp_send_json_error( [ 'message' => __( 'Could not initialize scan job.', 'maroon-horizon-smart-firewall') ] );
        }

        wp_send_json_success( [
            'job_id' => $job_id,
            'total'  => $total,
            'status' => 'running',
        ] );
    }

    public function ajax_scan_core_tick() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall') ] );
        }
        check_ajax_referer( 'sfais_scanner_nonce', 'nonce' );

        $job_id = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
        if ( $job_id === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing job id.', 'maroon-horizon-smart-firewall') ] );
        }

        $job = $this->sfais_scan_job_read( $job_id );
        if ( ! is_array( $job ) || empty( $job['type'] ) || $job['type'] !== 'core' ) {
            wp_send_json_error( [ 'message' => __( 'Scan job not found.', 'maroon-horizon-smart-firewall') ] );
        }

        if ( ! empty( $job['cancel'] ) ) {
            $job['status'] = 'cancelled';
            $this->sfais_scan_job_write( $job_id, $job );

            // Delete scan-job artifacts immediately (list can be large).
            $paths = $job['_paths'] ?? $this->sfais_scan_job_paths( $job_id );
            if ( ! empty( $paths['list'] ) && file_exists( $paths['list'] ) ) {
                SFAIS_FS::delete( $paths['list'] );
            }
            $tmp = $paths['job'] . '.tmp';
            if ( $tmp && file_exists( $tmp ) ) {
                SFAIS_FS::delete( $tmp );
            }
            if ( ! empty( $paths['job'] ) && file_exists( $paths['job'] ) ) {
                SFAIS_FS::delete( $paths['job'] );
            }
            wp_send_json_success( [
                'status'    => 'cancelled',
                'progress'  => 0,
                'processed' => (int) ( $job['processed'] ?? 0 ),
                'total'     => (int) ( $job['total'] ?? 0 ),
                'message'   => __( 'Scan cancelled.', 'maroon-horizon-smart-firewall'),
            ] );
        }

        if ( ! empty( $job['status'] ) && in_array( $job['status'], [ 'done', 'cancelled', 'error' ], true ) ) {
            $rep = ( isset( $job['report'] ) && is_array( $job['report'] ) ) ? $job['report'] : null;
            if ( is_array( $rep ) ) {
                $rep = $this->sfais_make_json_safe( $rep );
            }

            wp_send_json_success( [
                'status'    => $job['status'],
                'progress'  => 100,
                'processed' => (int) ( $job['processed'] ?? 0 ),
                'total'     => (int) ( $job['total'] ?? 0 ),
                'report'    => $rep,
            ] );
        }

        $paths = $job['_paths'] ?? $this->sfais_scan_job_paths( $job_id );
        $list  = $this->sfais_scan_job_read_list_lines( $paths['list'] );
        $total = (int) ( $job['total'] ?? count( $list ) );
        $cursor = (int) ( $job['cursor'] ?? 0 );

        $t0 = microtime( true );
        $max = 250;                 // safety cap per request
        $time_budget = 0.65;        // seconds per request

        $counts = isset( $job['counts'] ) && is_array( $job['counts'] ) ? $job['counts'] : [ 'clean' => 0, 'modified' => 0, 'missing' => 0, 'unknown' => 0 ];
        $items  = isset( $job['items'] ) && is_array( $job['items'] ) ? $job['items'] : [];

        $processed_this = 0;

        // 1.8.13: honour the ignore list (it was only read by the old synchronous scan). An ignore holds while the file is
        // unchanged: same MD5 as when it was ignored, or still missing for a "missing" ignore.
        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $ign_idx = SFAIS_Scanner::ignore_index();
        $counts['ignored'] = (int) ( $counts['ignored'] ?? 0 );

        while ( $cursor < $total && $processed_this < $max && ( microtime( true ) - $t0 ) < $time_budget ) {
            $line = isset( $list[ $cursor ] ) ? (string) $list[ $cursor ] : '';
            $cursor++;
            $processed_this++;

            if ( $line === '' ) {
                continue;
            }
            $parts = explode( "\t", $line );
            $rel   = isset( $parts[0] ) ? ltrim( (string) $parts[0], '/\\' ) : '';
            $md5   = isset( $parts[1] ) ? strtolower( (string) $parts[1] ) : '';
            if ( $rel === '' ) {
                continue;
            }

            $abs = wp_normalize_path( ABSPATH . $rel );

            if ( ! file_exists( $abs ) ) {
                if ( SFAIS_Scanner::is_ignored_now( $ign_idx, $rel, $abs, 'missing' ) ) {
                    $counts['ignored']++;
                    continue;
                }
                $counts['missing']++;
                $items[] = [ 'file' => $rel, 'status' => 'missing', 'reason' => 'File missing' ];
                continue;
            }

            if ( ! is_readable( $abs ) ) {
                if ( SFAIS_Scanner::is_ignored_now( $ign_idx, $rel, $abs, '' ) ) {
                    $counts['ignored']++;
                    continue;
                }
                $counts['unknown']++;
                $items[] = [ 'file' => $rel, 'status' => 'unknown', 'reason' => 'Unreadable' ];
                continue;
            }

            $hash = @md5_file( $abs );
            if ( ! is_string( $hash ) || $hash === '' ) {
                if ( SFAIS_Scanner::is_ignored_now( $ign_idx, $rel, $abs, '' ) ) {
                    $counts['ignored']++;
                    continue;
                }
                $counts['unknown']++;
                $items[] = [ 'file' => $rel, 'status' => 'unknown', 'reason' => 'Unreadable' ];
                continue;
            }

            $hash = strtolower( $hash );

            if ( $md5 !== '' && $hash === $md5 ) {
                $counts['clean']++;
            } elseif ( SFAIS_Scanner::is_ignored_now( $ign_idx, $rel, $abs, $hash ) ) {
                $counts['ignored']++;
            } else {
                $counts['modified']++;
                $items[] = [ 'file' => $rel, 'status' => 'modified', 'reason' => 'Checksum mismatch' ];
            }
        }

        $job['cursor']    = $cursor;
        $job['processed'] = $cursor;
        $job['counts']    = $counts;
        $job['items']     = $items;

        $progress = ( $total > 0 ) ? (int) floor( ( $cursor / $total ) * 100 ) : 0;
        if ( $progress > 100 ) { $progress = 100; }
        // Defensive: never emit 100% for a running job (avoids UI showing 100% before we have a final report payload).
        if ( $cursor < $total && $progress >= 100 ) { $progress = 99; }

        if ( $cursor >= $total ) {
            require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
            $scanner = new SFAIS_Scanner();

            $duration_ms = (int) round( ( microtime( true ) - (float) ( $job['started_at'] ?? microtime( true ) ) ) * 1000 );

            $report = [
                'type'    => 'core',
                'summary' => [
                    'modified' => (int) ( $counts['modified'] ?? 0 ),
                    'missing'  => (int) ( $counts['missing'] ?? 0 ),
                    'unknown'  => (int) ( $counts['unknown'] ?? 0 ),
                    'clean'    => (int) ( $counts['clean'] ?? 0 ),
                    'ignored'  => (int) ( $counts['ignored'] ?? 0 ),   // 1.8.13
                ],
                'items'   => $items,
                'meta'    => [
                    'engine'       => 'core_integrity',
                    'duration_ms'  => $duration_ms,
                    'generated_at' => current_time( 'mysql' ),
                ],
            ];

            $scanner->save_report( $report, true );

            $job['status'] = 'done';
            $job['report'] = $report;
            $this->sfais_scan_job_write( $job_id, $job );

            // List file is no longer needed once the report is generated.
            $paths = $job['_paths'] ?? $this->sfais_scan_job_paths( $job_id );
            if ( ! empty( $paths['list'] ) && file_exists( $paths['list'] ) ) {
                SFAIS_FS::delete( $paths['list'] );
            }
            // Delete scan-job JSON artifacts to prevent uploads bloat.
            $tmp = $paths['job'] . '.tmp';
            if ( $tmp && file_exists( $tmp ) ) {
                SFAIS_FS::delete( $tmp );
            }
            if ( ! empty( $paths['job'] ) && file_exists( $paths['job'] ) ) {
                SFAIS_FS::delete( $paths['job'] );
            }

            wp_send_json_success( [
                'status'    => 'done',
                'progress'  => 100,
                'processed' => $total,
                'total'     => $total,
                'report'    => $report,
                'message'   => __( 'Scan completed.', 'maroon-horizon-smart-firewall'),
            ] );
        }

        $this->sfais_scan_job_write( $job_id, $job );

        wp_send_json_success( [
            'status'    => 'running',
            'progress'  => $progress,
            'processed' => $cursor,
            'total'     => $total,
        ] );
    }

    public function ajax_scan_core_cancel() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall') ] );
        }
        check_ajax_referer( 'sfais_scanner_nonce', 'nonce' );

        $job_id = isset( $_POST['job_id'] ) ? sanitize_text_field( wp_unslash( $_POST['job_id'] ) ) : '';
        if ( $job_id === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing job id.', 'maroon-horizon-smart-firewall') ] );
        }

        $job = $this->sfais_scan_job_read( $job_id );
        if ( ! is_array( $job ) || ( $job['type'] ?? '' ) !== 'core' ) {
            wp_send_json_error( [ 'message' => __( 'Scan job not found.', 'maroon-horizon-smart-firewall') ] );
        }

        $job['cancel'] = true;
        $this->sfais_scan_job_write( $job_id, $job );

        wp_send_json_success( [ 'status' => 'cancelling' ] );
    }

    public function ajax_scan_uploads() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $uploads_basedir = function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : ( wp_upload_dir( null, false )['basedir'] ?? '' );
        if ( is_wp_error( $uploads_basedir ) ) {
            $uploads_basedir = '';
        }
        $theme_root = function_exists( 'get_theme_root' ) ? (string) get_theme_root() : '';

        $paths = array_values( array_filter( [ $uploads_basedir, $theme_root ] ) );

        $result  = $scanner->scan_paths($paths, false, true);

        if (!empty($result['success'])) wp_send_json_success($result);
        wp_send_json_error($result);
    }



    public function ajax_quarantine_move() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $rel = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $rel ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $reason  = $scanner->report_reason( $rel );   // 1.8.15: what the scan found, not "Manual action"
        $result  = $scanner->quarantine_move( $rel, '' !== $reason ? $reason : 'Moved by an admin' );

        if (!empty($result['success'])) wp_send_json_success($result);
        wp_send_json_error($result);
    }

    public function ajax_quarantine_delete() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $rel = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $rel ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $result  = $scanner->delete_permanently($rel);

        if (!empty($result['success'])) wp_send_json_success($result);
        wp_send_json_error($result);
    }

    public function ajax_quarantine_ignore() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $rel = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $rel ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $result  = $scanner->ignore_file($rel);

        if (!empty($result['success'])) wp_send_json_success($result);
        wp_send_json_error($result);
    }

    function ajax_quarantine_ignore_bulk() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

		$files_raw = [];
		if ( isset( $_POST['files'] ) ) {
			if ( is_string( $_POST['files'] ) ) {
				$files_json = sanitize_textarea_field( wp_unslash( $_POST['files'] ) );
				$decoded    = json_decode( $files_json, true );
				$files_raw  = is_array( $decoded ) ? $decoded : [];
			} elseif ( is_array( $_POST['files'] ) ) {
				$files_raw = array_map( 'sanitize_text_field', wp_unslash( $_POST['files'] ) );
			}
		}

		// Normalize and sanitize each submitted file path (defense in depth).
		$files = array_values( array_filter( array_map( 'sanitize_text_field', array_map( 'strval', (array) $files_raw ) ) ) );

        // Hard cap to prevent abuse.
        $files = array_slice($files, 0, 500);

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();

        // 1.8.13: one option write + one report update for the whole batch (SFAIS_Scanner::ignore_files()).
        $rels = [];
        foreach ($files as $f) {
            $rel = $this->sanitize_relpath( (string) $f );
            if ( '' !== $rel ) {
                $rels[] = $rel;
            }
        }
        $res     = $scanner->ignore_files( $rels );
        $ignored = count( $res['ignored'] );
        $failed  = $res['failed'];

        $payload = [
            'ignored' => $ignored,
            'failed'  => $failed,
            'message' => sprintf(
                /* translators: 1: ignored count, 2: failed count */
                __( 'Ignored %1$d file(s). Failed: %2$d.', 'maroon-horizon-smart-firewall'),
                $ignored,
                count($failed)
            )
        ];

        if ($ignored > 0) wp_send_json_success($payload);
        wp_send_json_error($payload);
    }


    public function ajax_quarantine_list() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $res     = $scanner->list_quarantine();

        if (!empty($res['success'])) wp_send_json_success($res);
        wp_send_json_error($res);
    }

    public function ajax_quarantine_restore() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $file = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $file ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        if (!$file) wp_send_json_error(['message' => __( 'Missing file parameter.', 'maroon-horizon-smart-firewall')]);

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $res     = $scanner->restore_from_quarantine($file);

        if (!empty($res['success'])) wp_send_json_success($res);
        wp_send_json_error($res);
    }

    public function ajax_quarantine_remove() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $file = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $file ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        if (!$file) wp_send_json_error(['message' => __( 'Missing file parameter.', 'maroon-horizon-smart-firewall')]);

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $res     = $scanner->delete_from_quarantine($file);

        if (!empty($res['success'])) wp_send_json_success($res);
        wp_send_json_error($res);
    }

    /**
     * 1.8.13: Ignored files list (Scanner tab). Entries whose file no longer exists are dropped.
     */
    public function ajax_scanner_ignored_list() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        wp_send_json_success( $scanner->list_ignored() );
    }

    /**
     * 1.8.13: Un-ignore one file (the next scan checks it again).
     */
    public function ajax_scanner_unignore() {
        if (!current_user_can('manage_options')) wp_send_json_error(['message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall')]);
        check_ajax_referer('sfais_scanner_nonce', 'nonce');

        $rel = $this->sanitize_relpath( sanitize_text_field( wp_unslash( $_POST['file'] ?? '' ) ) );
        if ( '' === $rel ) {
            wp_send_json_error( [ 'message' => __( 'Invalid file parameter.', 'maroon-horizon-smart-firewall' ) ] );
        }
        require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        $scanner = new SFAIS_Scanner();
        $res     = $scanner->unignore_file( $rel );

        if (!empty($res['success'])) wp_send_json_success($res);
        wp_send_json_error($res);
    }

    /* ----------------------------------------------------------------
     * ✅ License & Updates — safe fallbacks (no fatal -> no Network error)
     * ---------------------------------------------------------------- */




    /* ----------------------------------------------------------------
     * Pass-through helpers
     * ---------------------------------------------------------------- */
    public function detect_server_type() { return $this->ip_manager->detect_server_type(); }
    public function block_ip($ip)        { return $this->ip_manager->block_ip($ip); }
    public function unblock_ip($ip)      { return $this->ip_manager->unblock_ip($ip); }
    public function get_blocked_ips()    { return $this->ip_manager->get_blocked_ips(); }
    public function get_htaccess_ips()   { return $this->ip_manager->get_htaccess_ips(); }
    public function get_db_ips()         { return $this->ip_manager->get_db_ips(); }   // 1.8.13
    public function upgrade_htaccess_block() { $this->ip_manager->upgrade_htaccess_block(); }

    public function run_quick_check() {
        $sections  = $this->security_check->run_quick_check();
        $rating    = $this->security_check->compute_overall_rating($sections);
        $timestamp = time();   // 1.8.13: real UTC time - shown with wp_date() (current_time() is a local 'fake' timestamp)

        // 1.8.15: Recent activity gets a line when the score really changes (the check runs on every plugin screen)
        $previous = get_option('sfais_last_quick_rating');
        $old      = ( is_array( $previous ) && isset( $previous['score'] ) ) ? (int) $previous['score'] : null;
        if ( null === $old ) {
            /* translators: %d: score */
            do_action( 'mhsf_activity', 'check', sprintf( __( 'Security check · %d/100', 'maroon-horizon-smart-firewall' ), (int) ( $rating['score'] ?? 0 ) ) );
        } elseif ( $old !== (int) ( $rating['score'] ?? 0 ) ) {
            /* translators: 1: new score, 2: old score */
            do_action( 'mhsf_activity', 'check', sprintf( __( 'Security score changed · %1$d/100 (was %2$d)', 'maroon-horizon-smart-firewall' ), (int) ( $rating['score'] ?? 0 ), $old ) );
        }

        update_option('sfais_last_quick_check', $timestamp, false);
        update_option('sfais_last_quick_rating', $rating, false);

        return [
            'sections'  => $sections,
            'rating'    => $rating,
            'timestamp' => $timestamp,
        ];
    }

    /**
     * AJAX: Toggle Dashboard manual confirmations (Backup/User Security flags).
     * This endpoint must exist in both FREE + PRO builds because the Dashboard tab is fully functional in FREE.
     */
    public function ajax_toggle_manual_flag() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_send_json_error( [ 'message' => __( 'Unauthorized', 'maroon-horizon-smart-firewall' ) ] );
        }

        $flag = sanitize_key( wp_unslash( $_POST['flag'] ?? '' ) );
        if ( $flag === '' ) {
            wp_send_json_error( [ 'message' => __( 'Missing flag.', 'maroon-horizon-smart-firewall' ) ] );
        }

        $map = [
            'backup_found' => [
                'nonce_action' => 'sfais_backup_flags',
                'nonce_field'  => 'sfais_backup_nonce',
                'opt'          => 'sfais_backup_manual_found',
                'section'      => 'Backup & Maintenance',
                'label'        => 'Backup Found',
                'set_text'     => '✅ Mark as configured',
                'clear_text'   => '✖ Clear manual confirmation',
                'post_key'     => 'sfais_backup_action',
                'set_action'   => 'backup_found_set',
                'clear_action' => 'backup_found_clear',
            ],
            'backup_age' => [
                'nonce_action' => 'sfais_backup_flags',
                'nonce_field'  => 'sfais_backup_nonce',
                'opt'          => 'sfais_backup_manual_age_ok',
                'section'      => 'Backup & Maintenance',
                'label'        => 'Backup Age',
                'set_text'     => '✅ Mark as recent',
                'clear_text'   => '✖ Clear manual confirmation',
                'post_key'     => 'sfais_backup_action',
                'set_action'   => 'backup_age_set',
                'clear_action' => 'backup_age_clear',
            ],
            'strong_passwords' => [
                'nonce_action' => 'sfais_usersec_flags',
                'nonce_field'  => 'sfais_usersec_nonce',
                'opt'          => 'sfais_manual_strong_passwords',
                'section'      => 'User Security',
                'label'        => 'Strong Password Policy',
                'set_text'     => '✅ Mark as enforced',
                'clear_text'   => '✖ Clear manual confirmation',
                'post_key'     => 'sfais_usersec_action',
                'set_action'   => 'strong_passwords_set',
                'clear_action' => 'strong_passwords_clear',
            ],
            'two_factor' => [
                'nonce_action' => 'sfais_usersec_flags',
                'nonce_field'  => 'sfais_usersec_nonce',
                'opt'          => 'sfais_manual_2fa_enabled',
                'section'      => 'User Security',
                'label'        => 'Two-Factor Authentication (2FA)',
                'set_text'     => '✅ Mark as enabled',
                'clear_text'   => '✖ Clear manual confirmation',
                'post_key'     => 'sfais_usersec_action',
                'set_action'   => 'two_factor_set',
                'clear_action' => 'two_factor_clear',
            ],
        ];

        if ( ! isset( $map[ $flag ] ) ) {
            wp_send_json_error( [ 'message' => __( 'Unknown flag.', 'maroon-horizon-smart-firewall' ) ] );
        }

        $cfg = $map[ $flag ];

        $nonce = sanitize_text_field( wp_unslash( $_POST[ $cfg['nonce_field'] ] ?? '' ) );
        if ( ! $nonce || ! wp_verify_nonce( $nonce, $cfg['nonce_action'] ) ) {
            wp_send_json_error( [ 'message' => __( 'Security check failed. Please refresh the page.', 'maroon-horizon-smart-firewall' ) ] );
        }

        // 1.8.13: do what the clicked button says (set / clear) - a plain toggle turned a stale "Mark as ..." into a clear
        $posted  = isset( $_POST[ $cfg['post_key'] ] ) ? sanitize_key( wp_unslash( $_POST[ $cfg['post_key'] ] ) ) : '';
        $enabled = (bool) get_option( $cfg['opt'], false );
        $enable  = ( $posted === $cfg['set_action'] ) ? true : ( ( $posted === $cfg['clear_action'] ) ? false : ! $enabled );
        if ( $enable ) {
            update_option( $cfg['opt'], 1, false );
            $enabled = true;
        } else {
            delete_option( $cfg['opt'] );
            $enabled = false;
        }

        // Refresh payload used by the Dashboard (sections + rating + timestamp).
        $quick    = $this->run_quick_check();
        $sections = isset( $quick['sections'] ) && is_array( $quick['sections'] ) ? $quick['sections'] : [];
        $rating   = isset( $quick['rating'] ) && is_array( $quick['rating'] ) ? $quick['rating'] : [
            'grade'   => 'N/A',
            'score'   => 0,
            'label'   => 'No data',
            'summary' => '',
        ];
        $ts = isset( $quick['timestamp'] ) ? (int) $quick['timestamp'] : ( function_exists( 'current_time' ) ? (int) current_time( 'timestamp' ) : time() );

        $last_checked_text = $ts
            ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts )
            : __( 'Not run yet', 'maroon-horizon-smart-firewall' );

        // Locate the updated row item in sections.
        $found_item = null;
        foreach ( (array) $sections as $sec ) {
            $title = $sec['title'] ?? '';
            if ( $title && stripos( $title, $cfg['section'] ) !== false ) {
                $items = $sec['items'] ?? [];
                foreach ( (array) $items as $it ) {
                    $lab = $it['label'] ?? '';
                    if ( $lab && stripos( $lab, $cfg['label'] ) !== false ) {
                        $found_item = $it;
                        break 2;
                    }
                }
            }
        }

        $badge_html = static function( $status ) {
            $map2 = [
                'ok'   => [ '🟢', 'ok',   'OK' ],
                'warn' => [ '🟡', 'warn', 'Warning' ],
                'crit' => [ '🔴', 'crit', 'Critical' ],
                'info' => [ '🔵', 'info', 'Info' ],
            ];
            $m = $map2[ $status ] ?? $map2['info'];
            return '<span class="sfais-badge ' . esc_attr( $m[1] ) . '">' . esc_html( $m[0] . ' ' . $m[2] ) . '</span>';
        };

        $item_status  = $found_item['status']  ?? 'info';
        $item_value   = $found_item['value']   ?? '';
        $item_message = $found_item['message'] ?? '';

        if ( $item_message === '' ) {
            if ( stripos( $cfg['label'], 'Strong Password Policy' ) !== false ) {
                $item_message = 'Enforce strong admin passwords to reduce account compromise risk. If you already enforce this via a security plugin/host policy, you can mark it as confirmed.';
            } elseif ( stripos( $cfg['label'], 'Two-Factor Authentication (2FA)' ) !== false ) {
                $item_message = 'Two-factor authentication significantly reduces the risk of account takeovers. If you have 2FA enabled via a plugin or hosting provider, you can mark it as confirmed.';
            } elseif ( stripos( $cfg['label'], 'Backup Found' ) !== false ) {
                $item_message = 'Backups protect you from data loss and malware incidents. Ensure backups run regularly and are stored off-site, then confirm once configured.';
            } elseif ( stripos( $cfg['label'], 'Backup Age' ) !== false ) {
                $item_message = 'Backups should be recent. If you verify your last successful backup is within an acceptable window (e.g., 7 days), mark it as confirmed.';
            }
        }

        $next_label  = $enabled ? $cfg['clear_text'] : $cfg['set_text'];
        $next_action = $enabled ? $cfg['clear_action'] : $cfg['set_action'];

        $grade       = strtoupper( (string) ( $rating['grade'] ?? 'N/A' ) );
        $grade_class = preg_replace( '/[^a-z]/', '', strtolower( $grade ) );
        $score       = isset( $rating['score'] ) ? (int) $rating['score'] : 0;
        $label       = (string) ( $rating['label'] ?? 'No data' );
        $summary     = (string) ( $rating['summary'] ?? '' );

        wp_send_json_success( [
            'flag'        => $flag,
            'enabled'     => $enabled,
            'next_label'  => $next_label,
            'next_action' => $next_action,
            'post_key'    => $cfg['post_key'],
            'badge_html'  => wp_kses( $badge_html( $item_status ), [ 'span' => [ 'class' => true ] ] ),
            'value'       => (string) $item_value,
            'message'     => (string) $item_message,
            'rating'      => [
                'grade'       => $grade,
                'grade_class' => $grade_class,
                'score'       => $score,
                'label'       => $label,
                'summary'     => $summary,
            ],
            'last_checked_text' => $last_checked_text,
            // 1.8.13: whole Dashboard redrawn (recommended fixes, shields, activity) - not only this row
            'dashboard_html'    => class_exists( 'SFAIS_Admin_UI' ) ? SFAIS_Admin_UI::dashboard_refresh_payload()['dashboard_html'] : '',
        ] );
    }

}

new SFAIS_Functions();
