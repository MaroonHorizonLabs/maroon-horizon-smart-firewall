<?php
if (!defined('ABSPATH')) exit;

class SFAIS_IP_Manager {

    private $option_key = 'sfais_blocked_ips';

    /** Legacy manual block: "# BEGIN SFAIS" / "# END SFAIS" alone on their lines (not the blocks of other features). */
    const LEGACY_BLOCK_RX = '/^# BEGIN SFAIS[ \t]*\R(.*?)^# END SFAIS[ \t]*(?:\R|\z)/ms';

    /** 1.8.15: most manual addresses the IP Blocker holds (each one is also three lines in .htaccess). */
    const MAX_MANUAL_IPS = 1000;

    /** Result of the last .htaccess write: '', 'ok', 'unverified', 'restored' or 'failed' (see SFAIS_FS::write_htaccess_checked). */
    private $last_htaccess_status = '';

    /**
     * 1.8.13: after an unblock that unlocked the locked .htaccess for a moment (1.8.11): '' (not unlocked), 'ok' (locked
     * again with the same permissions) or 'failed' (could not be locked again - the message says so).
     */
    private $relock_status = '';

    /**
     * 1.8.12 (Vlad option A): Cloudflare's published edge addresses (https://www.cloudflare.com/ips/, last changed
     * 28 Sep 2023). Shipped inside the plugin and updated with plugin releases - nothing is downloaded.
     */
    const CLOUDFLARE_RANGES = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    ];

    /** True when the current request arrived through Cloudflare (set by the client-IP resolver). */
    private static $via_cloudflare = false;

    public function __construct() {
        // Ensure stored manual list has no duplicates on load
        // 1.8.13: and every address in its one canonical form (IPv6 "2001:DB8:0::1" -> "2001:db8::1"); written only when
        // something changed.
        $ips = get_option($this->option_key, []);
        if (is_array($ips)) {
            $clean = $this->normalize_list( $ips );
            if ( $clean !== $ips ) {
                update_option($this->option_key, $clean);
            }
        }
    }

    /**
     * 1.8.13: one canonical form per address, so the same IP is always stored, compared and written the same way
     * (IPv6 compressed + lowercase via inet_pton/inet_ntop).
     *
     * @param mixed $ip
     * @return string Canonical address, '' when it is not one valid IP address.
     */
    public function normalize_ip( $ip ) {
        $ip = trim( (string) $ip );
        if ( $ip === '' || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return '';
        }
        $bin = inet_pton( $ip );
        if ( $bin === false ) {
            return '';
        }
        $out = inet_ntop( $bin );
        return is_string( $out ) ? strtolower( $out ) : '';
    }

    /** 1.8.13: canonical, unique, valid addresses only (keeps the order). */
    private function normalize_list( $list ) {
        $out = [];
        foreach ( (array) $list as $ip ) {
            $n = $this->normalize_ip( $ip );
            if ( $n !== '' && ! in_array( $n, $out, true ) ) {
                $out[] = $n;
            }
        }
        return $out;
    }

    /**
     * 1.8.13: the address typed into the IP Blocker, or why it can't be used. Exactly ONE address is accepted - a range
     * ("1.2.3.0/24", "1.2.3.4-1.2.3.9") or a list is refused instead of quietly blocking only its first address.
     *
     * @return array{0:string,1:string} [ canonical IP or '', error message or '' ]
     */
    private function parse_ip_input( $str ) {
        $s = trim( (string) $str );
        if ( $s !== '' && strpos( $s, '/' ) === false && preg_match( '/^\[([^\]]+)\]$/', $s, $m ) ) {
            $s = trim( $m[1] );   // [2001:db8::1]
        }
        $ip = $this->normalize_ip( $s );
        if ( $ip !== '' ) {
            return [ $ip, '' ];
        }
        $range_msg = __( 'Ranges are not supported yet - enter one IP address.', 'maroon-horizon-smart-firewall' );
        if ( strpos( $s, '/' ) !== false ) {
            return [ '', $range_msg ];
        }
        $valid = 0;
        foreach ( (array) preg_split( '/[\s,;\-]+/', $s, -1, PREG_SPLIT_NO_EMPTY ) as $part ) {
            if ( $this->normalize_ip( $part ) !== '' ) {
                ++$valid;
            }
        }
        if ( $valid > 1 ) {
            return [ '', strpos( $s, '-' ) !== false ? $range_msg : __( 'Enter one IP address at a time.', 'maroon-horizon-smart-firewall' ) ];
        }
        return [ '', '' ];
    }

    /** 1.8.13: the WordPress firewall list (sfais_blocked_ips), canonical. */
    public function get_db_ips() {
        $ips = get_option( $this->option_key, [] );
        return $this->normalize_list( is_array( $ips ) ? $ips : [] );
    }

    public function detect_server_type() {
        $server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
        if (strpos($server, 'apache') !== false || strpos($server, 'litespeed') !== false) return 'apache';
        if (strpos($server, 'nginx') !== false) return 'nginx';
        return 'other';
    }

    /**
     * Block an IP. Always adds it to the WordPress-level firewall (DB list); on Apache/LiteSpeed also writes the
     * server-level rule into the MHSF block of .htaccess when possible. 1.8.9: refuses the admin's own address, the
     * proxy/CDN address and this server's own addresses, and every message says plainly where the IP is blocked.
     */
    public function block_ip( $ip ) {
        // 1.8.13: exactly one address, canonical (a range or a list is refused, never cut to its first address).
        list( $ip, $input_error ) = $this->parse_ip_input( $ip );
        if ( $input_error !== '' ) {
            return [ 'status' => false, 'message' => $input_error ];
        }
        if ( $ip === '' ) {
            return [ 'status' => false, 'message' => __( 'That is not a valid IP address. Example: 203.0.113.7', 'maroon-horizon-smart-firewall' ) ];
        }
        $this->last_htaccess_status = '';
        $this->relock_status        = '';

        $refused = $this->protected_ip_reason( $ip );
        if ( $refused !== '' ) {
            return [ 'status' => false, 'message' => $refused ];
        }

        // 1.8.15: max 1,000 addresses (the list the tab shows: WordPress firewall + server rules). An address already in
        // the list can still be blocked again (e.g. to add its missing server rule).
        $listed = $this->get_blocked_ips();
        if ( count( $listed ) >= self::MAX_MANUAL_IPS && ! in_array( $ip, $listed, true ) ) {
            return [ 'status' => false, 'message' => __( 'The IP Blocker holds up to 1,000 addresses. Unblock old ones first.', 'maroon-horizon-smart-firewall' ) ];
        }

        // Always add to the WordPress-level firewall.
        $this->save_ip( $ip );

        if ( $this->detect_server_type() !== 'apache' ) {
            /* translators: %s: IP address. */
            return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( __( '%s is blocked by the WordPress firewall. This server does not use .htaccess, so no server rule is needed.', 'maroon-horizon-smart-firewall' ), $ip ) ];
        }

        if ( $this->update_htaccess( $ip ) ) {
            // 1.8.13: written, but the site could not load its own page afterwards - say so instead of plain success.
            if ( $this->last_htaccess_status === 'unverified' ) {
                /* translators: %s: IP address. */
                return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( __( '%s is blocked by the WordPress firewall and the server rule was added to .htaccess, but the site check could not run. Open your site once to make sure it still loads.', 'maroon-horizon-smart-firewall' ), $ip ) ];
            }
            /* translators: %s: IP address. */
            return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( __( '%s is blocked on the server (.htaccess) and by the WordPress firewall.', 'maroon-horizon-smart-firewall' ), $ip ) ];
        }

        return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( '%s %s',
            /* translators: %s: IP address. */
            sprintf( __( '%s is blocked by the WordPress firewall.', 'maroon-horizon-smart-firewall' ), $ip ),
            $this->htaccess_not_written_reason()
        ) ];
    }

    /**
     * Unblock an IP from the WordPress-level firewall and from .htaccess (if possible).
     */
    public function unblock_ip( $ip ) {
        list( $ip, $input_error ) = $this->parse_ip_input( $ip );
        if ( $input_error !== '' ) {
            return [ 'status' => false, 'message' => $input_error ];
        }
        if ( $ip === '' ) {
            return [ 'status' => false, 'message' => __( 'That is not a valid IP address.', 'maroon-horizon-smart-firewall' ) ];
        }
        $this->last_htaccess_status = '';
        $this->relock_status        = '';

        // Remove from manual DB list
        // 1.8.13: every stored spelling of this address (older versions stored IPv6 as typed).
        $ips = get_option( $this->option_key, [] );
        if ( is_array( $ips ) ) {
            $keep = [];
            foreach ( $ips as $stored ) {
                if ( $this->normalize_ip( $stored ) !== $ip ) {
                    $keep[] = $stored;
                }
            }
            update_option( $this->option_key, $this->normalize_list( $keep ) );
        }

        // Remove from .htaccess if possible
        $removed = $this->remove_ip_from_htaccess( $ip );

        // 1.8.13: the re-lock result is reported, never assumed.
        $relock_msg = '';
        if ( $this->relock_status === 'ok' ) {
            $relock_msg = ' ' . __( '.htaccess was unlocked for a moment to remove the server rule and is locked again.', 'maroon-horizon-smart-firewall' );
        } elseif ( $this->relock_status === 'failed' ) {
            $relock_msg = ' ' . __( '.htaccess was unlocked for a moment, but it could not be locked again - lock it again with the Lock .htaccess button.', 'maroon-horizon-smart-firewall' );
        }

        if ( $removed === false ) {
            return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( '%s %s',
                /* translators: %s: IP address. */
                sprintf( __( '%s is no longer blocked by the WordPress firewall, but the server rule is still in .htaccess.', 'maroon-horizon-smart-firewall' ), $ip ),
                $this->htaccess_not_written_reason()
            ) . $relock_msg ];
        }

        // 1.8.13: the rule was removed, but the site could not load its own page afterwards.
        $check_msg = $this->last_htaccess_status === 'unverified'
            ? ' ' . __( 'The server rule was removed from .htaccess, but the site check could not run. Open your site once to make sure it still loads.', 'maroon-horizon-smart-firewall' )
            : '';

        /* translators: %s: IP address. */
        return [ 'status' => true, 'ip' => $ip, 'message' => sprintf( __( '%s is unblocked and can visit the site again.', 'maroon-horizon-smart-firewall' ), $ip ) . $relock_msg . $check_msg ];
    }

    /**
     * Why the last .htaccess change did not happen, in plain words.
     */
    private function htaccess_not_written_reason() {
        if ( $this->last_htaccess_status === 'restored' ) {
            return __( 'The server rejected the changed .htaccess, so the plugin put the previous file back at once - your site stayed online.', 'maroon-horizon-smart-firewall' );
        }
        if ( $this->relock_status !== '' ) {
            // 1.8.13: it was unlocked for the change, so "locked" is not the reason.
            return __( 'WordPress could not write to .htaccess, so the server rule was not changed.', 'maroon-horizon-smart-firewall' );
        }
        $ht = ABSPATH . '.htaccess';
        if ( ! file_exists( $ht ) ) {
            return __( 'There is no .htaccess file in the WordPress folder, so no server rule was added.', 'maroon-horizon-smart-firewall' );
        }
        if ( class_exists( 'SFAIS_FS' ) && ! SFAIS_FS::is_writable( $ht ) ) {
            return __( '.htaccess is locked (read-only), so the server rule was not changed. Unlock .htaccess and try again.', 'maroon-horizon-smart-firewall' );
        }
        return __( 'WordPress could not write to .htaccess, so the server rule was not changed.', 'maroon-horizon-smart-firewall' );
    }

    /**
     * Addresses that must never be blocked: the admin's own, the proxy/CDN the visit arrives through, this server.
     *
     * @return string Reason ('' = may be blocked).
     */
    private function protected_ip_reason( $ip ) {
        // 1.8.13: compared in canonical form ($ip already is).
        $client = $this->normalize_ip( $this->sfais_get_client_ip() );
        $remote = $this->normalize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' );
        $server = $this->normalize_ip( isset( $_SERVER['SERVER_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) : '' );

        if ( $client !== '' && $ip === $client ) {
            /* translators: %s: IP address. */
            return sprintf( __( '%s is your own IP address right now. Blocking it would lock you out of this site, so it was not blocked.', 'maroon-horizon-smart-firewall' ), $ip );
        }
        if ( $this->is_cloudflare_ip( $ip ) ) {
            /* translators: %s: IP address. */
            return sprintf( __( '%s belongs to Cloudflare. Blocking it would block every visitor who comes through Cloudflare, so it was not blocked.', 'maroon-horizon-smart-firewall' ), $ip );
        }
        if ( $remote !== '' && $ip === $remote ) {
            /* translators: %s: IP address. */
            return sprintf( __( '%s is the proxy or CDN address your visit arrives through. Blocking it would block every visitor who comes the same way, so it was not blocked.', 'maroon-horizon-smart-firewall' ), $ip );
        }
        if ( ( $server !== '' && $ip === $server ) || $ip === '::1' || ( $this->sfais_is_ipv4( $ip ) && $this->ip_in_cidr( $ip, '127.0.0.0/8' ) ) ) {
            /* translators: %s: IP address. */
            return sprintf( __( '%s belongs to this server itself. Blocking it would break WordPress tasks such as scheduled jobs and updates, so it was not blocked.', 'maroon-horizon-smart-firewall' ), $ip );
        }
        return '';
    }

    /**
     * Return a UNIQUE list of plain IPs (manual + .htaccess).
     * The UI determines and displays chips (.htaccess / PHP Firewall).
     * Does NOT include threat feed subnets (kept separate).
     */
    public function get_blocked_ips() {
        // 1.8.13: both lists in canonical form, so one address is one row.
        $db_ips   = $this->get_db_ips();

        $file_ips = $this->read_htaccess_blocklist();

        // Merge + dedupe and return plain IPs only
        $all = array_values(array_unique(array_merge($db_ips, $file_ips), SORT_STRING));

        // ⚠ Do NOT update_option here; keep this function side-effect free.
        return $all;
    }

    /**
     * When .htaccess becomes writable again, rebuild the SFAIS block with all manual IPs from DB.
     * 1.8.13: plus the IPs that already have a server rule (as update_htaccess does), so no server rule vanishes on unlock.
     */
    public function resync_htaccess_if_unlocked() {
        $ht = ABSPATH . '.htaccess';
        if (file_exists($ht) && SFAIS_FS::is_writable($ht)) {
            $file_ips = $this->read_htaccess_blocklist();
            $ips      = array_values( array_unique( array_merge( $this->get_db_ips(), $file_ips ), SORT_STRING ) );
            if ( empty( $ips ) && empty( $file_ips ) ) {
                return;   // nothing to write (no empty MHSF block is added)
            }
            $this->rewrite_htaccess_blocklist($ips);
        }
    }

    /**
     * (Optional) Allow other plugin components to reuse the same client-IP resolver.
     */
    public function get_client_ip() {
        return $this->sfais_get_client_ip();
    }

    /**
     * Whether an address belongs to Cloudflare's published edge ranges.
     */
    public function is_cloudflare_ip( $ip ) {
        $ip = (string) $ip;
        if ( ! $this->sfais_is_valid_ip( $ip ) ) {
            return false;
        }
        foreach ( self::CLOUDFLARE_RANGES as $range ) {
            if ( $this->sfais_ip_in_cidr_any( $ip, $range ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the current request arrived through Cloudflare (the visitor's real address is then the one Cloudflare reports).
     */
    public function request_via_cloudflare() {
        $this->sfais_get_client_ip();
        return self::$via_cloudflare;
    }

    /** The visitor address in Cloudflare's CF-Connecting-IP header ('' when missing or invalid). */
    private function cloudflare_visitor_ip() {
        $cf = isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) ) : '';
        return $this->sfais_is_valid_ip( $cf ) ? $cf : '';
    }

    /**
     * 1.8.12: rebuild an MHSF block written by an older version (no Cloudflare line yet) once, when .htaccess is writable.
     */
    public function upgrade_htaccess_block() {
        $ht = ABSPATH . '.htaccess';
        if ( ! file_exists( $ht ) || ! class_exists( 'SFAIS_FS' ) || ! SFAIS_FS::is_writable( $ht ) ) {
            return;
        }
        $content = SFAIS_FS::read( $ht );
        if ( ! is_string( $content ) || ! preg_match( '/# BEGIN MHSF(.*?)# END MHSF/s', $content, $m ) ) {
            return;
        }
        if ( strpos( $m[1], 'RewriteCond %{REMOTE_ADDR}' ) === false || strpos( $m[1], 'CF-Connecting-IP' ) !== false ) {
            return;
        }
        $this->rewrite_htaccess_blocklist( $this->read_htaccess_blocklist() );
    }

    /**
     * Runtime PHP firewall:
     *  - Manual IP list (exact IP match)
     *  - Threat Feed (compiled integer ranges, optional add-on)
     */
    public function php_firewall_check() {

        // ✅ Never block WP-CLI / CLI maintenance tasks (wp-cli, cron shells, etc.)
        if ( ( defined( 'WP_CLI' ) && WP_CLI ) || PHP_SAPI === 'cli' ) {
            return;
        }

        

        // ✅ Never block wp-admin screens for logged-in administrators.
        // Freemius pricing/account pages and other admin UI rely on admin-ajax and REST calls.
        // (admin-ajax.php counts as is_admin(), so this also covers the Freemius pricing/account AJAX calls of admins.)
        if ( is_admin() && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
            return;
        }

        // 1.8.13: the old "never block admin-ajax actions starting with fs_" bypass is gone - it let ANY visitor, also a
        // blocked one, past the manual list and the Threat Feed. Freemius registers its AJAX actions for logged-in users
        // only (no wp_ajax_nopriv_ actions), and administrators are already let through by the check above.

        // ✅ Resolve real client IP safely (common proxies)
        // 1.8.13: canonical form, compared with the canonical list (IPv6 can be written in many ways).
        $user_ip = $this->normalize_ip( $this->sfais_get_client_ip() );

        // Manual IP block (exact match)
        $blocked_manual = $this->get_db_ips();

        if ($user_ip && in_array($user_ip, $blocked_manual, true)) {
            status_header(403);
            exit('Access denied by MH Smart Firewall (IP blocked).');
        }

		// Threat Feed (subnet-based, optional add-on; manual + AI storage kept separate)
		        // Allow add-ons (e.g., PRO Threat Feed) to provide additional block decisions.
		        $extra_reason = apply_filters( 'sfais_firewall_extra_block_reason', '', $user_ip, $this );
		        if ( is_string( $extra_reason ) && $extra_reason !== '' ) {
		            // Ensure any dynamically provided reason is safe for output.
		            $extra_reason = sanitize_text_field( $extra_reason );
		            status_header( 403 );
		            exit( 'Access denied by MH Smart Firewall (' . esc_html( $extra_reason ) . ').' );
		        }


            }

    /* -------------------- Client IP Resolution (SAFE) -------------------- */

    /**
     * Resolve the real client IP in a safe way (common proxies).
      * - Reverse proxy: trust XFF/X-Real-IP/Client-IP/True-Client-IP only if REMOTE_ADDR is private/loopback.
     *
     * Cached per-request to avoid repeated parsing/remote CIDR checks.
     */
    private function sfais_get_client_ip() {
        static $cached = null;
        if ($cached !== null) {
            return $cached;
        }

        $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? trim( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) ) : '';
        if (!$this->sfais_is_valid_ip($remote)) {
            $cached = '';
            return $cached;
        }

        // 1.8.12: Cloudflare - the visitor address Cloudflare reports (CF-Connecting-IP) counts ONLY when the request
        // really comes from Cloudflare's published addresses; the same header from anyone else is ignored.
        if ( $this->is_cloudflare_ip( $remote ) ) {
            $cf = $this->cloudflare_visitor_ip();
            if ( $cf !== '' ) {
                self::$via_cloudflare = true;
                $cached = $cf;
                return $cached;
            }
        }

        // 1) Common reverse proxies (only trust if the proxy IP is private/loopback)
        if ($this->sfais_is_private_or_loopback($remote)) {

            // X-Forwarded-For can be a CSV list: client, proxy1, proxy2...
            if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
                $xff_raw = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
                $picked  = $this->sfais_pick_public_ip_from_xff( (string) $xff_raw );
                // 1.8.12: a local proxy in front of WordPress and Cloudflare in front of that - the last public hop is
                // a Cloudflare address, so the visitor is the one Cloudflare reports.
                if ( $picked !== '' && $this->is_cloudflare_ip( $picked ) && $this->cloudflare_visitor_ip() !== '' ) {
                    self::$via_cloudflare = true;
                    $cached = $this->cloudflare_visitor_ip();
                    return $cached;
                }
                if ($picked !== '') {
                    $cached = $picked;
                    return $cached;
                }
            }

            if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
                $xrip = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ) );
                if ($this->sfais_is_valid_ip($xrip)) {
                    $cached = $xrip;
                    return $cached;
                }
            }

            // Some proxies/CDNs use these (ONLY trusted behind private hop)
            if (!empty($_SERVER['HTTP_TRUE_CLIENT_IP'])) {
                $tci = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) );
                if ($this->sfais_is_valid_ip($tci)) {
                    $cached = $tci;
                    return $cached;
                }
            }

            if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
                $cip = trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) ) );
                if ($this->sfais_is_valid_ip($cip)) {
                    $cached = $cip;
                    return $cached;
                }
            }
        }

        // Fallback: what PHP sees
        $cached = $remote;
        return $cached;
    }

    private function sfais_is_valid_ip($ip) {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP);
    }

    private function sfais_is_ipv4($ip) {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
    }

    private function sfais_is_private_or_loopback($ip) {
        // If it's NOT public-routable, it's OK to consider forwarded headers.
        // FILTER_FLAG_NO_RES_RANGE excludes special/reserved ranges (loopback, link-local, etc)
        $flags = FILTER_FLAG_NO_PRIV_RANGE;
        if (defined('FILTER_FLAG_NO_RES_RANGE')) {
            $flags |= FILTER_FLAG_NO_RES_RANGE;
        }
        $is_public = filter_var($ip, FILTER_VALIDATE_IP, $flags);
        return $is_public === false;
    }

    private function sfais_pick_public_ip_from_xff($xff) {
        $parts = array_map('trim', explode(',', (string) $xff));
        if (!$parts) return '';

        $flags = FILTER_FLAG_NO_PRIV_RANGE;
        if (defined('FILTER_FLAG_NO_RES_RANGE')) {
            $flags |= FILTER_FLAG_NO_RES_RANGE;
        }

        // 1.8.3: walk from the RIGHT (the hop our proxy saw) and skip private / loopback proxies; the left-most entries are
        // written by the visitor and can be faked.
        foreach (array_reverse($parts) as $cand) {
            if (!$this->sfais_is_valid_ip($cand)) continue;
            $is_public = filter_var($cand, FILTER_VALIDATE_IP, $flags);
            if ($is_public !== false) return $cand;
        }

        // Fallback: first valid IP
        foreach ($parts as $cand) {
            if ($this->sfais_is_valid_ip($cand)) return $cand;
        }

        return '';
    }

    private function sfais_ip_in_cidr_any($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }

        list($subnet, $bits) = explode('/', $cidr, 2);
        $subnet = trim($subnet);
        $bits   = (int) $bits;

        if (!is_string($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) return false;
        if (!filter_var($subnet, FILTER_VALIDATE_IP)) return false;

        $ip_bin     = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);

        if ($ip_bin === false || $subnet_bin === false) return false;
        if (strlen($ip_bin) !== strlen($subnet_bin)) return false;

        $max_bits = strlen($ip_bin) * 8;
        if ($bits < 0 || $bits > $max_bits) return false;

        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;

        if ($bytes > 0) {
            if (substr($ip_bin, 0, $bytes) !== substr($subnet_bin, 0, $bytes)) return false;
        }

        if ($rem === 0) return true;

        $mask = (0xFF << (8 - $rem)) & 0xFF;

        $ip_byte     = ord($ip_bin[$bytes]);
        $subnet_byte = ord($subnet_bin[$bytes]);

        return (($ip_byte & $mask) === ($subnet_byte & $mask));
    }

    /* -------------------- Helpers -------------------- */

    /**
     * Filesystem read via SFAIS_FS (WP_Filesystem) with a conservative fallback.
     *
     * @param string $path
     * @return string|false
     */
    private function mhsf_fs_read( $path ) {
        $path = (string) $path;

        if ( $path === '' ) {
            return false;
        }

        // Ensure filesystem helper is available.
        if ( ! class_exists( 'SFAIS_FS' ) ) {
            $fs_helper = defined( 'SFAIS_PATH' ) ? SFAIS_PATH . 'includes/core/class-sfais-fs.php' : '';
            if ( $fs_helper && is_file( $fs_helper ) ) {
                require_once $fs_helper;
            }
        }

        if ( class_exists( 'SFAIS_FS' ) ) {
            $c = SFAIS_FS::read( $path );
            return is_string( $c ) ? $c : false;
        }

        return false;
    }

    /**
     * Manual IP storage (exact IPs).
     */
    private function save_ip($ip) {
        $ips = get_option($this->option_key, []);
        if (!is_array($ips)) $ips = [];
        if (!in_array($ip, $ips, true)) {
            $ips[] = $ip;
            $ips = array_values(array_unique(array_map('trim', $ips), SORT_STRING));
            update_option($this->option_key, $ips);
        }
    }
    // 1.8.13: extract_ip() removed - it kept the first IPv4 of any text, so "172.30.81.64/28" quietly became
    // "172.30.81.64"; its IPv6 pattern missed valid forms like "::abcd". parse_ip_input() replaces it.

    /**
     * Check whether an IP is inside a given IPv4 CIDR subnet.
     * (legacy helper, kept for potential fallback)
     */
    private function ip_in_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            // Non-CIDR entry – treat as exact IP
            return $ip === $cidr;
        }

        list($subnet, $maskBits) = explode('/', $cidr, 2);
        $subnet   = trim($subnet);
        $maskBits = (int) trim($maskBits);

        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        if ($maskBits < 0 || $maskBits > 32) {
            return false;
        }

        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = $maskBits == 0 ? 0 : (~0 << (32 - $maskBits)) & 0xFFFFFFFF;

        return (($ipLong & $mask) === ($subnetLong & $mask));
    }

    /**
     * Read MHSF block from .htaccess and extract IPs.
     *
     * Supports the MHSF mod_rewrite syntax:
     *  - RewriteCond %{REMOTE_ADDR} ^1\.2\.3\.4$
     *
     * Backward-compatible with legacy "# BEGIN SFAIS" blocks (Apache 2.2/2.4 authz syntaxes).
     */
    public function get_htaccess_ips() {
        return $this->read_htaccess_blocklist();
    }

    private function read_htaccess_blocklist() {
        $ht = ABSPATH . '.htaccess';
        if ( ! file_exists( $ht ) ) {
            return [];
        }

        $content = $this->mhsf_fs_read( $ht );
        if ( ! is_string( $content ) || $content === '' ) {
            return [];
        }

        $ips = [];

        // Preferred: MHSF mod_rewrite block.
        if ( preg_match( '/# BEGIN MHSF(.*?)# END MHSF/s', $content, $m ) ) {
            $inner = (string) $m[1];

            if ( preg_match_all( '/^\s*RewriteCond\s+%\{REMOTE_ADDR\}\s+\^(.+?)\$(?:\s+\[[A-Z,]+\])?\s*$/mi', $inner, $mm ) ) {
                foreach ( (array) ( $mm[1] ?? [] ) as $rx ) {
                    $rx = trim( (string) $rx );

                    // Unescape dot/colon (rules are typically written via preg_quote()).
                    $candidate = preg_replace( '/\\\\([\.:])/', '$1', $rx );

                    // 1.8.13: canonical form (a rule written for "2001:DB8::1" is the same address as "2001:db8::1").
                    $candidate = is_string( $candidate ) ? $this->normalize_ip( $candidate ) : '';
                    if ( $candidate !== '' ) {
                        $ips[] = $candidate;
                    }
                }
            }

            return array_values( array_unique( array_filter( array_map( 'trim', $ips ) ), SORT_STRING ) );
        }

        // Backward compatibility: legacy SFAIS authz blocks (Apache 2.2 / 2.4 syntaxes).
        if ( preg_match( self::LEGACY_BLOCK_RX, $content, $m2 ) ) {
            $inner = (string) $m2[1];

            // Legacy Apache 2.2 compatibility syntax
            if ( preg_match_all( '/^\s*Deny\s+from\s+([0-9\.\:a-fA-F]+)\s*$/mi', $inner, $mm3 ) ) {
                if ( ! empty( $mm3[1] ) ) {
                    $ips = array_merge( $ips, $mm3[1] );
                }
            }

            // Apache 2.4+ authz syntax
            if ( preg_match_all( '/^\s*Require\s+not\s+ip\s+([0-9\.\:a-fA-F]+)\s*$/mi', $inner, $mm4 ) ) {
                if ( ! empty( $mm4[1] ) ) {
                    $ips = array_merge( $ips, $mm4[1] );
                }
            }
        }

        $ips = array_values( array_unique( array_filter( array_map( 'trim', $ips ) ), SORT_STRING ) );

        // 1.8.13: canonical form, valid addresses only.
        return $this->normalize_list( $ips );
    }

    /**
     * Replace (or create) the MHSF block in .htaccess with the given manual IP list.
     *
     * Notes:
     * - Writes mod_rewrite-based deny rules:
     *     RewriteCond %{REMOTE_ADDR} ^1\.2\.3\.4$
     *     RewriteRule ^ - [F,L]
     * - If "# BEGIN WordPress" exists, the MHSF block is inserted immediately above it.
     *   Otherwise, it is appended to the bottom of the file.
     * - Does not create a new .htaccess file if it doesn't already exist.
     * - Uses SFAIS_FS (WP_Filesystem) for compatibility and to avoid direct filesystem writes.
     */
    private function rewrite_htaccess_blocklist( $ips ) {
        $ht = ABSPATH . '.htaccess';

        if ( ! file_exists( $ht ) ) {
            return false;
        }

        // Hard-filter invalid entries to avoid breaking Apache parsing.
        // 1.8.13: canonical form, so the rule matches the address exactly as the server reports it (IPv6 lowercase, compressed).
        $ips = $this->normalize_list( $ips );

        $start = "# BEGIN MHSF";
        $end   = "# END MHSF";

        $block  = $start . "\n";
        $block .= "<IfModule mod_rewrite.c>\n";
        $block .= "RewriteEngine On\n";

        foreach ( $ips as $ip ) {
            // Escape for regex use inside RewriteCond (e.g., 29\.29\.29\.29).
            // 1.8.13: a canonical address holds only hex digits, ':' and '.', and only '.' is special in the regex (colons need
            // no escape), so IPv6 rules read plainly: ^2001:db8::1$ .
            $rx = str_replace( '.', '\\.', $ip );
            // 1.8.12: also the visitor address Cloudflare reports, so the server rule works behind Cloudflare. Safe without
            // checking the sender: a faked header can only get the sender blocked.
            $block .= "RewriteCond %{REMOTE_ADDR} ^" . $rx . "$ [OR]\n";
            $block .= "RewriteCond %{HTTP:CF-Connecting-IP} ^" . $rx . "$ [NC]\n";
            $block .= "RewriteRule ^ - [F,L]\n";
        }

        $block .= "</IfModule>\n";
        $block .= $end . "\n";

        $content = $this->mhsf_fs_read( $ht );
        if ( ! is_string( $content ) ) {
            return false;
        }

        // Remove existing MHSF block (if present).
        $content = preg_replace( '/# BEGIN MHSF.*?# END MHSF\s*/s', '', $content );

        // Remove the legacy SFAIS manual block (if present) so we don't keep two parallel block syntaxes.
        // 1.8.9: ONLY that block - the marker alone on its line. The old pattern also matched other features' blocks
        // ("# BEGIN SFAIS Force HTTPS ... # END SFAIS Force HTTPS"), cut them in half and left a bare "Force HTTPS"
        // line that took the whole site down with HTTP 500.
        $content = preg_replace( self::LEGACY_BLOCK_RX, '', $content );

        // 1.8.9: remove a bare leftover line from that bug if the server still tolerated it.
        $content = preg_replace( '/^[ \t]*(?:Force HTTPS|Protect wp-config\.php)[ \t]*(?:\R|\z)/m', '', (string) $content );

        // Insert above WordPress rules if present, otherwise append.
        if ( preg_match( '/^\s*# BEGIN WordPress\b/m', $content, $mw, PREG_OFFSET_CAPTURE ) ) {
            $pos    = (int) $mw[0][1];
            $before = substr( $content, 0, $pos );
            $after  = substr( $content, $pos );

            $before = rtrim( (string) $before, "\r\n" );
            $after  = ltrim( (string) $after, "\r\n" );

            $new_content = '';
            if ( $before !== '' ) {
                $new_content .= $before . "\n\n";
            }
            // 1.8.13: one final newline (each rewrite used to add one more blank line at the end of the file).
            $new_content .= rtrim( $block, "\r\n" ) . "\n\n" . rtrim( $after, "\r\n" ) . "\n";
        } else {
            $new_content = rtrim( (string) $content, "\r\n" ) . "\n\n" . rtrim( $block, "\r\n" ) . "\n";
        }

        // 1.8.9: written with a check that the site still answers; a broken result is undone at once.
        $this->last_htaccess_status = class_exists( 'SFAIS_FS' ) ? SFAIS_FS::write_htaccess_checked( $ht, $new_content ) : 'failed';
        if ( ! in_array( $this->last_htaccess_status, [ 'ok', 'unverified' ], true ) ) {
            return false;
        }

        // Verify the write actually took effect.
        $after = $this->read_htaccess_blocklist();
        if ( empty( $ips ) ) {
            // Empty list is valid; block exists but no denies.
            return is_array( $after );
        }

        // Confirm at least one IP and especially the list entries can be read back.
        foreach ( $ips as $ip ) {
            if ( in_array( $ip, $after, true ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Update .htaccess with a single new manual IP — by rebuilding the MHSF block.
     */

    /**
     * Update .htaccess with a single new manual IP — by rebuilding the MHSF block.
     *
     * Returns true only when .htaccess was successfully written and the IP is confirmed
     * present in the MHSF block (read-back verification).
     */
    private function update_htaccess( $ip ) {

        // DB list is the canonical manual list.
        $db_ips = $this->get_db_ips();   // 1.8.13: canonical

        // Preserve any existing file-only entries inside the MHSF block.
        $file_ips = $this->read_htaccess_blocklist();

        $ips = array_values( array_unique( array_merge( $db_ips, $file_ips ), SORT_STRING ) );

        // Ensure the new IP is included in the file output
        if ( $ip && ! in_array( $ip, $ips, true ) ) {
            $ips[] = $ip;
        }

        if ( ! $this->rewrite_htaccess_blocklist( $ips ) ) {
            return false;
        }

        // Confirm presence after write
        $after = $this->read_htaccess_blocklist();
        return $ip ? in_array( $ip, $after, true ) : true;
    }

    /**
     * Remove an IP from the MHSF .htaccess block (if writable).
     */

    /**
     * Remove an IP from the MHSF .htaccess block (if writable).
     *
     * We rebuild the MHSF block from the current file blocklist minus the IP,
     * which is safer than doing regex line surgery across both 2.2 and 2.4 syntaxes.
     *
     * @return bool true if removed (or not present), false if .htaccess could not be written.
     */
    private function remove_ip_from_htaccess( $ip ) {
        $ht = ABSPATH . '.htaccess';
        if ( ! file_exists( $ht ) ) {
            return true;
        }

        $current = $this->read_htaccess_blocklist();
        if ( ! in_array( $ip, $current, true ) ) {
            // No server rule for this IP - nothing to change (also when .htaccess is locked).
            return true;
        }

        $current = array_values( array_diff( $current, [ $ip ] ) );

        if ( SFAIS_FS::is_writable( $ht ) ) {
            // 1.8.13: removed = the rule is really gone when the file is read back.
            return $this->rewrite_htaccess_blocklist( $current ) && ! in_array( $ip, $this->read_htaccess_blocklist(), true );
        }

        // 1.8.11 (Vlad): .htaccess is locked - unlock it for a moment, remove the rule, lock it again with the same
        // permissions, so "Unblock" always really unblocks. If unlocking is not possible, the caller explains why.
        clearstatcache( true, $ht );
        $perms = fileperms( $ht );
        if ( $perms === false || ! SFAIS_FS::chmod( $ht, 0644 ) ) {
            return false;
        }
        clearstatcache( true, $ht );

        $ok = SFAIS_FS::is_writable( $ht ) && $this->rewrite_htaccess_blocklist( $current ) && ! in_array( $ip, $this->read_htaccess_blocklist(), true );

        // 1.8.13: check the re-lock (same permissions again and read-only for WordPress) instead of assuming it worked.
        $relocked = SFAIS_FS::chmod( $ht, $perms & 0777 );
        clearstatcache( true, $ht );
        $now      = fileperms( $ht );
        $relocked = $relocked && $now !== false && ( $now & 0777 ) === ( $perms & 0777 ) && ! SFAIS_FS::is_writable( $ht );

        $this->relock_status = $relocked ? 'ok' : 'failed';
        return $ok;
    }
}
