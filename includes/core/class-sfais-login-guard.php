<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Login Guard
 *
 * Simple, robust rate-limiting for login attempts.
 * - Tracks failed logins per IP using transients.
 * - Locks out attackers for a period after too many failures.
 * - Resets on successful login.
 * - 1.8.4: ways back in for a locked-out administrator:
 *   1. an unlock link by e-mail (administrator accounts only, single use, 15 minutes),
 *   2. Settings > Login Guard: list of locked addresses with Unlock / Unlock all,
 *   3. tries during a lockout no longer extend it, and the message says when it ends,
 *   4. emergency switch: define( 'MHSF_LOGIN_GUARD_OFF', true ); in wp-config.php (readme FAQ).
 *
 * This module is part of the FREE + PRO feature set.
 */
class SFAIS_Login_Guard {

    /**
     * Maximum failed attempts before lockout.
     *
     * @var int
     */
    protected $max_attempts = 5;

    /**
     * Lockout duration in minutes.
     *
     * @var int
     */
    protected $lockout_minutes = 30;

    /**
     * Unlock link lifetime in minutes, and the pause between two unlock e-mails for one account.
     */
    const UNLOCK_LINK_MINUTES = 15;
    const UNLOCK_MAIL_GAP_MINUTES = 10;

    /**
     * Option with the currently locked addresses (ip => unix time the lock ends) for the Settings list. Not autoloaded.
     */
    const LOCKS_OPTION = 'sfais_login_locks';

    /**
     * True while this request was refused because of a lockout (that refusal must not count as a new failure).
     *
     * @var bool
     */
    protected $refused_locked = false;

    public function __construct() {
        // Emergency switch for site owners with FTP access only (readme FAQ).
        if ( defined( 'MHSF_LOGIN_GUARD_OFF' ) && MHSF_LOGIN_GUARD_OFF ) {
            return;
        }

        // Check lockout before authentication.
        add_filter( 'authenticate', [ $this, 'maybe_block_login' ], 30, 3 );

        // Track failed logins.
        add_action( 'wp_login_failed', [ $this, 'handle_failed_login' ], 10, 1 );

        // Reset on successful login.
        add_action( 'wp_login', [ $this, 'handle_successful_login' ], 10, 2 );

        // Unlock by e-mail (wp-login.php?action=sfais_unlock_request / sfais_unlock).
        add_action( 'login_form_sfais_unlock_request', [ $this, 'unlock_request_screen' ] );
        add_action( 'login_form_sfais_unlock', [ $this, 'unlock_link_screen' ] );
        add_filter( 'login_message', [ $this, 'login_message' ] );

        // Settings > Login Guard: Unlock / Unlock all.
        add_action( 'admin_post_sfais_login_unlock', [ $this, 'admin_unlock' ] );
    }

    /**
     * If IP is locked, block login.
     *
     * @param WP_User|WP_Error|null $user
     * @param string                $username
     * @param string                $password
     *
     * @return WP_User|WP_Error|null
     */
    public function maybe_block_login( $user, $username, $password ) {
        // Only affect real login requests.
        if ( ! $this->is_login_request() ) {
            return $user;
        }

        $ip = $this->get_ip_address();
        if ( empty( $ip ) ) {
            return $user;
        }

        if ( $this->is_locked_out( $ip ) ) {
            $this->refused_locked = true;
            return new WP_Error( 'sfais_login_locked', $this->locked_message( $ip ) );
        }

        return $user;
    }

    /**
     * The message on a refused login: when the lock ends + the e-mail unlock link.
     *
     * @param string $ip
     *
     * @return string
     */
    protected function locked_message( $ip ) {
        $minutes = max( 1, (int) ceil( $this->lock_seconds_left( $ip ) / MINUTE_IN_SECONDS ) );
        $text    = sprintf(
            /* translators: %d: minutes until the login lock ends */
            _n( 'Too many failed login attempts. Please try again in %d minute.', 'Too many failed login attempts. Please try again in %d minutes.', $minutes, 'maroon-horizon-smart-firewall' ),
            $minutes
        );
        $link = add_query_arg( 'action', 'sfais_unlock_request', wp_login_url() );

        return esc_html( $text ) . '<br><a href="' . esc_url( $link ) . '">' . esc_html__( 'Administrator? Get an unlock link by e-mail', 'maroon-horizon-smart-firewall' ) . '</a>';
    }

    /**
     * Handle a failed login attempt.
     *
     * @param string $username
     */
    public function handle_failed_login( $username ) {
        if ( ! $this->is_login_request() ) {
            return;
        }

        // 1.8.4: a try that was refused because of the lock does not extend the lock.
        if ( $this->refused_locked ) {
            return;
        }

        $ip = $this->get_ip_address();
        if ( empty( $ip ) ) {
            return;
        }

        $attempts = $this->get_failed_attempts( $ip );
        $attempts++;

        $this->set_failed_attempts( $ip, $attempts );

        if ( $attempts >= $this->max_attempts ) {
            $this->lock_out_ip( $ip );
        }
    }

    /**
     * Reset counters on successful login.
     *
     * @param string  $user_login
     * @param WP_User $user
     */
    public function handle_successful_login( $user_login, $user ) {
        $ip = $this->get_ip_address();
        if ( empty( $ip ) ) {
            return;
        }

        $this->clear_failed_attempts( $ip );
        $this->clear_lockout( $ip );
    }

    /**
     * wp-login.php?action=sfais_unlock_request - asks for the administrator's user name or e-mail and sends the link.
     * The answer is the same whether the account exists or not (no account guessing).
     */
    public function unlock_request_screen() {
        $sent = false;
        $method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
        if ( 'POST' === $method ) {
            check_admin_referer( 'sfais_unlock_request' );
            $login = isset( $_POST['sfais_user'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_user'] ) ) : '';
            $this->maybe_send_unlock_mail( $login );
            $sent = true;
        }

        login_header( __( 'Unlock login', 'maroon-horizon-smart-firewall' ) );
        if ( $sent ) {
            echo '<p class="message">' . esc_html__( 'If this is an administrator account, an unlock link has been sent to its e-mail address. The link works once, for 15 minutes, from the device you open it on.', 'maroon-horizon-smart-firewall' ) . '</p>';
        } else {
            echo '<p class="message">' . esc_html__( 'Locked out? Enter your administrator user name or e-mail address and we will e-mail you a link that unlocks the login for your address.', 'maroon-horizon-smart-firewall' ) . '</p>';
            echo '<form method="post" action="' . esc_url( add_query_arg( 'action', 'sfais_unlock_request', wp_login_url() ) ) . '">';
            wp_nonce_field( 'sfais_unlock_request' );
            echo '<p><label for="sfais_user">' . esc_html__( 'User name or e-mail address', 'maroon-horizon-smart-firewall' ) . '</label>';
            echo '<input type="text" name="sfais_user" id="sfais_user" class="input" autocomplete="username" required></p>';
            echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Send unlock link', 'maroon-horizon-smart-firewall' ) . '"></p>';
            echo '</form>';
        }
        echo '<p id="nav"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to login', 'maroon-horizon-smart-firewall' ) . '</a></p>';
        login_footer();
        exit;
    }

    /**
     * Send the unlock link - only to an account that can manage the site, at most once per UNLOCK_MAIL_GAP_MINUTES.
     *
     * @param string $login User name or e-mail address.
     */
    protected function maybe_send_unlock_mail( $login ) {
        if ( '' === $login ) {
            return;
        }
        $user = is_email( $login ) ? get_user_by( 'email', $login ) : get_user_by( 'login', $login );
        if ( ! $user || ! user_can( $user, 'manage_options' ) || ! is_email( $user->user_email ) ) {
            return;
        }
        $gap_key = 'sfais_unlock_mail_' . (int) $user->ID;
        if ( false !== get_transient( $gap_key ) ) {
            return;
        }
        set_transient( $gap_key, 1, self::UNLOCK_MAIL_GAP_MINUTES * MINUTE_IN_SECONDS );

        $token = bin2hex( random_bytes( 32 ) );
        set_transient( 'sfais_unlock_' . hash( 'sha256', $token ), (int) $user->ID, self::UNLOCK_LINK_MINUTES * MINUTE_IN_SECONDS );
        $link = add_query_arg( array( 'action' => 'sfais_unlock', 'sfais_key' => $token ), wp_login_url() );

        $site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
        /* translators: %s: site name */
        $subject = sprintf( __( '[%s] Unlock your login', 'maroon-horizon-smart-firewall' ), $site );
        $body    = sprintf(
            /* translators: 1: site address, 2: unlock link, 3: minutes */
            __( "Someone asked to unlock the login of %1\$s for your account.\n\nTo unlock it for the device you open this link on, use (works once, for %3\$d minutes):\n%2\$s\n\nIf this was not you, ignore this e-mail - nothing changes. The login stays locked for the address that failed too often.\n\nMaroon Horizon Smart Firewall", 'maroon-horizon-smart-firewall' ),
            home_url( '/' ),
            $link,
            self::UNLOCK_LINK_MINUTES
        );
        wp_mail( $user->user_email, $subject, $body );
    }

    /**
     * wp-login.php?action=sfais_unlock&sfais_key=... - single use: clears the lock + failure count of the address opening it.
     */
    public function unlock_link_screen() {
        // not 'key': wp-login.php turns any ?key= into a password reset. No nonce possible (logged out, e-mailed link): the
        // 64-hex one-time key IS the check, like WordPress's own password-reset link.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $key = isset( $_GET['sfais_key'] ) ? sanitize_text_field( wp_unslash( $_GET['sfais_key'] ) ) : '';
        $ok  = false;
        if ( preg_match( '/^[0-9a-f]{64}$/', $key ) ) {
            $tkey = 'sfais_unlock_' . hash( 'sha256', $key );
            if ( false !== get_transient( $tkey ) ) {
                delete_transient( $tkey );
                $ip = $this->get_ip_address();
                if ( '' !== $ip ) {
                    $this->clear_failed_attempts( $ip );
                    $this->clear_lockout( $ip );
                    $ok = true;
                }
            }
        }
        wp_safe_redirect( add_query_arg( 'sfais_unlocked', $ok ? '1' : '0', wp_login_url() ) );
        exit;
    }

    /**
     * The note above the login form after an unlock link was used.
     *
     * @param string $message
     *
     * @return string
     */
    public function login_message( $message ) {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only (no state change).
        $flag = isset( $_GET['sfais_unlocked'] ) ? sanitize_key( wp_unslash( $_GET['sfais_unlocked'] ) ) : '';
        if ( '' === $flag ) {
            return $message;
        }
        $ok = '1' === $flag;
        return $message . '<p class="message">' . ( $ok
            ? esc_html__( 'The login is unlocked for your address. You can log in now.', 'maroon-horizon-smart-firewall' )
            : esc_html__( 'This unlock link is not valid any more (used already or older than 15 minutes). Ask for a new one.', 'maroon-horizon-smart-firewall' ) ) . '</p>';
    }

    /**
     * Settings > Login Guard: Unlock one address or all (admin-post, nonce + capability checked).
     */
    public function admin_unlock() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'maroon-horizon-smart-firewall' ) );
        }
        check_admin_referer( 'sfais_login_unlock' );
        $which = isset( $_POST['sfais_ip'] ) ? sanitize_text_field( wp_unslash( $_POST['sfais_ip'] ) ) : '';
        $done  = 0;
        foreach ( array_keys( self::locked_list() ) as $ip ) {
            if ( 'all' === $which || $ip === $which ) {
                $this->clear_failed_attempts( $ip );
                $this->clear_lockout( $ip );
                $done++;
            }
        }
        wp_safe_redirect( add_query_arg( 'sfais_unlocked_n', $done, admin_url( 'admin.php?page=sfais-settings' ) ) );
        exit;
    }

    /**
     * Currently locked addresses: ip => unix time the lock ends (expired entries dropped).
     *
     * @return array
     */
    public static function locked_list() {
        $list = get_option( self::LOCKS_OPTION, array() );
        $list = is_array( $list ) ? $list : array();
        $now  = time();
        $live = array();
        foreach ( $list as $ip => $until ) {
            if ( (int) $until > $now && false !== get_transient( 'sfais_login_lock_' . md5( (string) $ip ) ) ) {
                $live[ (string) $ip ] = (int) $until;
            }
        }
        if ( count( $live ) !== count( $list ) ) {
            update_option( self::LOCKS_OPTION, $live, false );
        }
        return $live;
    }

    /**
     * Check if current request is a login attempt context.
     *
     * @return bool
     */
    protected function is_login_request() {
        $script = isset( $_SERVER['SCRIPT_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) : '';

        if ( false !== strpos( $script, 'wp-login.php' ) ) {
            return true;
        }

        return false;
    }

    /**
     * Get visitor IP address (best-effort, sanitized).
     *
     * @return string
     */
    protected function get_ip_address() {
        // 1.8.3: the SAME resolver as the firewall - forwarded headers count only when the request really comes through a
        // local / private proxy (before: X-Real-IP / Client-IP / X-Forwarded-For were trusted from anyone, so a fake header
        // per try skipped the lockout or locked out someone else).
        static $mgr = null;
        if ( null === $mgr && class_exists( 'SFAIS_IP_Manager' ) ) {
            $mgr = new SFAIS_IP_Manager();
        }
        $ip = $mgr && method_exists( $mgr, 'get_client_ip' ) ? (string) $mgr->get_client_ip() : '';
        if ( '' === $ip && ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
    }

    /**
     * Build transient keys.
     *
     * @param string $ip
     *
     * @return string
     */
    protected function get_attempts_key( $ip ) {
        return 'sfais_login_fail_' . md5( $ip );
    }

    protected function get_lockout_key( $ip ) {
        return 'sfais_login_lock_' . md5( $ip );
    }

    /**
     * Get number of failed attempts for IP.
     *
     * @param string $ip
     *
     * @return int
     */
    protected function get_failed_attempts( $ip ) {
        $key   = $this->get_attempts_key( $ip );
        $value = get_transient( $key );

        if ( ! is_numeric( $value ) ) {
            return 0;
        }

        return (int) $value;
    }

    /**
     * Store failed attempts for IP.
     *
     * @param string $ip
     * @param int    $attempts
     */
    protected function set_failed_attempts( $ip, $attempts ) {
        $key = $this->get_attempts_key( $ip );

        $expiration = max( 5 * MINUTE_IN_SECONDS, $this->lockout_minutes * MINUTE_IN_SECONDS );
        set_transient( $key, (int) $attempts, $expiration );
    }

    /**
     * Clear failed attempts for IP.
     *
     * @param string $ip
     */
    protected function clear_failed_attempts( $ip ) {
        $key = $this->get_attempts_key( $ip );
        delete_transient( $key );
    }

    /**
     * Lock out an IP for the lockout duration (the transient holds the end time; the Settings list gets the address).
     *
     * @param string $ip
     */
    protected function lock_out_ip( $ip ) {
        $key   = $this->get_lockout_key( $ip );
        $until = time() + $this->lockout_minutes * MINUTE_IN_SECONDS;
        set_transient( $key, $until, $this->lockout_minutes * MINUTE_IN_SECONDS );
        do_action( 'mhsf_activity', 'login', 'Login Guard locked 1 IP address' );   // 1.8.15: Recent activity groups these per hour

        $list = get_option( self::LOCKS_OPTION, array() );
        $list = is_array( $list ) ? $list : array();
        $list[ (string) $ip ] = $until;
        if ( count( $list ) > 200 ) {   // keep the option small under a big attack: newest 200
            arsort( $list );
            $list = array_slice( $list, 0, 200, true );
        }
        update_option( self::LOCKS_OPTION, $list, false );
    }

    /**
     * Clear lockout for IP.
     *
     * @param string $ip
     */
    protected function clear_lockout( $ip ) {
        $key = $this->get_lockout_key( $ip );
        delete_transient( $key );

        $list = get_option( self::LOCKS_OPTION, array() );
        if ( is_array( $list ) && isset( $list[ (string) $ip ] ) ) {
            unset( $list[ (string) $ip ] );
            update_option( self::LOCKS_OPTION, $list, false );
        }
    }

    /**
     * Check if IP is currently locked.
     *
     * @param string $ip
     *
     * @return bool
     */
    protected function is_locked_out( $ip ) {
        $key   = $this->get_lockout_key( $ip );
        $value = get_transient( $key );

        return ( false !== $value );
    }

    /**
     * Seconds until the lock of IP ends (locks from before 1.8.4 hold "1": then the full duration is assumed).
     *
     * @param string $ip
     *
     * @return int
     */
    protected function lock_seconds_left( $ip ) {
        $value = (int) get_transient( $this->get_lockout_key( $ip ) );
        return $value > 1 ? max( 0, $value - time() ) : $this->lockout_minutes * MINUTE_IN_SECONDS;
    }
}
