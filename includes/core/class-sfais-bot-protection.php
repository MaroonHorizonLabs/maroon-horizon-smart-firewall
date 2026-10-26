<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Bot Protection
 *
 * Conservative bad-bot filtering:
 *  - Only targets obviously bad / non-browser User-Agents.
 *  - Skips logged-in users, admin, cron, CLI, and localhost.
 *
 * This module is part of the FREE + PRO feature set.
 */
class SFAIS_Bot_Protection {

    public function __construct() {
        // Run very early, but after WordPress is loaded enough to call helpers.
        add_action( 'init', [ $this, 'maybe_block_bad_bot' ], 1 );
    }

    /**
     * Detect and block obviously bad bots.
     */
    public function maybe_block_bad_bot() {
        if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
            return;
        }

        if ( is_admin() || ( function_exists( 'wp_doing_ajax' ) && wp_doing_ajax() ) ) {
            return;
        }

        if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
            return;
        }

        if ( defined( 'WP_CLI' ) && WP_CLI ) {
            return;
        }

        $ip_raw = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
        $ip     = filter_var( $ip_raw, FILTER_VALIDATE_IP ) ? $ip_raw : '';
        if ( $ip === '127.0.0.1' || $ip === '::1' ) {
            return;
        }

        $ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? strtolower( trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) ) ) : '';

        if ( $ua === '' ) {
            return;
        }

        $bad_signatures = [
            'sqlmap',
            'nikto',
            'wpscan',
            'acunetix',
            'nessus',
            'curl/',
            'python-requests',
            'libwww-perl',
            'wget/',
            'httplib',
            'scanbot',
            'masscan',
        ];

        foreach ( $bad_signatures as $sig ) {
            if ( strpos( $ua, $sig ) !== false ) {
                $this->block_request();
            }
        }
    }

    /**
     * Actually block the request with a 403 response.
     */
    protected function block_request() {
        if ( ! headers_sent() ) {
            status_header( 403 );
            header( 'Content-Type: text/html; charset=utf-8' );
        }

        wp_die(
            esc_html__( 'Access denied.', 'maroon-horizon-smart-firewall' ),
            esc_html__( 'Forbidden', 'maroon-horizon-smart-firewall' ),
            [
                'response' => 403,
            ]
        );
    }
}
