<?php

/**
 * Plugin Name: MH Smart Firewall - Security, Malware Scanner & Login Protection
 * Plugin URI: https://mh.ie/maroon-horizon-smart-firewall/
 * Description: Security hardening toolkit for WordPress with firewall controls, patch toggles, file integrity checks, malware scanning, and IP protection.
 * Version: 1.8.17
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Tested up to: 7.1
 * Author: Maroon Horizon Ltd
 * Author URI: https://mh.ie
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: maroon-horizon-smart-firewall
 * Domain Path: /languages
 *
 * // Freemius deployment directives:
 */
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
/**
 * Minimal Freemius stub (safety).
 * If the SDK cannot be loaded for any reason, this prevents fatal errors from method calls.
 */
if ( !class_exists( 'MHSF_Freemius_Null', false ) ) {
    class MHSF_Freemius_Null {
        public function add_filter() {
            return null;
        }

        public function add_action() {
            return null;
        }

        public function set_basename() {
            return null;
        }

        public function __call( $name, $args ) {
            return null;
        }

    }

}
/**
 * ============================================================
 * EDITION CONFLICT GUARD (WP.org compliant)
 * ============================================================
 *
 * The FREE and PRO editions are mutually exclusive.
 *
 * WP.org rule: plugins must not activate/deactivate other plugins.
 *
 * Strategy:
 * 1) Activation-time guard:
 *    - If the other edition is active, self-deactivate this plugin and abort activation
 *      with a clear message.
 * 2) Runtime guard:
 *    - If both editions are active, bail out early to avoid double hooks / redeclare fatals.
 *    - Show an admin notice explaining what the user must do.
 */
// Current plugin (this edition).
$mhsf_current_basename = ( function_exists( 'plugin_basename' ) ? plugin_basename( __FILE__ ) : basename( __FILE__ ) );
$mhsf_current_dir = basename( dirname( __FILE__ ) );
$mhsf_is_pro_edition = false !== strpos( $mhsf_current_basename, '-pro/' ) || 'maroon-horizon-smart-firewall-pro' === $mhsf_current_dir;
$mhsf_get_other_candidates = static function () use($mhsf_current_basename, $mhsf_current_dir, $mhsf_is_pro_edition) {
    $candidates = array();
    // Canonical basenames.
    if ( $mhsf_is_pro_edition ) {
        $candidates[] = 'maroon-horizon-smart-firewall/maroon-horizon-smart-firewall.php';
        $candidates[] = 'maroon-horizon-smart-firewall-free/maroon-horizon-smart-firewall.php';
    } else {
        $candidates[] = 'maroon-horizon-smart-firewall-pro/maroon-horizon-smart-firewall.php';
    }
    // Derive from current directory naming.
    if ( $mhsf_is_pro_edition ) {
        // Strip a trailing "-pro".
        if ( 0 === strpos( $mhsf_current_dir, 'maroon-horizon-smart-firewall' ) ) {
            $derived_dir = preg_replace( '/-pro$/', '', $mhsf_current_dir );
            if ( $derived_dir && $derived_dir !== $mhsf_current_dir ) {
                $candidates[] = $derived_dir . '/' . basename( __FILE__ );
            }
        }
    } else {
        // Add "-pro" suffix.
        if ( 0 === strpos( $mhsf_current_dir, 'maroon-horizon-smart-firewall' ) && 'maroon-horizon-smart-firewall-pro' !== $mhsf_current_dir ) {
            $candidates[] = $mhsf_current_dir . '-pro/' . basename( __FILE__ );
        }
        // If current dir is canonical free slug, also try canonical pro slug.
        if ( 'maroon-horizon-smart-firewall' === $mhsf_current_dir ) {
            $candidates[] = 'maroon-horizon-smart-firewall-pro/' . basename( __FILE__ );
        }
    }
    // Filter to existing files if possible.
    if ( defined( 'WP_PLUGIN_DIR' ) ) {
        $existing = array();
        foreach ( $candidates as $candidate ) {
            $candidate = ltrim( (string) $candidate, '/' );
            if ( file_exists( WP_PLUGIN_DIR . '/' . $candidate ) ) {
                $existing[] = $candidate;
            }
        }
        if ( !empty( $existing ) ) {
            $candidates = $existing;
        }
    }
    $candidates = array_values( array_unique( array_filter( array_map( 'strval', $candidates ) ) ) );
    return $candidates;
};
$mhsf_runtime_conflict_check = static function ( array $other_candidates ) {
    $active_plugins = ( function_exists( 'get_option' ) ? (array) get_option( 'active_plugins', array() ) : array() );
    $sitewide = array();
    if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'get_site_option' ) ) {
        $sitewide = (array) get_site_option( 'active_sitewide_plugins', array() );
    }
    $conflict = array(
        'has_conflict'       => false,
        'other_basename'     => '',
        'other_network_wide' => false,
    );
    foreach ( $other_candidates as $candidate ) {
        if ( in_array( $candidate, $active_plugins, true ) ) {
            $conflict['has_conflict'] = true;
            $conflict['other_basename'] = $candidate;
            break;
        }
        if ( !empty( $sitewide ) && isset( $sitewide[$candidate] ) ) {
            $conflict['has_conflict'] = true;
            $conflict['other_basename'] = $candidate;
            $conflict['other_network_wide'] = true;
            break;
        }
    }
    return $conflict;
};
// Activation-time guard: if the other edition is active, self-deactivate and abort activation.
register_activation_hook( __FILE__, static function ( $network_wide ) use($mhsf_get_other_candidates, $mhsf_is_pro_edition, $mhsf_current_basename) {
    // Load plugin helpers when needed.
    if ( !function_exists( 'is_plugin_active' ) || !function_exists( 'is_plugin_active_for_network' ) || !function_exists( 'deactivate_plugins' ) || !function_exists( 'get_plugins' ) ) {
        $plugin_php = ABSPATH . 'wp-admin/includes/plugin.php';
        if ( file_exists( $plugin_php ) ) {
            require_once $plugin_php;
        }
    }
    $candidates = (array) $mhsf_get_other_candidates();
    // Fallback scan: find sibling edition via plugin headers.
    if ( function_exists( 'get_plugins' ) ) {
        $all = (array) get_plugins();
        $best = '';
        $best_score = -1;
        foreach ( $all as $basename => $data ) {
            if ( $basename === $mhsf_current_basename ) {
                continue;
            }
            $textdomain = ( isset( $data['TextDomain'] ) ? (string) $data['TextDomain'] : '' );
            $name = ( isset( $data['Name'] ) ? (string) $data['Name'] : '' );
            $plugin_uri = ( isset( $data['PluginURI'] ) ? (string) $data['PluginURI'] : '' );
            $looks_related = false;
            if ( 'maroon-horizon-smart-firewall' === $textdomain ) {
                $looks_related = true;
            } elseif ( false !== stripos( $name, 'Maroon Horizon Smart Firewall' ) || 0 === stripos( $name, 'MH Smart Firewall' ) ) {
                $looks_related = true;
            }
            // 1.8.3: no 'mh.ie in Plugin URI' match - every Maroon Horizon plugin has one; 1.8.17: new name 'MH Smart Firewall ...', the old name still counts
            if ( !$looks_related ) {
                continue;
            }
            $score = 0;
            if ( 'maroon-horizon-smart-firewall' === $textdomain ) {
                $score += 2;
            }
            if ( substr( $basename, -strlen( '/maroon-horizon-smart-firewall.php' ) ) === '/maroon-horizon-smart-firewall.php' ) {
                $score += 3;
            }
            // Prefer opposite edition folder naming.
            if ( $mhsf_is_pro_edition ) {
                if ( false === strpos( $basename, '-pro/' ) ) {
                    $score += 5;
                }
            } else {
                if ( false !== strpos( $basename, '-pro/' ) ) {
                    $score += 5;
                }
            }
            if ( $score > $best_score ) {
                $best = (string) $basename;
                $best_score = $score;
            }
        }
        if ( $best && !in_array( $best, $candidates, true ) ) {
            array_unshift( $candidates, $best );
        }
    }
    $has_conflict = false;
    $other_found = '';
    foreach ( $candidates as $candidate ) {
        $candidate = (string) $candidate;
        if ( function_exists( 'is_plugin_active' ) && is_plugin_active( $candidate ) ) {
            $has_conflict = true;
            $other_found = $candidate;
            break;
        }
        if ( function_exists( 'is_multisite' ) && is_multisite() && function_exists( 'is_plugin_active_for_network' ) && is_plugin_active_for_network( $candidate ) ) {
            $has_conflict = true;
            $other_found = $candidate;
            break;
        }
    }
    if ( !$has_conflict ) {
        return;
    }
    // 1.8.4 guided upgrade (Vlad option A): activating PRO while FREE is active = the upgrade. PRO switches FREE off and carries on
    // (license + settings are shared). FREE never deactivates anything (WordPress.org build), so FREE next to PRO stays blocked.
    if ( $mhsf_is_pro_edition && function_exists( 'deactivate_plugins' ) ) {
        deactivate_plugins( $other_found, true, (bool) $network_wide );
        update_option( 'mhsf_pro_welcome', 1, false );
        return;
    }
    // Self-deactivate (allowed) and abort activation.
    if ( function_exists( 'deactivate_plugins' ) ) {
        deactivate_plugins( $mhsf_current_basename, true, (bool) $network_wide );
    }
    $mhsf_this_name = ( $mhsf_is_pro_edition ? 'MH Smart Firewall Pro' : 'MH Smart Firewall' );
    $mhsf_other_name = ( $mhsf_is_pro_edition ? 'MH Smart Firewall' : 'MH Smart Firewall Pro' );
    $plugins_url = ( function_exists( 'network_admin_url' ) && $network_wide ? network_admin_url( 'plugins.php' ) : admin_url( 'plugins.php' ) );
    $message = '<p><strong>' . esc_html__( 'Plugin activation blocked', 'maroon-horizon-smart-firewall' ) . '</strong></p>';
    $message .= '<p>' . esc_html__( 'Only one edition of MH Smart Firewall can be active at a time.', 'maroon-horizon-smart-firewall' ) . '</p>';
    $message .= '<p>' . sprintf( 
        /* translators: 1: edition being activated, 2: edition currently active */
        esc_html__( 'You are trying to activate %1$s, but %2$s is currently active.', 'maroon-horizon-smart-firewall' ),
        '<strong>' . esc_html( $mhsf_this_name ) . '</strong>',
        '<strong>' . esc_html( $mhsf_other_name ) . '</strong>'
     ) . '</p>';
    $message .= '<p>' . sprintf( 
        /* translators: 1: edition to deactivate, 2: edition to activate */
        esc_html__( 'Please deactivate %1$s first, then activate %2$s again.', 'maroon-horizon-smart-firewall' ),
        '<strong>' . esc_html( $mhsf_other_name ) . '</strong>',
        '<strong>' . esc_html( $mhsf_this_name ) . '</strong>'
     ) . '</p>';
    $message .= '<p><a class="button button-primary" href="' . esc_url( $plugins_url ) . '">' . esc_html__( 'Go to Plugins', 'maroon-horizon-smart-firewall' ) . '</a></p>';
    wp_die( wp_kses_post( $message ), esc_html__( 'Plugin activation blocked', 'maroon-horizon-smart-firewall' ), array(
        'back_link' => true,
    ) );
} );
// Runtime guard (safety net).
$mhsf_other_candidates = (array) $mhsf_get_other_candidates();
$mhsf_conflict = $mhsf_runtime_conflict_check( $mhsf_other_candidates );
if ( !empty( $mhsf_conflict['has_conflict'] ) ) {
    if ( function_exists( 'add_action' ) && function_exists( 'is_admin' ) && is_admin() ) {
        $mhsf_this_name = ( $mhsf_is_pro_edition ? 'MH Smart Firewall Pro' : 'MH Smart Firewall' );
        $mhsf_other_name = ( $mhsf_is_pro_edition ? 'MH Smart Firewall' : 'MH Smart Firewall Pro' );
        $mhsf_notice_cb = static function () use($mhsf_this_name, $mhsf_other_name) {
            if ( !current_user_can( 'activate_plugins' ) && !(function_exists( 'is_network_admin' ) && is_network_admin() && current_user_can( 'manage_network_plugins' )) ) {
                return;
            }
            $plugins_url = ( function_exists( 'is_network_admin' ) && is_network_admin() && function_exists( 'network_admin_url' ) ? network_admin_url( 'plugins.php' ) : admin_url( 'plugins.php' ) );
            echo '<div class="notice notice-error">';
            echo '<p><strong>' . esc_html__( 'Edition conflict detected', 'maroon-horizon-smart-firewall' ) . '</strong></p>';
            echo '<p>' . esc_html__( 'Only one edition of MH Smart Firewall can be active at a time.', 'maroon-horizon-smart-firewall' ) . '</p>';
            echo '<p>' . sprintf( 
                /* translators: 1: active conflicting edition name, 2: this edition name */
                esc_html__( '%1$s is currently active. To use %2$s, please deactivate %1$s.', 'maroon-horizon-smart-firewall' ),
                '<strong>' . esc_html( $mhsf_other_name ) . '</strong>',
                '<strong>' . esc_html( $mhsf_this_name ) . '</strong>'
             ) . '</p>';
            echo '<p><a class="button button-primary" href="' . esc_url( $plugins_url ) . '">' . esc_html__( 'Go to Plugins', 'maroon-horizon-smart-firewall' ) . '</a></p>';
            echo '</div>';
        };
        add_action( 'admin_notices', $mhsf_notice_cb, 1 );
        add_action( 'network_admin_notices', $mhsf_notice_cb, 1 );
    }
    // Prevent Freemius SDK double-load and shared symbol collisions in this request.
    return;
}
// If an older variant is active and defines mhsf_fs(), avoid collisions.
if ( function_exists( 'mhsf_fs' ) && !defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    return;
}
// Freemius bootstrap (unique helper) + compatibility wrappers.
if ( !function_exists( 'mhsf_fs' ) ) {
    function mhsf_fs() {
        global $mhsf_fs;
        static $icon_hooked = false;
        if ( !isset( $mhsf_fs ) ) {
            $sdk_paths = array(dirname( __FILE__ ) . '/vendor/freemius/start.php', dirname( __FILE__ ) . '/vendor/freemius/freemius/start.php');
            $sdk_path = '';
            foreach ( $sdk_paths as $p ) {
                if ( file_exists( $p ) && is_readable( $p ) ) {
                    $sdk_path = $p;
                    break;
                }
            }
            if ( $sdk_path ) {
                require_once $sdk_path;
                // Detect whether this is the premium package (based on the deployed folder name).
                // Freemius deploys the premium build under the premium_slug folder.
                $mhsf_is_premium_build = basename( dirname( __FILE__ ) ) === 'maroon-horizon-smart-firewall-pro';
                $mhsf_fs = fs_dynamic_init( array(
                    'id'               => '22732',
                    'slug'             => 'maroon-horizon-smart-firewall',
                    'premium_slug'     => 'maroon-horizon-smart-firewall-pro',
                    'type'             => 'plugin',
                    'public_key'       => 'pk_c9f846bc68c45df4d6c746166b7b0',
                    'is_premium'       => false,
                    'premium_suffix'   => 'Pro',
                    'has_addons'       => false,
                    'has_paid_plans'   => true,
                    'anonymous_mode'   => !$mhsf_is_premium_build,
                    'is_org_compliant' => true,
                    'menu'             => array(
                        'slug'       => 'maroon-horizon-smart-firewall',
                        'first-path' => 'admin.php?page=sfais-dashboard',
                        'support'    => false,
                        'account'    => true,
                        'pricing'    => true,
                    ),
                    'is_live'          => true,
                ) );
                if ( is_object( $mhsf_fs ) && method_exists( $mhsf_fs, 'set_basename' ) ) {
                    $mhsf_fs->set_basename( $mhsf_is_premium_build, __FILE__ );
                }
                if ( is_object( $mhsf_fs ) && method_exists( $mhsf_fs, 'add_filter' ) ) {
                    // FREE (WordPress.org build) never deactivates other plugins. 1.8.4 guided upgrade (Vlad option A): activating
                    // PRO switches the FREE edition off (Freemius default) - PRO is not hosted on WordPress.org.
                    $mhsf_fs->add_filter( 'deactivate_on_activation', static function ( $deactivate ) use($mhsf_is_premium_build) {
                        return ( $mhsf_is_premium_build ? (bool) $deactivate : false );
                    } );
                    // Activation redirect behavior:
                    // - FREE build: do not redirect on activation (avoid forced opt-in/wizard).
                    // - PREMIUM build: allow Freemius to redirect to the license activation flow so
                    //   upgrades complete and premium entitlement is granted.
                    $mhsf_fs->add_filter( 'redirect_on_activation', static function ( $should_redirect ) use($mhsf_is_premium_build) {
                        return ( $mhsf_is_premium_build ? (bool) $should_redirect : false );
                    } );
                    // After connect/skip, optionally return to a caller-provided admin URL.
                    // This is used by our Settings "Opt-in" CTA and the first-run admin notice.
                    $mhsf_fs->add_filter( 'after_connect_url', static function ( $url ) {
                        $user_id = ( function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );
                        if ( $user_id > 0 ) {
                            $key = 'mhsf_fs_return_' . $user_id;
                            $stored = get_transient( $key );
                            if ( is_string( $stored ) && $stored !== '' ) {
                                delete_transient( $key );
                                return $stored;
                            }
                        }
                        return admin_url( 'admin.php?page=maroon-horizon-smart-firewall-account' );
                    } );
                    $mhsf_fs->add_filter( 'after_skip_url', static function ( $url ) {
                        $user_id = ( function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0 );
                        if ( $user_id > 0 ) {
                            $key = 'mhsf_fs_return_' . $user_id;
                            $stored = get_transient( $key );
                            if ( is_string( $stored ) && $stored !== '' ) {
                                delete_transient( $key );
                                return $stored;
                            }
                        }
                        return admin_url( 'plugins.php' );
                    } );
                }
            } else {
                $mhsf_fs = new MHSF_Freemius_Null();
            }
        }
        // Inject plugin icon into Freemius UI (optional).
        if ( !$icon_hooked && is_object( $mhsf_fs ) && method_exists( $mhsf_fs, 'add_filter' ) ) {
            $icon_hooked = true;
            $mhsf_fs->add_filter( 'plugin_icon', static function () {
                $icon_path = plugin_dir_path( __FILE__ ) . 'admin/img/sfais-logo-main.png';
                return ( file_exists( $icon_path ) && is_readable( $icon_path ) ? $icon_path : false );
            } );
        }
        return $mhsf_fs;
    }

}
// Initialize Freemius immediately.
$mhsf_fs_instance = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
if ( $mhsf_fs_instance ) {
    do_action( 'mhsf_fs_loaded' );
    // Freemius: run cleanup AFTER uninstall is reported (so feedback is not lost).
    $mhsf_fs_for_uninstall = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
    if ( $mhsf_fs_for_uninstall && method_exists( $mhsf_fs_for_uninstall, 'add_action' ) ) {
        $mhsf_fs_for_uninstall->add_action( 'after_uninstall', static function () {
            // 1.8.4: FREE and PRO share their settings. Deleting one edition while the other is still installed (e.g. FREE after the
            // upgrade to PRO) keeps everything; only the last edition removed cleans up.
            $mhsf_other = WP_PLUGIN_DIR . '/' . (( basename( __DIR__ ) === 'maroon-horizon-smart-firewall-pro' ? 'maroon-horizon-smart-firewall' : 'maroon-horizon-smart-firewall-pro' )) . '/maroon-horizon-smart-firewall.php';
            if ( file_exists( $mhsf_other ) ) {
                return;
            }
            // 1.8.15: first undo every change outside the data folder (permissions back, patch and IP Blocker .htaccess blocks,
            // marked index files) - the patches need their logs, which live in the data folder.
            if ( !class_exists( 'MHSF_Housekeeping' ) && file_exists( __DIR__ . '/includes/core/class-mhsf-housekeeping.php' ) ) {
                require_once __DIR__ . '/includes/core/class-mhsf-housekeeping.php';
            }
            if ( class_exists( 'MHSF_Housekeeping' ) ) {
                MHSF_Housekeeping::uninstall_files();
            }
            $mhsf_option_keys = array(
                'mhsf_ip_rules',
                'mhsf_optin_notice_dismissed',
                'mhsf_patch_toggles',
                'mhsf_scanner_ignored',
                'mhsf_settings',
                'mhsf_show_optin_notice',
                'sfais_ai_deep_history',
                'sfais_ai_deep_last_report',
                'sfais_ai_deep_scan_email',
                'sfais_ai_deep_scan_enabled',
                'sfais_backup_manual_age_ok',
                'sfais_backup_manual_found',
                'sfais_blocked_ips',
                'sfais_htaccess_safe',
                'sfais_ip_rules',
                'sfais_last_content_report',
                'sfais_last_core_report',
                'sfais_last_quick_check',
                'sfais_last_quick_rating',
                'sfais_manual_2fa_enabled',
                'sfais_manual_strong_passwords',
                'sfais_patch_author_enum',
                'sfais_patch_dirlisting',
                'sfais_patch_dirlisting_last_report',
                'sfais_patch_fileedit',
                'sfais_patch_filemods',
                'sfais_patch_force_ssl',
                'sfais_patch_permissions',
                'sfais_patch_permissions_last_report',
                'sfais_patch_php_wpcontent',
                'sfais_patch_toggles',
                'sfais_patch_versioninfo',
                'sfais_patch_wpconfig',
                'sfais_patch_xmlrpc',
                'sfais_scanner_ignored',
                'sfais_settings',
                'sfais_threat_feed_meta',
                'sfais_threat_feed_subnets',
                'sfais_threat_feed_mode',
                'sfais_threat_feed_autosync',
                'sfais_ai_model_data',
                'sfais_ai_model_meta',
                'mhsf_cloud_meta',
                'mhsf_cloud_fw',
                'mhsf_block_tor'
            );
            foreach ( $mhsf_option_keys as $mhsf_key ) {
                delete_option( $mhsf_key );
                if ( is_multisite() ) {
                    delete_site_option( $mhsf_key );
                }
            }
            // Transients.
            delete_transient( 'mhsf_upgrade_error' );
            delete_transient( 'sfais_upgrade_error' );
            if ( class_exists( 'MHSF_Pro_Cloud' ) ) {
                MHSF_Pro_Cloud::purge();
                // 1.8.3: PRO data files + daily sync event
            }
            // 1.8.15: last - the whole data folder (reports, quarantine, logs, PRO data), the options missing above, every
            // sfais_/mhsf_ transient, the Appearance user meta and every plugin cron event.
            if ( class_exists( 'MHSF_Housekeeping' ) ) {
                MHSF_Housekeeping::uninstall_data();
            }
        } );
    }
}
/*
 * 1.8.5 (Vlad option A): the FREE version has NO opt-in. Freemius runs in anonymous_mode, which never creates its opt-in page, so
 * every opt-in button or link ended on "Sorry, you are not allowed to access this page". FREE sends Freemius nothing; the only outside
 * requests are the ones the user starts (integrity check checksums from WordPress.org, the Freemius checkout behind "Upgrade to PRO").
 * Freemius's own "Opt In" link on the Plugins screen is removed as well. Old opt-in flags are cleaned once.
 */
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), static function ( $links ) {
    if ( defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE ) {
        return $links;
    }
    foreach ( (array) $links as $k => $html ) {
        if ( false !== strpos( (string) $k, 'opt-in-or-opt-out' ) || is_string( $html ) && false !== strpos( $html, 'opt-in-or-opt-out' ) ) {
            // Freemius puts the marker in the key
            unset($links[$k]);
        }
    }
    return $links;
}, PHP_INT_MAX );
add_action( 'admin_init', static function () {
    if ( false !== get_option( 'mhsf_show_optin_notice', false ) || false !== get_option( 'mhsf_optin_notice_dismissed', false ) ) {
        delete_option( 'mhsf_show_optin_notice' );
        delete_option( 'mhsf_optin_notice_dismissed' );
    }
} );
/**
 * 1.8.4: ONE clear first-run notice. Freemius's own "We made a few tweaks... Opt in" and "W00t! Premium ... activated"
 * notices repeat ours (FREE: the optional opt-in box below; PRO: "Activate License"), so they are removed before WordPress
 * prints them (removal also clears them for this page load).
 */
add_action( 'admin_notices', static function () {
    $fs = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
    if ( is_object( $fs ) && method_exists( $fs, 'remove_sticky' ) ) {
        $fs->remove_sticky( array('connect_account', 'premium_activated') );
    }
}, 1 );
/**
 * 1.8.4 guided upgrade (Vlad option A, 25 Oct). After PRO is bought inside the FREE plugin, ONE panel shows the two steps (Download PRO,
 * Upload & activate). WordPress.org guideline 8 forbids the FREE plugin installing PRO itself. Activating PRO then switches FREE off and
 * takes over the license (same site connection) and all settings. No feature is unlocked in FREE by this - it is a download prompt only.
 */
if ( !function_exists( 'mhsf_free_has_paid_pro' ) ) {
    function mhsf_free_has_paid_pro() {
        if ( defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE ) {
            return false;
        }
        $fs = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
        return is_object( $fs ) && method_exists( $fs, 'is_registered' ) && $fs->is_registered() && method_exists( $fs, 'can_use_premium_code' ) && $fs->can_use_premium_code();
    }

}
if ( !function_exists( 'mhsf_free_pro_next_step' ) ) {
    /**
     * Where the FREE edition sends a customer who already paid: the PRO download, or (PRO already uploaded) its activation link.
     *
     * @return array{url:string,installed:bool}
     */
    function mhsf_free_pro_next_step() {
        $pro = 'maroon-horizon-smart-firewall-pro/maroon-horizon-smart-firewall.php';
        if ( file_exists( WP_PLUGIN_DIR . '/' . $pro ) ) {
            return array(
                'url'       => wp_nonce_url( admin_url( 'plugins.php?action=activate&plugin=' . rawurlencode( $pro ) ), 'activate-plugin_' . $pro ),
                'installed' => true,
            );
        }
        $fs = mhsf_fs();
        return array(
            'url'       => ( method_exists( $fs, '_get_latest_download_local_url' ) ? (string) $fs->_get_latest_download_local_url() : admin_url( 'admin.php?page=maroon-horizon-smart-firewall-account' ) ),
            'installed' => false,
        );
    }

}
add_action( 'admin_notices', static function () {
    if ( !current_user_can( 'install_plugins' ) || !mhsf_free_has_paid_pro() ) {
        return;
    }
    // Freemius's own "Yee-haw! ... Please follow these steps" notices say the same less clearly.
    mhsf_fs()->remove_sticky( array(
        'license_activated',
        'plan_upgraded',
        'trial_started',
        'premium_activated'
    ) );
    $screen = ( function_exists( 'get_current_screen' ) ? get_current_screen() : null );
    $id = ( is_object( $screen ) ? (string) $screen->id : '' );
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing parameter only.
    $page = ( isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '' );
    if ( 0 !== strpos( $page, 'sfais-' ) && 0 !== strpos( $page, 'maroon-horizon-smart-firewall' ) && !in_array( $id, array('dashboard', 'plugins'), true ) ) {
        return;
    }
    $next = mhsf_free_pro_next_step();
    echo '<div class="notice notice-success" style="padding:12px 14px;border-left-width:4px;">';
    echo '<h2 style="margin:0 0 6px;">' . esc_html__( 'Thank you! Your MH Smart Firewall PRO license is ready.', 'maroon-horizon-smart-firewall' ) . '</h2>';
    if ( $next['installed'] ) {
        echo '<p style="margin:0 0 10px;">' . esc_html__( 'PRO is already uploaded. One click to switch it on:', 'maroon-horizon-smart-firewall' ) . '</p>';
        echo '<p style="margin:0 0 10px;"><a class="button button-primary button-hero" href="' . esc_url( $next['url'] ) . '">' . esc_html__( 'Activate PRO', 'maroon-horizon-smart-firewall' ) . '</a></p>';
    } else {
        echo '<p style="margin:0 0 10px;">' . esc_html__( 'Two steps to switch on PRO on this site:', 'maroon-horizon-smart-firewall' ) . '</p>';
        echo '<p style="margin:0 0 8px;"><a class="button button-primary" href="' . esc_url( $next['url'] ) . '">' . esc_html__( '1. Download PRO', 'maroon-horizon-smart-firewall' ) . '</a> ';
        echo '<span class="description">' . esc_html__( 'saves a .zip file to your computer', 'maroon-horizon-smart-firewall' ) . '</span></p>';
        echo '<p style="margin:0 0 10px;"><a class="button" href="' . esc_url( admin_url( 'plugin-install.php?tab=upload' ) ) . '">' . esc_html__( '2. Upload & activate', 'maroon-horizon-smart-firewall' ) . '</a> ';
        echo '<span class="description">' . esc_html__( 'choose the .zip, click Install Now, then Activate Plugin', 'maroon-horizon-smart-firewall' ) . '</span></p>';
    }
    echo '<p class="description" style="margin:0;">' . esc_html__( 'When PRO is activated it switches this free version off, takes over your license automatically and keeps all your settings.', 'maroon-horizon-smart-firewall' ) . '</p>';
    echo '</div>';
}, 5 );
/**
 * 1.8.4: ONE menu. Before the licence is activated Freemius adds its own top-level "Maroon Horizon Smart Firewall" entry for
 * its licence screen. Our menu already links there ("Activate License"), so only the extra entry is hidden - the page stays.
 */
add_action( 'admin_menu', static function () {
    $fs = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
    if ( is_object( $fs ) && method_exists( $fs, 'is_activation_mode' ) && $fs->is_activation_mode() ) {
        remove_menu_page( 'maroon-horizon-smart-firewall' );
    }
}, PHP_INT_MAX );
/**
 * Bridge page for "Already purchased? Manage Account".
 *
 * IMPORTANT:
 * Do NOT redirect from inside the page renderer callback.
 * WordPress outputs admin markup before calling the callback, which causes
 * "headers already sent" warnings when using wp_safe_redirect().
 *
 * We redirect early on admin_init (before output), and keep a hidden page
 * registration so the route exists.
 */
// Early redirect before any admin output is sent.
add_action( 'admin_menu', static function () {
    $target = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-account' );
    $render = static function () use($target) {
        // Renderer fallback: do not rely on headers (avoids "headers already sent").
        echo '<div class="wrap">';
        echo '<h1>' . esc_html__( 'Redirecting…', 'maroon-horizon-smart-firewall' ) . '</h1>';
        echo '<p>' . esc_html__( 'If you are not redirected automatically, use the link below:', 'maroon-horizon-smart-firewall' ) . '</p>';
        echo '<p><a class="button button-primary" href="' . esc_url( $target ) . '">' . esc_html__( 'Open Account', 'maroon-horizon-smart-firewall' ) . '</a></p>';
        echo '</div>';
    };
    foreach ( array('maroon-horizon-smart-firewall-manage-account', 'mhsf-manage-account') as $slug ) {
        $hook = add_submenu_page(
            null,
            'Manage Account',
            'Manage Account',
            'manage_options',
            $slug,
            $render
        );
        if ( $hook ) {
            add_action( 'load-' . $hook, static function () use($target) {
                if ( !current_user_can( 'manage_options' ) ) {
                    wp_die( esc_html__( 'Sorry, you are not allowed to access this page.', 'maroon-horizon-smart-firewall' ) );
                }
                wp_safe_redirect( $target );
                exit;
            } );
        }
    }
}, 20 );
/**
 * ================================
 * PLUGIN CONSTANTS
 * ================================
 */
if ( !defined( 'SFAIS_PATH' ) ) {
    define( 'SFAIS_PATH', plugin_dir_path( __FILE__ ) );
}
if ( !defined( 'SFAIS_PLUGIN_FILE' ) ) {
    define( 'SFAIS_PLUGIN_FILE', __FILE__ );
}
// Canonical plugin location constants.
if ( !defined( 'MHSF_PLUGIN_FILE' ) ) {
    define( 'MHSF_PLUGIN_FILE', __FILE__ );
}
if ( !defined( 'MHSF_PLUGIN_DIR' ) ) {
    define( 'MHSF_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}
if ( !defined( 'MHSF_PLUGIN_URL' ) ) {
    define( 'MHSF_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}
// Path helpers (uploads/{plugin-slug}/...).
$mhsf_paths_file = SFAIS_PATH . 'includes/core/mhsf-paths.php';
if ( file_exists( $mhsf_paths_file ) ) {
    require_once $mhsf_paths_file;
}
// 1.8.15: activity log for the Dashboard's Recent activity (both editions)
require_once SFAIS_PATH . 'includes/core/mhsf-activity.php';
if ( !defined( 'SFAIS_URL' ) ) {
    define( 'SFAIS_URL', plugin_dir_url( __FILE__ ) );
}
if ( !defined( 'SFAIS_BASENAME' ) ) {
    define( 'SFAIS_BASENAME', plugin_basename( __FILE__ ) );
}
if ( !defined( 'SFAIS_VERSION' ) ) {
    define( 'SFAIS_VERSION', '1.8.17' );
}
/**
 * =======================================
 * BUILD / ENTITLEMENT FLAGS
 * =======================================
 *
 * - FREE build (WP.org): contains no premium runtime code.
 * - PRO build: includes premium runtime code under /includes/pro/ and premium-only core modules.
 *
 * NOTE: Any license/entitlement checks live only in the PRO build (and are stripped from the FREE artifact).
 */
if ( !defined( 'SFAIS_IS_PREMIUM_CODE' ) ) {
    define( 'SFAIS_IS_PREMIUM_CODE', basename( dirname( __FILE__ ) ) === 'maroon-horizon-smart-firewall-pro' );
}
/**
 * CORE FUNCTIONALITY (FREE + PRO)
 */
require_once SFAIS_PATH . 'includes/core/class-sfais-fs.php';
// 1.8.15: housekeeping (daily + hourly clean-up, Run clean-up now, uninstall clean-up) - FREE + PRO.
require_once SFAIS_PATH . 'includes/core/class-mhsf-housekeeping.php';
MHSF_Housekeeping::init();
// Patch manager: the premium build may load the premium override earlier.
// In the FREE build, only the lite implementation exists.
if ( !class_exists( 'SFAIS_Patch_Manager', false ) ) {
    require_once SFAIS_PATH . 'includes/core/class-sfais-patch-manager.php';
}
require_once SFAIS_PATH . 'includes/core/class-sfais-ip-manager.php';
require_once SFAIS_PATH . 'includes/core/class-sfais-security-check.php';
require_once SFAIS_PATH . 'includes/core/class-sfais-login-guard.php';
require_once SFAIS_PATH . 'includes/core/class-sfais-bot-protection.php';
// Functions: the premium build may load the premium override earlier.
// In the FREE build, only the lite implementation exists.
if ( !class_exists( 'SFAIS_Functions', false ) ) {
    require_once SFAIS_PATH . 'includes/core/class-sfais-functions.php';
}
/**
 * ADMIN UI
 */
if ( is_admin() ) {
    require_once SFAIS_PATH . 'admin/class-sfais-admin-ui.php';
}
/**
 * DEACTIVATION CLEANUP
 */
if ( function_exists( 'register_deactivation_hook' ) ) {
    register_deactivation_hook( __FILE__, 'mhsf_deactivate_plugin' );
}
if ( !function_exists( 'mhsf_deactivate_plugin' ) ) {
    function mhsf_deactivate_plugin() {
        /**
         * Deactivation cleanup is intentionally delegated to edition-specific modules.
         *
         * FREE must not contain premium cron hook identifiers or premium background job code.
         */
        if ( function_exists( 'do_action' ) ) {
            do_action( 'mhsf_deactivate_cleanup' );
        }
    }

}
/**
 * IMPORTANT:
 * We intentionally DO NOT register our own "maroon-horizon-smart-firewall-account" page.
 * Freemius registers and renders it natively once connected.
 * Overriding it causes duplicated output.
 */