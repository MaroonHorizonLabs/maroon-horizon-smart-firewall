<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
class SFAIS_Admin_UI {
    public function __construct() {
        add_action( 'admin_menu', [$this, 'register_menu'] );
        add_action( 'admin_enqueue_scripts', [$this, 'menu_icon_css'] );
        // 1.8.7 design: per-user Appearance (Auto / Light / Dark) -> body class on the plugin's own screens.
        add_filter( 'admin_body_class', [$this, 'appearance_body_class'] );
        add_action( 'admin_post_mhsf_set_appearance', [$this, 'save_appearance'] );
        // The "sfais-upgrade" admin page is rendered as a safe CTA page (no redirects).
        add_action(
            'admin_enqueue_scripts',
            [$this, 'enqueue_assets'],
            10,
            1
        );
    }

    /**
     * Menu icon (Vlad 25 Oct: variant A) - the official logo's shield outline + brain with circuit dots, as a CSS mask filled with
     * currentColor: it takes EXACTLY the colour WordPress gives its own menu icons in every colour scheme, hover and active state.
     * (A data-URI icon is painted by svg-painter.js with the scheme's "icons.base" colour, which in the Light scheme is #999 while
     * the built-in icons are #6a6a6a - so plugin icons looked lighter there.)
     */
    const MENU_ICON_SVG_BASE64 = 'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0iYmxhY2siIGZpbGwtcnVsZT0iZXZlbm9kZCIgZD0iTTEyLjAgMi4wIFExNS45IDMuOSAyMC42IDQuNiBMMjAuNiAxMS4wIEMyMC42IDE1LjYgMTcuMCAxOS42IDEyLjAgMjIuMCBDNy4wIDE5LjYgMy40IDE1LjYgMy40IDExLjAgTDMuNCA0LjYgUTguMSAzLjkgMTIuMCAyLjAgWiBNMTIuMCAzLjY0OCBRMTUuMjc2IDUuMjQ0IDE5LjIyNCA1LjgzMiBMMTkuMjI0IDExLjIwOCBDMTkuMjI0IDE1LjA3MiAxNi4yIDE4LjQzMiAxMi4wIDIwLjQ0OCBDNy44IDE4LjQzMiA0Ljc3NiAxNS4wNzIgNC43NzYgMTEuMjA4IEw0Ljc3NiA1LjgzMiBROC43MjQgNS4yNDQgMTIuMCAzLjY0OCBaIE0xMS41NSA3LjMgQzEwLjAgNi40IDguMyA2LjggNy45IDguMSBDNi41IDguMiA2LjAgOS45IDYuOCAxMC45IEM1LjggMTEuOCA2LjAgMTMuNiA3LjMgMTQuMCBDNy4wIDE1LjQgOC4xIDE2LjcgOS41IDE2LjQgQzEwLjAgMTcuNCAxMS4xIDE3LjUgMTEuNTUgMTcuMCBaIE0xMi40NSA3LjMgQzE0LjAgNi40IDE1LjcgNi44IDE2LjEgOC4xIEMxNy41IDguMiAxOC4wIDkuOSAxNy4yIDEwLjkgQzE4LjIgMTEuOCAxOC4wIDEzLjYgMTYuNyAxNC4wIEMxNy4wIDE1LjQgMTUuOSAxNi43IDE0LjUgMTYuNCBDMTQuMCAxNy40IDEyLjkgMTcuNSAxMi40NSAxNy4wIFogTTguNTIgMTAuMCBhMC43OCAwLjc4IDAgMSAwIDEuNTYgMCBhMC43OCAwLjc4IDAgMSAwIC0xLjU2IDAgWiBNNy45MiAxMy4xIGEwLjc4IDAuNzggMCAxIDAgMS41NiAwIGEwLjc4IDAuNzggMCAxIDAgLTEuNTYgMCBaIE05LjQ4IDE1LjAgYTAuNjIgMC42MiAwIDEgMCAxLjI0IDAgYTAuNjIgMC42MiAwIDEgMCAtMS4yNCAwIFogTTEzLjkyIDEwLjAgYTAuNzggMC43OCAwIDEgMCAxLjU2IDAgYTAuNzggMC43OCAwIDEgMCAtMS41NiAwIFogTTE0LjUyIDEzLjEgYTAuNzggMC43OCAwIDEgMCAxLjU2IDAgYTAuNzggMC43OCAwIDEgMCAtMS41NiAwIFogTTEzLjI4IDE1LjAgYTAuNjIgMC42MiAwIDEgMCAxLjI0IDAgYTAuNjIgMC42MiAwIDEgMCAtMS4yNCAwIFoiLz48L3N2Zz4=';

    public function menu_icon_css() {
        $mask = 'url("data:image/svg+xml;base64,' . self::MENU_ICON_SVG_BASE64 . '") no-repeat center / 20px 20px';
        wp_add_inline_style( 
            'admin-menu',
            // WordPress's own menu stylesheet - loaded on every admin page
            '#adminmenu #toplevel_page_sfais-dashboard div.wp-menu-image::before{content:"";display:block;width:20px;height:20px;padding:0;margin:7px auto 0;' . 'background-color:currentColor;-webkit-mask:' . $mask . ';mask:' . $mask . ';}'
         );
    }

    /** Appearance of the plugin screens for the current user: auto (follows the computer) | light | dark. */
    public static function appearance() {
        $v = (string) get_user_meta( get_current_user_id(), 'mhsf_appearance', true );
        return ( in_array( $v, array('auto', 'light', 'dark'), true ) ? $v : 'auto' );
    }

    private static function is_plugin_screen() {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- routing parameter only.
        $page = ( isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '' );
        return '' !== $page && 0 === strpos( $page, 'sfais-' );
    }

    public function appearance_body_class( $classes ) {
        return ( self::is_plugin_screen() ? $classes . ' mhsf-ui-' . self::appearance() . ' ' : $classes );
    }

    public function save_appearance() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'maroon-horizon-smart-firewall' ) );
        }
        check_admin_referer( 'mhsf_set_appearance' );
        $v = ( isset( $_POST['mhsf_appearance'] ) ? sanitize_key( wp_unslash( $_POST['mhsf_appearance'] ) ) : 'auto' );
        update_user_meta( get_current_user_id(), 'mhsf_appearance', ( in_array( $v, array('auto', 'light', 'dark'), true ) ? $v : 'auto' ) );
        wp_safe_redirect( admin_url( 'admin.php?page=sfais-settings#mhsf-appearance' ) );
        exit;
    }

    public function register_menu() {
        // Top-level menu
        add_menu_page(
            'Maroon Horizon Smart Firewall',
            // page title
            'MH Smart Firewall',
            // menu title (short, text only)
            'manage_options',
            // capability
            'sfais-dashboard',
            // slug
            [$this, 'render_admin_page'],
            // callback
            'none',
            // icon: drawn by menu_icon_css() (WordPress: "'none' ... so an icon can be added via CSS")
            65
        );
        // Explicit Dashboard submenu (so first child is "Dashboard")
        add_submenu_page(
            'sfais-dashboard',
            'Dashboard',
            'Dashboard',
            'manage_options',
            'sfais-dashboard',
            [$this, 'render_admin_page']
        );
        add_submenu_page(
            'sfais-dashboard',
            'IP Blocker',
            'IP Blocker',
            'manage_options',
            'sfais-ip-blocker',
            [$this, 'render_admin_page']
        );
        add_submenu_page(
            'sfais-dashboard',
            'Security Patches',
            'Security Patches',
            'manage_options',
            'sfais-patches',
            [$this, 'render_admin_page']
        );
        add_submenu_page(
            'sfais-dashboard',
            'Malware Scanner',
            'Malware Scanner',
            'manage_options',
            'sfais-scanner',
            [$this, 'render_admin_page']
        );
        add_submenu_page(
            'sfais-dashboard',
            'Settings',
            'Settings',
            'manage_options',
            'sfais-settings',
            [$this, 'render_admin_page']
        );
        // IMPORTANT:
        // Edition detection MUST NOT depend on license state.
        // In the WP.org FREE package, a license activation (Manage Account) must not flip the UI to "active".
        // Therefore, determine "active" strictly by codebase presence (premium package), not by entitlement.
        $is_pro_package = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
        $sfais_paid = !$is_pro_package && function_exists( 'mhsf_free_has_paid_pro' ) && mhsf_free_has_paid_pro();
        // 1.8.4 guided upgrade
        $menu_title = ( $is_pro_package ? apply_filters( 'mhsf_ui_pro_active_label', 'Active' ) : (( $sfais_paid ? __( 'Get PRO', 'maroon-horizon-smart-firewall' ) : 'Upgrade to PRO' )) );
        $page_title = $menu_title;
        // IMPORTANT: Use a normal WP slug and redirect in callback (do not use external URL as slug).
        add_submenu_page(
            'sfais-dashboard',
            $page_title,
            $menu_title,
            'manage_options',
            'sfais-upgrade',
            [$this, 'upgrade_or_account_redirect']
        );
        // Make the submenu item link directly to the Freemius pricing/account page (no redirect needed).
        // We keep the sfais-upgrade page registered so direct access still works.
        $target_url = $this->get_upgrade_menu_target_url( $is_pro_package );
        if ( !empty( $target_url ) ) {
            global $submenu;
            if ( isset( $submenu['sfais-dashboard'] ) && is_array( $submenu['sfais-dashboard'] ) ) {
                foreach ( $submenu['sfais-dashboard'] as $idx => $item ) {
                    if ( isset( $item[2] ) && $item[2] === 'sfais-upgrade' ) {
                        // Prefer relative admin.php?... when possible so WP adds the correct admin base URL.
                        $submenu['sfais-dashboard'][$idx][2] = $this->normalize_admin_menu_url( $target_url );
                        break;
                    }
                }
            }
        }
    }

    public function enqueue_assets( $hook ) {
        // Load assets only on our plugin screens.
        //
        // Do NOT rely on $hook containing a specific string. Hook names can vary
        // by environment and by how the admin menu was registered. The most
        // reliable signal is the requested admin page slug.
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Routing parameter in wp-admin (no state change).
        $page = ( isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '' );
        if ( $page === '' || strpos( $page, 'sfais-' ) !== 0 ) {
            return;
        }
        $css_path = ( defined( 'SFAIS_PATH' ) ? SFAIS_PATH . 'admin/css/sfais-admin.css' : '' );
        $js_path = ( defined( 'SFAIS_PATH' ) ? SFAIS_PATH . 'admin/js/sfais-tabs.js' : '' );
        $ver_css = ( defined( 'SFAIS_VERSION' ) ? SFAIS_VERSION : (( $css_path && file_exists( $css_path ) ? (string) filemtime( $css_path ) : '1.0.0' )) );
        $ver_js = ( defined( 'SFAIS_VERSION' ) ? SFAIS_VERSION : (( $js_path && file_exists( $js_path ) ? (string) filemtime( $js_path ) : '1.0.0' )) );
        // Main CSS + Tabs JS
        wp_enqueue_style(
            'sfais-admin-css',
            SFAIS_URL . 'admin/css/sfais-admin.css',
            [],
            $ver_css
        );
        // 1.8.7 design layer (dark + light looks, header, tabs, cards, switches) - after the main stylesheet.
        wp_enqueue_style(
            'mhsf-ui-css',
            SFAIS_URL . 'admin/css/mhsf-ui.css',
            ['sfais-admin-css'],
            $ver_css
        );
        wp_enqueue_script(
            'sfais-tabs-js',
            SFAIS_URL . 'admin/js/sfais-tabs.js',
            ['jquery', 'wp-i18n'],
            $ver_js,
            true
        );
        // Additional admin JS (migrated from inline script blocks for WP.org compliance)
        // Choose FREE or PRO runtime assets by codebase presence + entitlement.
        $premium_code = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
        $entitled = false;
        $ipb_rel = 'admin/js/sfais-ip-blocker.js';
        $scn_rel = 'admin/js/sfais-scanner.js';
        $ipb_js_file = ( defined( 'SFAIS_PATH' ) ? SFAIS_PATH . $ipb_rel : '' );
        $scn_js_file = ( defined( 'SFAIS_PATH' ) ? SFAIS_PATH . $scn_rel : '' );
        $ipb_js_url = SFAIS_URL . $ipb_rel;
        $scn_js_url = SFAIS_URL . $scn_rel;
        $ver_ipb = ( defined( 'SFAIS_VERSION' ) ? SFAIS_VERSION : (( $ipb_js_file && file_exists( $ipb_js_file ) ? (string) filemtime( $ipb_js_file ) : '1.0.0' )) );
        $ver_scn = ( defined( 'SFAIS_VERSION' ) ? SFAIS_VERSION : (( $scn_js_file && file_exists( $scn_js_file ) ? (string) filemtime( $scn_js_file ) : '1.0.0' )) );
        wp_enqueue_script(
            'sfais-ip-blocker-js',
            $ipb_js_url,
            ['sfais-tabs-js'],
            $ver_ipb,
            true
        );
        wp_enqueue_script(
            'sfais-scanner-js',
            $scn_js_url,
            ['sfais-tabs-js'],
            $ver_scn,
            true
        );
        // Data for migrated scripts (use wp_add_inline_script instead of echoing script tags in templates).
        $ipb_data = [
            'ajaxurl'       => admin_url( 'admin-ajax.php' ),
            'htLockNonce'   => wp_create_nonce( 'sfais_htaccess_lock_action' ),
            'countryLabels' => [],
        ];
        wp_add_inline_script( 'sfais-ip-blocker-js', 'window.sfaisIpBlockerData = ' . wp_json_encode( $ipb_data ) . ';', 'before' );
        // Scanner data
        $scanner_entitled = false;
        // Deep Scan report exists only in the premium build.
        $last_ai_deep_report = null;
        $scanner_data = [
            'ajaxurl'     => admin_url( 'admin-ajax.php' ),
            'nonce'       => wp_create_nonce( 'sfais_scanner_nonce' ),
            'lastCore'    => get_option( 'sfais_last_core_report' ),
            'lastContent' => get_option( 'sfais_last_content_report' ),
            'lastAiDeep'  => $last_ai_deep_report,
            'isPro'       => $scanner_entitled,
        ];
        wp_add_inline_script( 'sfais-scanner-js', 'window.sfaisScannerData = ' . wp_json_encode( $scanner_data ) . ';', 'before' );
        // Enable JS translations (optional; falls back to English if no JSON is present)
        if ( function_exists( 'wp_set_script_translations' ) ) {
            wp_set_script_translations( 'sfais-tabs-js', 'maroon-horizon-smart-firewall', ( defined( 'SFAIS_PATH' ) ? SFAIS_PATH . 'languages' : null ) );
        }
        // Inline admin CSS (menu tweaks + "Upgrade/Active" highlight + logo animation).
        $inline_css = '
			/* Constrain SVG icon to normal WP menu icon size */
			#adminmenu .toplevel_page_sfais-dashboard .wp-menu-image img {
				width: 20px !important;
				height: 20px !important;
				max-width: 20px !important;
				max-height: 20px !important;
				display: block;
			}

			/* Keep label on a single line so it does not drop under the icon */
			#adminmenu .toplevel_page_sfais-dashboard .wp-menu-name {
				white-space: nowrap;
			}

			/* Highlight the Upgrade/Active submenu item */
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="page=sfais-upgrade"],
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="maroon-horizon-smart-firewall-pricing"],
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="maroon-horizon-smart-firewall-account"],
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href$="page=maroon-horizon-smart-firewall"] {
				background: rgba(255, 120, 60, 0.14) !important;
				font-weight: 600;
				border-radius: 2px;
				margin: 2px 0;
			}
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="page=sfais-upgrade"]:hover,
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="maroon-horizon-smart-firewall-pricing"]:hover,
			#adminmenu .toplevel_page_sfais-dashboard .wp-submenu a[href*="maroon-horizon-smart-firewall-account"]:hover {
				background: rgba(255, 120, 60, 0.22) !important;
				color: #fff !important;
			}

			/* Active header button */
			.sfais-pro-active-btn {
				background: #e6f9ec !important;
				border-color: #2e7d32 !important;
				color: #2e7d32 !important;
				font-weight: 600;
			}
			.sfais-pro-active-btn:hover {
				background: #2e7d32 !important;
				color: #ffffff !important;
				border-color: #2e7d32 !important;
			}

			
			/* Header CTA layout (match Settings > License & Account) */
			.sfais-header-actions {
				display: flex;
				gap: 8px;
				align-items: center;
				flex-wrap: wrap;
			}

/* Dashicons inside header buttons */
			.sfais-header-actions .dashicons {
				vertical-align: middle;
				margin-right: 6px;
				line-height: 1;
			}

			/* HEADER LOGO ANIMATION */
			.sfais-logo-animated {
				display: flex;
				align-items: center;
				gap: 10px;
			}
			.sfais-logo-title {
				margin: 0;
				font-size: 22px;
			}
			.sfais-logo-mark {
				position: relative;
				width: 42px;
				height: 42px;
				border-radius: 14px;
				overflow: visible;
			}
			.sfais-logo-mark img {
				width: 100%;
				height: 100%;
				display: block;
				border-radius: 14px;
				position: relative;
				z-index: 2;
			}

			/* Outer orbit rings around the logo */
			.sfais-logo-mark::before,
			.sfais-logo-mark::after {
				content: "";
				position: absolute;
				inset: -4px;
				border-radius: 50%;
				border: 1px solid rgba(255, 60, 60, 0.4);
				box-sizing: border-box;
				animation: sfais-orbit 5s linear infinite;
				z-index: 1;
			}
			.sfais-logo-mark::after {
				inset: -9px;
				border-color: rgba(255, 60, 60, 0.22);
				animation-duration: 8s;
				animation-direction: reverse;
			}

			/* Pulsing glow behind the logo */
			.sfais-logo-glow {
				position: absolute;
				inset: 4px;
				border-radius: 14px;
				box-shadow:
					0 0 10px rgba(255, 60, 60, 0.65),
					0 0 20px rgba(255, 60, 60, 0.45);
				opacity: 0;
				animation: sfais-pulse-glow 2.6s ease-in-out infinite;
				pointer-events: none;
				z-index: 0;
			}

			@keyframes sfais-orbit {
				0%   { transform: rotate(0deg); }
				100% { transform: rotate(360deg); }
			}
			@keyframes sfais-pulse-glow {
				0%   { opacity: 0; transform: scale(0.96); }
				40%  { opacity: 1; transform: scale(1.03); }
				100% { opacity: 0; transform: scale(0.97); }
			}
		';
        wp_add_inline_style( 'sfais-admin-css', $inline_css );
    }

    /**
     * Normalize an admin URL to a relative admin.php?... form when possible.
     * This keeps submenu links stable across different site URLs.
     */
    private function normalize_admin_menu_url( $url ) {
        $url = (string) $url;
        if ( $url === '' ) {
            return '';
        }
        // Strip the admin base if the URL points to the same site.
        $admin_base = admin_url( '/' );
        if ( $admin_base && strpos( $url, $admin_base ) === 0 ) {
            return ltrim( substr( $url, strlen( $admin_base ) ), '/' );
        }
        // Best-effort: strip everything up to /wp-admin/ (covers non-standard admin_url() cases).
        $pos = strpos( $url, '/wp-admin/' );
        if ( $pos !== false ) {
            return ltrim( substr( $url, $pos + 10 ), '/' );
        }
        return $url;
    }

    /**
     * Returns the best target URL for the "Upgrade to PRO" / "active" submenu.
     *
     * Prefer Freemius-generated URLs when available.
     */
    private function get_upgrade_menu_target_url( $is_pro ) {
        $fs = ( function_exists( 'mhsf_fs' ) ? mhsf_fs() : false );
        $fallback_url = apply_filters( 'sfais_fallback_upgrade_url', 'https://mh.ie/' );
        // If Freemius is available, prefer the internal WP admin pages *without* forcing a billing cycle.
        // This avoids edge cases where a specific cycle isn't configured (or causes redirects).
        if ( $fs ) {
            $pricing_admin = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-pricing' );
            $account_admin = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-account' );
            // 1.8.4: the PRO package without a licence goes to the licence screen (filter lives in the PRO-only UI text file).
            if ( !$is_pro && function_exists( 'mhsf_free_has_paid_pro' ) && mhsf_free_has_paid_pro() ) {
                $next = mhsf_free_pro_next_step();
                // 1.8.4: already paid - the download (or activation), not the pricing page
                return $next['url'];
            }
            return ( $is_pro ? (string) apply_filters( 'mhsf_ui_pro_target_url', $account_admin ) : $pricing_admin );
        }
        // No Freemius available.
        return $fallback_url;
    }

    /**
     * Handle direct access to the sfais-upgrade admin page *before* any output.
     * This avoids "headers already sent" warnings on some environments.
     */
    public function maybe_handle_upgrade_redirect() {
        if ( !is_admin() ) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Routing parameter in wp-admin (no state change).
        $page = ( isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : '' );
        if ( $page === '' || $page !== 'sfais-upgrade' ) {
            return;
        }
        if ( !current_user_can( 'manage_options' ) ) {
            return;
        }
        $is_pro_package = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
        $target = $this->get_upgrade_menu_target_url( $is_pro_package );
        if ( !empty( $target ) ) {
            wp_safe_redirect( esc_url_raw( $target ) );
            exit;
        }
    }

    public function render_admin_page() {
        if ( !current_user_can( 'manage_options' ) ) {
            return;
        }
        // Valid tab IDs used in markup and JS
        $valid_tabs = [
            'dashboard',
            'ip-blocker',
            'patches',
            'scanner',
            'settings'
        ];
        // 1) If the request came from a form in our UI, respect the tab that was active at submit time
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.NonceVerification.Missing -- UI state only; does not change settings or data.
        $posted_tab = ( isset( $_POST['sfais_tab'] ) ? sanitize_key( (string) wp_unslash( $_POST['sfais_tab'] ) ) : '' );
        if ( $posted_tab && in_array( $posted_tab, $valid_tabs, true ) ) {
            $default_tab = $posted_tab;
        } else {
            // 2) Support deep-linking via ?tab=... (useful for submenu links and debugging).
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Routing parameter in wp-admin (no state change).
            $get_tab = ( isset( $_GET['tab'] ) ? sanitize_key( (string) wp_unslash( $_GET['tab'] ) ) : '' );
            if ( $get_tab && in_array( $get_tab, $valid_tabs, true ) ) {
                $default_tab = $get_tab;
            } else {
                // 3) Otherwise, decide from the submenu slug (?page=...)
                // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Routing parameter in wp-admin (no state change).
                $current_page = ( isset( $_GET['page'] ) ? sanitize_key( (string) wp_unslash( $_GET['page'] ) ) : 'sfais-dashboard' );
                switch ( $current_page ) {
                    case 'sfais-ip-blocker':
                        $default_tab = 'ip-blocker';
                        break;
                    case 'sfais-patches':
                        $default_tab = 'patches';
                        break;
                    case 'sfais-scanner':
                        $default_tab = 'scanner';
                        break;
                    case 'sfais-settings':
                        $default_tab = 'settings';
                        break;
                    default:
                        $default_tab = 'dashboard';
                        break;
                }
            }
        }
        // IMPORTANT:
        // Edition detection MUST NOT depend on license state. In the WP.org FREE package a license activation
        // must not flip the UI to "active".
        $is_pro_package = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
        // Determine URLs for header buttons.
        // Use Freemius internal admin pages without forcing a billing cycle.
        // Also prefer opening internal admin pages in the same tab (more reliable on some local stacks).
        $upgrade_url = $this->get_upgrade_menu_target_url( false );
        $account_url = $this->get_upgrade_menu_target_url( true );
        // Match the Settings tab (License & Account) CTA destinations.
        $sfais_pricing_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-pricing' );
        $is_internal_upgrade = strpos( (string) $upgrade_url, '/wp-admin/' ) !== false || strpos( (string) $upgrade_url, 'admin.php?page=' ) !== false;
        $is_internal_account = strpos( (string) $account_url, '/wp-admin/' ) !== false || strpos( (string) $account_url, 'admin.php?page=' ) !== false;
        $sfais_needs_licence = $is_pro_package && (bool) apply_filters( 'mhsf_ui_pro_needs_licence', false );
        // Progressive enhancement:
        // - Render the correct tab as active server-side (works even if JS/CSS fails to load).
        // - Use real admin URLs in tab links so they still work when JS is blocked.
        $tab_urls = array(
            'dashboard'  => ( function_exists( 'menu_page_url' ) ? menu_page_url( 'sfais-dashboard', false ) : admin_url( 'admin.php?page=sfais-dashboard' ) ),
            'ip-blocker' => ( function_exists( 'menu_page_url' ) ? menu_page_url( 'sfais-ip-blocker', false ) : admin_url( 'admin.php?page=sfais-ip-blocker' ) ),
            'patches'    => ( function_exists( 'menu_page_url' ) ? menu_page_url( 'sfais-patches', false ) : admin_url( 'admin.php?page=sfais-patches' ) ),
            'scanner'    => ( function_exists( 'menu_page_url' ) ? menu_page_url( 'sfais-scanner', false ) : admin_url( 'admin.php?page=sfais-scanner' ) ),
            'settings'   => ( function_exists( 'menu_page_url' ) ? menu_page_url( 'sfais-settings', false ) : admin_url( 'admin.php?page=sfais-settings' ) ),
        );
        $tab_active = function ( $id ) use($default_tab) {
            return ( $default_tab === $id ? ' active' : '' );
        };
        ?>
		<div class="sfais-wrap" data-default-tab="<?php 
        echo esc_attr( $default_tab );
        ?>">
			<div class="sfais-header" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;">

				<div class="sfais-logo-animated">
					<div class="sfais-logo-mark">
						<img src="<?php 
        echo esc_url( SFAIS_URL . 'admin/img/sfais-logo-main.png' );
        ?>"
							 alt="Maroon Horizon Smart Firewall logo">
						<span class="sfais-logo-glow" aria-hidden="true"></span>
					</div>
					<div class="mhsf-brand-text">
						<?php 
        $mhsf_rating = get_option( 'sfais_last_quick_rating' );
        $mhsf_kick = ( $is_pro_package ? ( $sfais_needs_licence ? __( 'Smart Firewall · PRO (not activated)', 'maroon-horizon-smart-firewall' ) : __( 'Smart Firewall · PRO', 'maroon-horizon-smart-firewall' ) ) : __( 'Smart Firewall · Free', 'maroon-horizon-smart-firewall' ) );
        ?>
						<span class="mhsf-kick"><?php 
        echo esc_html( $mhsf_kick );
        ?></span>
						<h1 class="sfais-logo-title">Maroon Horizon Smart Firewall</h1>
						<span class="mhsf-tagline" id="mhsf-header-score"><?php 
        if ( is_array( $mhsf_rating ) && isset( $mhsf_rating['score'] ) ) {
            /* translators: 1: score, 2: label like Fair */
            echo esc_html( sprintf( __( 'Security score %1$d/100 · %2$s', 'maroon-horizon-smart-firewall' ), (int) $mhsf_rating['score'], (string) ($mhsf_rating['label'] ?? '') ) );
        } else {
            esc_html_e( 'Harden WordPress, block bad IPs and bots, limit login attempts and scan your files for malware.', 'maroon-horizon-smart-firewall' );
        }
        ?></span>
					</div>
				</div>

				<div class="sfais-header-actions">
					<?php 
        if ( $is_pro_package ) {
            ?>
						<a href="<?php 
            echo esc_url( $account_url );
            ?>" <?php 
            if ( !$is_internal_account ) {
                ?>target="_blank" rel="noopener noreferrer"<?php 
            }
            ?>
						   class="button sfais-pro-active-btn<?php 
            echo ( $sfais_needs_licence ? ' button-primary' : '' );
            ?>">
							<span class="dashicons <?php 
            echo ( $sfais_needs_licence ? 'dashicons-admin-network' : 'dashicons-yes-alt' );
            ?>"></span>
											<?php 
            echo esc_html( apply_filters( 'mhsf_ui_pro_active_label', 'Active' ) );
            ?>
						</a>
					<?php 
        } elseif ( function_exists( 'mhsf_free_has_paid_pro' ) && mhsf_free_has_paid_pro() ) {
            ?>
						<a href="<?php 
            echo esc_url( $upgrade_url );
            ?>" class="button button-primary">
							<span class="dashicons dashicons-download" style="margin-top:4px;"></span>
							<?php 
            esc_html_e( 'Get PRO', 'maroon-horizon-smart-firewall' );
            ?>
						</a>
					<?php 
        } else {
            ?>
						<a href="<?php 
            echo esc_url( $sfais_pricing_url );
            ?>"
						   class="button button-primary">
							🚀 Upgrade to PRO
						</a><?php 
        }
        ?>
				</div>
			</div>

			<p class="subtitle">
				<?php 
        esc_html_e( 'Harden WordPress, block bad IPs and bots, limit login attempts and scan your files for malware.', 'maroon-horizon-smart-firewall' );
        ?>
			</p>

			<nav class="sfais-tabs">
				<a href="<?php 
        echo esc_url( $tab_urls['dashboard'] );
        ?>" data-tab="dashboard" class="<?php 
        echo esc_attr( trim( $tab_active( 'dashboard' ) ) );
        ?>">
					<span class="dashicons dashicons-dashboard sfais-tab-icon"></span>
					<span class="sfais-tab-label">Dashboard</span>
				</a>
				<a href="<?php 
        echo esc_url( $tab_urls['ip-blocker'] );
        ?>" data-tab="ip-blocker" class="<?php 
        echo esc_attr( trim( $tab_active( 'ip-blocker' ) ) );
        ?>">
					<span class="dashicons dashicons-shield-alt sfais-tab-icon"></span>
					<span class="sfais-tab-label">IP Blocker</span>
				</a>
				<a href="<?php 
        echo esc_url( $tab_urls['patches'] );
        ?>" data-tab="patches" class="<?php 
        echo esc_attr( trim( $tab_active( 'patches' ) ) );
        ?>">
					<span class="dashicons dashicons-admin-tools sfais-tab-icon"></span>
					<span class="sfais-tab-label">Security Patches</span>
				</a>
				<a href="<?php 
        echo esc_url( $tab_urls['scanner'] );
        ?>" data-tab="scanner" class="<?php 
        echo esc_attr( trim( $tab_active( 'scanner' ) ) );
        ?>">
					<span class="dashicons dashicons-search sfais-tab-icon"></span>
					<span class="sfais-tab-label">Malware Scanner</span>
				</a>
				<a href="<?php 
        echo esc_url( $tab_urls['settings'] );
        ?>" data-tab="settings" class="<?php 
        echo esc_attr( trim( $tab_active( 'settings' ) ) );
        ?>">
					<span class="dashicons dashicons-admin-generic sfais-tab-icon"></span>
					<span class="sfais-tab-label">Settings</span>
				</a>
			</nav>

			<div class="sfais-tab-content<?php 
        echo esc_attr( $tab_active( 'dashboard' ) );
        ?>" id="dashboard">
				<?php 
        require SFAIS_PATH . 'admin/tabs/dashboard.php';
        ?>
			</div>

			<div class="sfais-tab-content<?php 
        echo esc_attr( $tab_active( 'ip-blocker' ) );
        ?>" id="ip-blocker">
				<?php 
        require SFAIS_PATH . 'admin/tabs/ip-blocker.php';
        ?>
			</div>

			<div class="sfais-tab-content<?php 
        echo esc_attr( $tab_active( 'patches' ) );
        ?>" id="patches">
				<?php 
        require SFAIS_PATH . 'admin/tabs/patches.php';
        ?>
			</div>

			<div class="sfais-tab-content<?php 
        echo esc_attr( $tab_active( 'scanner' ) );
        ?>" id="scanner">
				<?php 
        require SFAIS_PATH . 'admin/tabs/scanner.php';
        ?>
			</div>

			<div class="sfais-tab-content<?php 
        echo esc_attr( $tab_active( 'settings' ) );
        ?>" id="settings">
				<?php 
        require SFAIS_PATH . 'admin/tabs/settings.php';
        ?>
			</div>
		</div>
		<?php 
    }

    /**
     * Submenu callback for "Upgrade to PRO" / "active".
     * Renders a safe CTA page that links to Freemius pricing/account pages.
     */
    public function upgrade_or_account_redirect() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to access this page.', 'maroon-horizon-smart-firewall' ) );
        }
        $is_pro_package = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
        $target = $this->get_upgrade_menu_target_url( $is_pro_package );
        $fallback_url = apply_filters( 'sfais_fallback_upgrade_url', 'https://mh.ie/' );
        // Render a safe CTA page instead of redirecting. Redirects can trigger
        // "Cannot modify header information" warnings on some local stacks.
        $title = ( $is_pro_package ? apply_filters( 'mhsf_upgrade_page_title_pro', esc_html__( 'Active', 'maroon-horizon-smart-firewall' ) ) : esc_html__( 'Upgrade to PRO', 'maroon-horizon-smart-firewall' ) );
        $desc = ( $is_pro_package ? apply_filters( 'mhsf_upgrade_page_desc_pro', esc_html__( 'Account is active. Use the account portal to manage billing and activations.', 'maroon-horizon-smart-firewall' ) ) : esc_html__( 'Choose a plan to unlock PRO features like threat feed, real-time malware detection, and automated protection updates.', 'maroon-horizon-smart-firewall' ) );
        $button_label = ( $is_pro_package ? esc_html__( 'Open Account Portal', 'maroon-horizon-smart-firewall' ) : esc_html__( 'Open Pricing & Plans', 'maroon-horizon-smart-firewall' ) );
        $button_url = ( !empty( $target ) ? $target : $fallback_url );
        $secondary_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-account' );
        echo '<div class="wrap">';
        echo '<h1>' . esc_html( $title ) . '</h1>';
        echo '<p style="max-width:820px;">' . esc_html( $desc ) . '</p>';
        echo '<p style="margin-top:16px;">';
        echo '  <a class="button button-primary" href="' . esc_url( $button_url ) . '">' . esc_html( $button_label ) . '</a> ';
        // Provide a secondary shortcut for users who already purchased.
        if ( !$is_pro_package ) {
            echo '  <a class="button" href="' . esc_url( $secondary_url ) . '">' . esc_html__( 'Manage Account', 'maroon-horizon-smart-firewall' ) . '</a>';
        }
        echo '</p>';
        echo '</div>';
    }

    /**
     * 1.8.13: fresh Dashboard after a change made on another tab (Security Patches, manual confirmations). All tabs live on
     * one page, so without this the score ring, header score, check rows, recommended fixes and "x of 10 patches on" stayed
     * as they were until the page was reloaded. Renders the Dashboard tab again (it runs the check itself) and returns its
     * HTML + the new rating for the AJAX answer.
     *
     * @return array{dashboard_html:string,rating:array,last_checked_text:string}
     */
    public static function dashboard_refresh_payload() {
        // The Dashboard tab also handles its old non-AJAX confirmation forms; the AJAX request already did that work.
        // phpcs:disable WordPress.Security.NonceVerification.Missing -- keys are only removed for the render and put back.
        $held = array();
        foreach ( array('sfais_backup_action', 'sfais_usersec_action') as $key ) {
            if ( isset( $_POST[$key] ) ) {
                $held[$key] = sanitize_key( wp_unslash( $_POST[$key] ) );
                // action keys like backup_found_set - no trailing phpcs note (Freemius moves it)
                unset($_POST[$key]);
            }
        }
        ob_start();
        require SFAIS_PATH . 'admin/tabs/dashboard.php';
        $html = (string) ob_get_clean();
        foreach ( $held as $key => $value ) {
            $_POST[$key] = $value;
        }
        // phpcs:enable WordPress.Security.NonceVerification.Missing
        $rating = get_option( 'sfais_last_quick_rating' );
        $rating = ( is_array( $rating ) ? $rating : array() );
        $grade = strtoupper( (string) ($rating['grade'] ?? 'N/A') );
        $ts = (int) get_option( 'sfais_last_quick_check', 0 );
        return array(
            'dashboard_html'    => $html,
            'rating'            => array(
                'grade'       => $grade,
                'grade_class' => preg_replace( '/[^a-z]/', '', strtolower( $grade ) ),
                'score'       => (int) ($rating['score'] ?? 0),
                'label'       => (string) ($rating['label'] ?? ''),
                'summary'     => (string) ($rating['summary'] ?? ''),
            ),
            'last_checked_text' => ( $ts ? wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts ) : __( 'Not run yet', 'maroon-horizon-smart-firewall' ) ),
        );
    }

}

new SFAIS_Admin_UI();