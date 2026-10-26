<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
class SFAIS_Security_Check {
    /**
     * Run all quick checks and return sections.
     * The controller (SFAIS_Functions) will compute the overall rating.
     */
    public function run_quick_check() {
        $sections = [];
        $sections['system'] = [
            'title' => 'System Environment',
            'items' => [
                $this->check_php_version(),
                $this->check_wp_version(),
                $this->check_server_type(),
                $this->check_wp_version_info_hidden()
            ],
        ];
        $sections['files'] = [
            'title' => 'File & Configuration Security',
            'items' => [
                $this->check_htaccess_writable(),
                $this->check_wp_config_writable(),
                $this->check_file_editing_disabled(),
                $this->check_directory_browsing(),
                $this->check_uploads_permissions()
            ],
        ];
        $sections['firewall'] = [
            'title' => 'Firewall & Protection',
            'items' => [
                $this->check_php_firewall_active(),
                $this->check_blocked_ip_count(),
                $this->check_limit_login_item(),
                $this->check_bot_protection_item(),
                $this->check_threat_feed_item()
            ],
        ];
        $sections['users'] = [
            'title' => 'User Security',
            'items' => [$this->check_admin_username(), $this->check_strong_passwords_item(), $this->check_2fa_item()],
        ];
        $sections['ssl'] = [
            'title' => 'Website Security & SSL',
            'items' => [$this->check_https_active(), $this->check_force_https_redirect()],
        ];
        $sections['backup'] = [
            'title' => 'Backup & Maintenance',
            'items' => [$this->check_backup_found_item(), $this->check_backup_age_item(), $this->check_unused_plugins_item()],
        ];
        return $sections;
    }

    /**
     * Compute an overall security rating from the quick check sections.
     *
     * ✅ Scoring policy (aligned with your requirements):
     * - Start from 100
     * - 🟢 OK          => 0 points deducted
     * - 🔵 INFO        => 0 points deducted (informational items must not prevent 100/100)
     * - 🟡 WARNING     => deduct 5 points each
     * - 🔴 CRITICAL    => deduct 10 points each
     *
     */
    public function compute_overall_rating( $sections ) {
        $status_counts = [
            'ok'   => 0,
            'info' => 0,
            'warn' => 0,
            'crit' => 0,
        ];
        if ( !is_array( $sections ) ) {
            return [
                'grade'   => 'N/A',
                'score'   => 0,
                'label'   => 'No data',
                'summary' => 'Not enough information to calculate a rating yet.',
            ];
        }
        $deduct = 0;
        foreach ( $sections as $section ) {
            if ( empty( $section['items'] ) || !is_array( $section['items'] ) ) {
                continue;
            }
            foreach ( $section['items'] as $item ) {
                $status = ( isset( $item['status'] ) ? $item['status'] : 'info' );
                if ( !isset( $status_counts[$status] ) ) {
                    $status = 'info';
                }
                $status_counts[$status]++;
                // Deduction rules
                switch ( $status ) {
                    case 'crit':
                        $deduct += 10;
                        break;
                    case 'warn':
                        $deduct += 5;
                        break;
                    case 'ok':
                    case 'info':
                    default:
                        // no deduction
                        break;
                }
            }
        }
        $score = 100 - (int) $deduct;
        if ( $score < 0 ) {
            $score = 0;
        }
        if ( $score > 100 ) {
            $score = 100;
        }
        // Grading buckets
        $grade = 'C';
        $label = 'Fair';
        $summary = 'Some key protections are missing. Prioritise the warnings below.';
        if ( $score >= 90 ) {
            $grade = 'A';
            $label = 'Excellent';
            $summary = 'Your security posture looks very strong. Keep everything updated and review occasionally.';
        } elseif ( $score >= 75 ) {
            $grade = 'B';
            $label = 'Good';
            $summary = 'Your site is well protected, but there are a few improvements recommended below.';
        } elseif ( $score >= 60 ) {
            $grade = 'C';
            $label = 'Fair';
            $summary = 'Some key protections are missing. Prioritise the warnings below.';
        } elseif ( $score >= 40 ) {
            $grade = 'D';
            $label = 'Weak';
            $summary = 'Your site is exposed. Fix the critical and warning items as soon as possible.';
        } else {
            $grade = 'E';
            $label = 'At Risk';
            $summary = 'Your security level is very low. Fix the critical items below first.';
        }
        return [
            'grade'   => $grade,
            'score'   => $score,
            'label'   => $label,
            'summary' => $summary,
        ];
    }

    /* -------------------------------------------------------------
     * Individual checks
     * ------------------------------------------------------------- */
    private function detect_server_type() {
        $server = ( isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '' );
        if ( strpos( $server, 'apache' ) !== false || strpos( $server, 'litespeed' ) !== false ) {
            return 'apache';
        }
        if ( strpos( $server, 'nginx' ) !== false ) {
            return 'nginx';
        }
        return 'other';
    }

    /**
     * ✅ Best-practice PHP version evaluation (aligned with Dashboard table rules).
     * Returns status: crit / warn / ok.
     */
    private function check_php_version() {
        $php_version = PHP_VERSION;
        // 1.8.13: status from the official PHP support dates compared with TODAY (php.net/supported-versions), so a branch
        // turns Warning / Critical on the day its support ends - the old fixed texts kept 8.1 at Warning after its end.
        $branches = [
            '8.1' => ['25 Nov 2021', '2023-11-25', '2025-12-31'],
            '8.2' => ['8 Dec 2022', '2024-12-31', '2026-12-31'],
            '8.3' => ['23 Nov 2023', '2025-12-31', '2027-12-31'],
            '8.4' => ['21 Nov 2024', '2026-12-31', '2028-12-31'],
            '8.5' => ['20 Nov 2025', '2027-12-31', '2029-12-31'],
        ];
        $branch = implode( '.', array_slice( explode( '.', $php_version ), 0, 2 ) );
        $today = gmdate( 'Y-m-d' );
        $fmt = static function ( $ymd ) {
            return gmdate( 'j M Y', (int) strtotime( $ymd . ' 12:00:00 UTC' ) );
        };
        if ( version_compare( $php_version, '8.1.0', '<' ) ) {
            $status = 'crit';
            $message = 'Critical. This PHP version no longer gets security fixes. Ask your host to switch to PHP 8.3 or newer as soon as possible.';
        } elseif ( isset( $branches[$branch] ) ) {
            list( $released, $active_end, $security_end ) = $branches[$branch];
            if ( $today > $security_end ) {
                $status = 'crit';
                $message = sprintf(
                    'Critical. PHP %1$s (released %2$s) stopped getting security fixes on %3$s. Ask your host to switch to PHP 8.3 or newer as soon as possible.',
                    $branch,
                    $released,
                    $fmt( $security_end )
                );
            } elseif ( $today > $active_end ) {
                $status = 'warn';
                $message = sprintf(
                    'Warning. PHP %1$s (released %2$s) now gets security fixes only, until %3$s. Plan the switch to a newer PHP version.',
                    $branch,
                    $released,
                    $fmt( $security_end )
                );
            } else {
                $status = 'ok';
                $message = sprintf(
                    'Good. PHP %1$s (released %2$s) is fully supported until %3$s and gets security fixes until %4$s.',
                    $branch,
                    $released,
                    $fmt( $active_end ),
                    $fmt( $security_end )
                );
            }
        } else {
            $status = 'ok';
            $message = sprintf( 'Good. PHP %s is newer than the versions this plugin knows - it is supported.', $branch );
        }
        return [
            'label'   => 'PHP Version',
            'value'   => $php_version,
            'status'  => $status,
            'message' => $message,
        ];
    }

    /**
     * ✅ Best-practice WordPress version evaluation (aligned with Dashboard table rules).
     * Returns status: crit / warn / ok.
     */
    private function check_wp_version() {
        $wp_version = get_bloginfo( 'version' );
        if ( preg_match( '/^(\\d+\\.\\d+)/', $wp_version, $m ) ) {
            $major = $m[1];
        } else {
            $major = $wp_version;
        }
        $status = 'crit';
        $message = 'Critical. Your WordPress version is very old and should be updated immediately to a supported 6.x release.';
        if ( version_compare( $major, '5.9', '<' ) ) {
            if ( $major === '5.8' ) {
                $status = 'crit';
                $message = 'Critical. Your WordPress version is 5.8, released 20 Jul 2021. It is several years old and far behind current WordPress security and performance improvements. You should upgrade immediately to a supported 6.x version.';
            } else {
                $status = 'crit';
                $message = 'Critical. Your WordPress version is 5.7 or older, with the 5.7 branch first released 9 Mar 2021. This core is no longer considered safe for modern sites. You should update to a supported 6.x version as soon as possible.';
            }
        } elseif ( $major === '5.9' ) {
            $status = 'warn';
            $message = 'Warning. Your WordPress version is 5.9, released 25 Jan 2022. It still receives security fixes, but it is several major releases behind the current 6.x series. Our advice is to upgrade to a recent 6.x version as soon as your theme and plugins are compatible.';
        } elseif ( $major === '6.0' ) {
            $status = 'warn';
            $message = 'Warning. Your WordPress version is 6.0, released 24 May 2022. While security updates are still backported, this branch is now old and misses many hardening and performance improvements. Plan an upgrade to a newer 6.x version as soon as possible.';
        } elseif ( $major === '6.1' ) {
            $status = 'warn';
            $message = 'Warning. Your WordPress version is 6.1, released 1 Nov 2022. It is no longer considered a modern baseline for WordPress security. You should upgrade to a recent 6.x release to benefit from newer protections and editor improvements.';
        } elseif ( $major === '6.2' ) {
            $status = 'warn';
            $message = 'Warning. Your WordPress version is 6.2, released 29 Mar 2023. It is still maintained for security, but already multiple major versions behind. Our advice is to move to at least the 6.5+ range as soon as possible.';
        } elseif ( $major === '6.3' ) {
            $status = 'ok';
            $message = 'Good. Your WordPress version is 6.3, released 8 Aug 2023. It is a relatively modern release and receives security fixes, but you are still behind newer 6.6+ features and hardening. We recommend planning an upgrade soon.';
        } elseif ( $major === '6.4' ) {
            $status = 'ok';
            $message = 'Good. Your WordPress version is 6.4, released 7 Nov 2023. This is a solid, modern baseline, but newer 6.6+ versions include additional security and performance improvements. We recommend upgrading when convenient.';
        } elseif ( $major === '6.5' ) {
            $status = 'ok';
            $message = 'Good. Your WordPress version is 6.5, released 2 Apr 2024. It is a recent and stable branch, but not the latest generation of WordPress anymore. Our advice is to keep an eye on updates and move to 6.6+ when your stack is ready.';
        } elseif ( $major === '6.6' ) {
            $status = 'ok';
            $message = 'Excellent. Your WordPress version is 6.6, released 16 Jul 2024. This is part of the current generation of WordPress and is fully up to date for most sites. Your core security posture is excellent — keep automatic updates enabled.';
        } elseif ( $major === '6.7' ) {
            $status = 'ok';
            $message = 'Excellent. Your WordPress version is 6.7, released 12 Nov 2024. It belongs to the latest WordPress series and receives the newest security and stability fixes. Your WordPress core is in excellent shape; just continue updating promptly when new releases appear.';
        } elseif ( $major === '6.8' ) {
            $status = 'ok';
            $message = 'Excellent. Your WordPress version is 6.8, released 15 Apr 2025. This is a very recent major release with active security and maintenance updates. Your WordPress installation is fully up to date — keep it that way by allowing automatic updates.';
        } elseif ( $major === '6.9' ) {
            $status = 'ok';
            $message = 'Excellent. Your WordPress version is 6.9, released 2 Dec 2025. It receives security and maintenance updates. Keep automatic updates enabled to stay fully protected.';
        } else {
            // 1.8.7: no fixed version/date for newer releases (the old text said "6.9 or newer" for 7.x too)
            $status = 'ok';
            $message = sprintf( 'Excellent. Your WordPress version is %s, a current major release with active security updates. Keep automatic updates enabled to stay fully protected.', $major );
        }
        // 1.8.13: the texts above are per branch; WordPress's own update check says whether a newer release is out.
        $newer = $this->wp_update_available( $wp_version );
        if ( $newer && 'ok' === $status ) {
            $status = 'warn';
            $message = sprintf( 'Update available. WordPress %1$s is out (this site runs %2$s). Update soon - security fixes come with new releases.', $newer, $wp_version );
        } elseif ( false === $newer && 'ok' === $status ) {
            $message = sprintf( 'Excellent. WordPress %s is the latest version. Keep automatic updates on to stay protected.', $wp_version );
        }
        return [
            'label'   => 'WordPress Version',
            'value'   => $wp_version,
            'status'  => $status,
            'message' => $message,
        ];
    }

    // ✅ Check: Hide WordPress Version Info
    private function check_wp_version_info_hidden() {
        $hidden = (bool) get_option( 'sfais_patch_versioninfo' );
        return [
            'label'   => 'Hide WordPress Version Info',
            'value'   => ( $hidden ? 'Hidden' : 'Visible' ),
            'status'  => ( $hidden ? 'ok' : 'warn' ),
            'message' => ( $hidden ? 'Your WordPress version is hidden from page source, feeds and script/style links.' : 'Your WordPress version is still visible in your site source. Activate this patch in the Security Patches tab to hide it.' ),
        ];
    }

    private function check_server_type() {
        $type = $this->detect_server_type();
        $human = ( $type === 'apache' ? 'Apache/LiteSpeed' : (( $type === 'nginx' ? 'Nginx' : 'Other' )) );
        return [
            'label'   => 'Server Type',
            'value'   => $human,
            'status'  => 'info',
            'message' => 'Detected server type determines available protections.',
        ];
    }

    private function check_htaccess_writable() {
        $server_type = $this->detect_server_type();
        $ht = ABSPATH . '.htaccess';
        $exists = file_exists( $ht );
        $perm = '----';
        if ( $exists && is_readable( $ht ) ) {
            $fp = fileperms( $ht );
            if ( $fp !== false ) {
                $perm = substr( sprintf( '%o', $fp ), -4 );
            }
        }
        $writable = $exists && SFAIS_FS::is_writable( $ht );
        $safe_mode = (bool) get_option( 'sfais_htaccess_safe', false );
        if ( $server_type !== 'apache' ) {
            if ( !$exists ) {
                return [
                    'label'   => '.htaccess Status',
                    'value'   => 'Not used on this server',
                    'status'  => 'info',
                    'message' => 'Your server (for example Nginx) does not use .htaccess. Smart Firewall will run in PHP mode; server-level rules must be added to your Nginx configuration.',
                ];
            }
            return [
                'label'   => '.htaccess Status',
                'value'   => "Present (perm {$perm})",
                'status'  => 'info',
                'message' => 'This server type ignores .htaccess (likely Nginx). Smart Firewall will run in PHP mode; any server rules must go into your Nginx configuration, not .htaccess.',
            ];
        }
        if ( !$exists ) {
            return [
                'label'   => '.htaccess Status',
                'value'   => 'Missing',
                'status'  => 'warn',
                'message' => 'No .htaccess file detected — Smart Firewall will use PHP fallback.',
            ];
        }
        if ( $safe_mode && !$writable ) {
            return [
                'label'   => '.htaccess Writable',
                'value'   => "No (perm {$perm})",
                'status'  => 'ok',
                'message' => 'File intentionally read-only for security; Smart Firewall will use PHP firewall mode as fallback. If you want to sync blocked IPs into .htaccess, temporarily unlock it, update rules, and then lock it again.',
            ];
        }
        if ( $writable ) {
            return [
                'label'   => '.htaccess Writable',
                'value'   => "Yes (perm {$perm})",
                'status'  => 'ok',
                'message' => 'Writable by plugin; Smart Firewall can auto-manage blocked IPs directly in .htaccess on this server.',
            ];
        }
        return [
            'label'   => '.htaccess Writable',
            'value'   => "No (perm {$perm})",
            'status'  => 'ok',
            'message' => 'Your .htaccess file is read-only, which is secure. Smart Firewall will use PHP firewall mode as fallback. If you want to write blocked IPs into .htaccess, you can temporarily make it writable, sync rules, and then lock it again.',
        ];
    }

    private function check_wp_config_writable() {
        $cfg = ABSPATH . 'wp-config.php';
        // 1.8.13: WordPress also loads wp-config.php from the folder above (when that folder is not another WordPress).
        if ( !file_exists( $cfg ) && file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && !file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
            $cfg = dirname( ABSPATH ) . '/wp-config.php';
        }
        $exists = file_exists( $cfg );
        $perm = '----';
        if ( $exists && is_readable( $cfg ) ) {
            $fp = fileperms( $cfg );
            if ( $fp !== false ) {
                $perm = substr( sprintf( '%o', $fp ), -4 );
            }
        }
        $writable = $exists && SFAIS_FS::is_writable( $cfg );
        if ( !$exists ) {
            return [
                'label'   => 'wp-config.php Writable',
                'value'   => 'Not found',
                'status'  => 'info',
                'message' => 'wp-config.php was not found where WordPress normally keeps it, so its permissions could not be checked.',
            ];
        }
        return [
            'label'   => 'wp-config.php Writable',
            'value'   => ( $writable ? "Yes (perm {$perm})" : "No (perm {$perm})" ),
            'status'  => ( $writable ? 'warn' : 'ok' ),
            'message' => ( $writable ? 'This file should not be writable by the web server.' : 'Good: wp-config.php is read-only for the web server.' ),
        ];
    }

    private function check_file_editing_disabled() {
        // 1.8.13: the real effect for the admin who looks at the page (constant, the PRO patch or another plugin) - the old
        // check read the PRO option only when licensed, while the patch keeps working without a licence.
        $patch_on = false;
        $disabled = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT || $patch_on || is_user_logged_in() && current_user_can( 'manage_options' ) && !current_user_can( 'edit_plugins' ) && !current_user_can( 'edit_themes' );
        return [
            'label'   => 'File Editing in Admin',
            'value'   => ( $disabled ? 'Disabled' : 'Enabled' ),
            'status'  => ( $disabled ? 'ok' : 'info' ),
            'message' => ( $disabled ? 'The theme and plugin file editors are switched off in the dashboard.' : 'The theme and plugin file editors are on. Switching them off stops code changes through a stolen admin login.' ),
        ];
    }

    /**
     * ✅ Updated: Directory Browsing check now reflects the patch behavior.
     * It verifies minimal index files in the same directories the patch manages.
     * Warn only if one or more of those directories exists and has no index.* file.
     */
    private function check_directory_browsing() {
        $label = 'Directory Browsing';
        // Directories managed by the "Prevent Directory Browsing" patch (minimal index files).
        $dirs = [];
        $content_dir = '';
        if ( defined( 'WP_PLUGIN_DIR' ) ) {
            $content_dir = dirname( WP_PLUGIN_DIR );
        }
        $uploads_basedir = ( function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '' );
        if ( is_wp_error( $uploads_basedir ) ) {
            $uploads_basedir = '';
        }
        $theme_root = ( function_exists( 'get_theme_root' ) ? (string) get_theme_root() : '' );
        if ( '' !== $content_dir ) {
            $dirs[] = $content_dir;
        }
        if ( '' !== $uploads_basedir ) {
            $dirs[] = $uploads_basedir;
        }
        if ( '' !== $theme_root ) {
            $dirs[] = $theme_root;
        }
        if ( defined( 'WP_PLUGIN_DIR' ) ) {
            $dirs[] = WP_PLUGIN_DIR;
        }
        $dirs = array_values( array_unique( array_filter( $dirs ) ) );
        $existing = 0;
        $unprotected = 0;
        foreach ( $dirs as $dir ) {
            if ( !is_dir( $dir ) ) {
                continue;
            }
            $existing++;
            $base = rtrim( $dir, '/\\' );
            $has_index = file_exists( $base . '/index.php' ) || file_exists( $base . '/index.htm' ) || file_exists( $base . '/index.html' );
            if ( !$has_index ) {
                $unprotected++;
            }
        }
        // If none of the directories exist, we cannot assert status confidently.
        if ( $existing === 0 ) {
            return [
                'label'   => $label,
                'value'   => 'Unknown',
                'status'  => 'info',
                'message' => 'Ensure directory listing is disabled in your server config.',
            ];
        }
        if ( $unprotected === 0 ) {
            return [
                'label'   => $label,
                'value'   => 'Protected',
                'status'  => 'ok',
                'message' => 'The main folders (wp-content, uploads, themes, plugins) have an index file, so they can\'t be listed.',
            ];
        }
        return [
            'label'   => $label,
            'value'   => 'Possibly Enabled',
            'status'  => 'warn',
            'message' => 'One or more key content directories are missing an index file. Activate the patch to add minimal index files and prevent directory browsing.',
        ];
    }

    private function check_uploads_permissions() {
        $dir = ( function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '' );
        if ( is_wp_error( $dir ) ) {
            $dir = '';
        }
        $ok = is_dir( $dir ) && is_readable( $dir ) && SFAIS_FS::is_writable( $dir );
        $perm = '---';
        if ( $ok && is_readable( $dir ) ) {
            $fp = fileperms( $dir );
            if ( $fp !== false ) {
                $perm = substr( sprintf( '%o', $fp ), -3 );
            }
        }
        $good = in_array( $perm, ['755', '750'], true );
        return [
            'label'   => 'File Permissions (uploads)',
            'value'   => $perm,
            'status'  => ( $ok && $good ? 'ok' : 'warn' ),
            'message' => ( $ok ? ( $good ? 'Permissions secure.' : 'Check permissions (755 recommended).' ) : 'Uploads not accessible.' ),
        ];
    }

    private function check_php_firewall_active() {
        return [
            'label'   => 'PHP Firewall Active',
            'value'   => 'Yes',
            'status'  => 'ok',
            'message' => 'PHP-level firewall is running and filtering requests.',
        ];
    }

    private function check_blocked_ip_count() {
        $count = count( get_option( 'sfais_blocked_ips', [] ) );
        return [
            'label'   => 'Manually Blocked IPs',
            'value'   => $count,
            'status'  => 'info',
            'message' => 'Manually blocked IP addresses only. Subnet blocks from the Threat Feed are handled separately.',
        ];
    }

    private function check_limit_login_item() {
        $active = class_exists( 'SFAIS_Login_Guard' ) || class_exists( 'SFAIS_Pro_Login_Guard' );
        if ( defined( 'MHSF_LOGIN_GUARD_OFF' ) && MHSF_LOGIN_GUARD_OFF ) {
            // 1.8.13: the emergency switch really turns it off
            return [
                'label'   => 'Limit Login Attempts',
                'value'   => 'Off (wp-config.php)',
                'status'  => 'warn',
                'message' => 'Login Guard is switched off by MHSF_LOGIN_GUARD_OFF in wp-config.php. Remove that line to protect the login again.',
            ];
        }
        return [
            'label'   => 'Limit Login Attempts',
            'value'   => ( $active ? 'Enabled' : 'Inactive' ),
            'status'  => ( $active ? 'ok' : 'warn' ),
            'message' => ( $active ? 'This site allows up to 5 failed login attempts per IP address. After 5 failures, that IP is locked for 30 minutes. Counters reset automatically on successful login.' : apply_filters( 'mhsf_security_check_login_guard_missing_message', 'Module is not loaded. Please check your installation or contact support.' ) ),
        ];
    }

    private function check_bot_protection_item() {
        $active = class_exists( 'SFAIS_Bot_Protection' ) || class_exists( 'SFAIS_Pro_Bot_Protection' );
        return [
            'label'   => 'Bot Protection',
            'value'   => ( $active ? 'Enabled' : 'Inactive' ),
            'status'  => ( $active ? 'ok' : 'warn' ),
            'message' => ( $active ? apply_filters( 'mhsf_security_check_bot_protection_active_message', 'Requests from known attack and scanning tools (recognised by their User-Agent, e.g. sqlmap, WPScan, Nikto) are refused.' ) : apply_filters( 'mhsf_security_check_bot_protection_missing_message', 'Module is not loaded. Please check your installation or contact support.' ) ),
        ];
    }

    private function check_threat_feed_item() {
        $pro_file = '';
        return [
            'label'   => 'Threat Feed',
            'value'   => 'PRO feature',
            'status'  => 'info',
            'message' => 'The Threat Feed (90,000+ high-risk networks, updated daily) is part of PRO. Manual IP blocks and the firewall stay active in the free version.',
        ];
    }

    private function check_strong_passwords_item() {
        $manual = (bool) get_option( 'sfais_manual_strong_passwords', false );
        if ( $manual ) {
            return [
                'label'   => 'Strong Password Policy',
                'value'   => 'Manually confirmed',
                'status'  => 'ok',
                'message' => 'Strong password enforcement has been manually confirmed by the site owner.',
            ];
        }
        $enforced = $this->is_strong_passwords_enforced();
        return [
            'label'   => 'Strong Password Policy',
            'value'   => ( $enforced ? ( is_string( $enforced ) ? 'Plugin active: ' . $enforced : 'Enforced' ) : 'Not enforced' ),
            'status'  => ( $enforced ? 'ok' : 'warn' ),
            'message' => ( $enforced ? ( is_string( $enforced ) ? sprintf( '%s is active. Make sure its strong-password option is on for administrators.', $enforced ) : 'Strong passwords are enforced (SFAIS_STRONG_PASSWORDS_ENFORCED in wp-config.php).' ) : 'Weak passwords are still allowed. Enable a strong-password policy using a dedicated security plugin or through your hosting/security setup.' ),
        ];
    }

    private function check_2fa_item() {
        $manual = (bool) get_option( 'sfais_manual_2fa_enabled', false );
        if ( $manual ) {
            return [
                'label'   => 'Two-Factor Authentication (2FA)',
                'value'   => 'Manually confirmed',
                'status'  => 'ok',
                'message' => '2FA usage has been manually confirmed by the site owner.',
            ];
        }
        $enabled = $this->is_two_factor_enabled();
        return [
            'label'   => 'Two-Factor Authentication (2FA)',
            'value'   => ( $enabled ? ( is_string( $enabled ) ? 'Plugin active: ' . $enabled : 'Enabled' ) : 'Not enabled' ),
            'status'  => ( $enabled ? 'ok' : 'warn' ),
            'message' => ( $enabled ? ( is_string( $enabled ) ? sprintf( '%s is active. Make sure 2FA is switched on for every administrator.', $enabled ) : 'Two-factor login is confirmed (SFAIS_2FA_ENFORCED in wp-config.php).' ) : '2FA is not currently enabled. We strongly recommend enabling 2FA for administrator accounts using a dedicated plugin.' ),
        ];
    }

    private function check_backup_found_item() {
        $manual = (bool) get_option( 'sfais_backup_manual_found', false );
        if ( $manual ) {
            return [
                'label'   => 'Backup Found',
                'value'   => 'Manually confirmed',
                'status'  => 'ok',
                'message' => 'Backups are manually confirmed as configured by the site owner.',
            ];
        }
        if ( !function_exists( 'is_plugin_active' ) ) {
            if ( file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
        }
        if ( function_exists( 'is_plugin_active' ) ) {
            $backup_plugins = [
                'updraftplus/updraftplus.php',
                'backwpup/backwpup.php',
                'duplicator/duplicator.php',
                'vaultpress/vaultpress.php',
                'jetpack-backup/jetpack-backup.php',
                // 1.8.13: was jetpack/jetpack.php - Jetpack alone makes no backups
                'all-in-one-wp-migration/all-in-one-wp-migration.php',
                'wpvivid-backuprestore/wpvivid-backuprestore.php',
                'blogvault-real-time-backup/blogvault.php',
                'backuply/backuply.php',
            ];
            foreach ( $backup_plugins as $plugin ) {
                if ( is_plugin_active( $plugin ) ) {
                    return [
                        'label'   => 'Backup Found',
                        'value'   => 'Backup plugin detected',
                        'status'  => 'info',
                        'message' => 'At least one backup plugin is active on this site. Review its settings to ensure backups run regularly and are stored off-site.',
                    ];
                }
            }
        }
        return [
            'label'   => 'Backup Found',
            'value'   => 'Not detected',
            'status'  => 'warn',
            'message' => 'Maroon Horizon Smart Firewall cannot detect any backup solution on this site. Set up regular backups with your host or a backup plugin, then confirm it in the dashboard.',
        ];
    }

    private function check_backup_age_item() {
        $manual = (bool) get_option( 'sfais_backup_manual_age_ok', false );
        if ( $manual ) {
            return [
                'label'   => 'Backup Age',
                'value'   => 'Manually confirmed',
                'status'  => 'ok',
                'message' => 'Backup recency has been manually confirmed by the site owner.',
            ];
        }
        if ( defined( 'SFAIS_BACKUP_AGE_DAYS' ) && is_numeric( SFAIS_BACKUP_AGE_DAYS ) ) {
            $days = (int) SFAIS_BACKUP_AGE_DAYS;
            if ( $days <= 2 ) {
                $status = 'ok';
                $message = 'Last backup appears very recent (within 2 days).';
            } elseif ( $days <= 7 ) {
                $status = 'info';
                $message = 'Last backup appears recent (within 7 days).';
            } elseif ( $days <= 30 ) {
                $status = 'warn';
                $message = 'Backups are older than 7 days. Consider increasing frequency, especially for active sites.';
            } else {
                $status = 'crit';
                $message = 'Backups are older than 30 days. This is risky — configure more frequent backups and confirm once you see recent restore points.';
            }
            return [
                'label'   => 'Backup Age',
                'value'   => $days . ' days',
                'status'  => $status,
                'message' => $message,
            ];
        }
        // ✅ Unknown must be Warning (not Info).
        return [
            'label'   => 'Backup Age',
            'value'   => 'Unknown',
            'status'  => 'warn',
            'message' => 'Backup age could not be verified. Confirm that your backups are recent (for example within 7 days) and then mark this as confirmed in the dashboard.',
        ];
    }

    private function check_unused_plugins_item() {
        if ( !function_exists( 'get_plugins' ) ) {
            if ( file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
        }
        $inactive_plugins = 0;
        if ( function_exists( 'get_plugins' ) ) {
            $plugins = get_plugins();
            $active_plugins = (array) get_option( 'active_plugins', [] );
            $all_plugin_keys = array_keys( $plugins );
            $inactive_plugins = count( array_diff( $all_plugin_keys, $active_plugins ) );
        }
        $extra_themes = 0;
        if ( function_exists( 'wp_get_themes' ) && function_exists( 'wp_get_theme' ) ) {
            $themes = wp_get_themes();
            $current_theme = wp_get_theme();
            foreach ( $themes as $stylesheet => $theme ) {
                if ( $theme->get_stylesheet() !== $current_theme->get_stylesheet() && $theme->get_stylesheet() !== $current_theme->get_template() ) {
                    $extra_themes++;
                }
            }
        }
        $value = sprintf( '%d inactive plugins, %d extra themes', (int) $inactive_plugins, (int) $extra_themes );
        if ( $inactive_plugins === 0 && $extra_themes <= 1 ) {
            $status = 'ok';
            $message = 'You keep plugins and themes lean — there are almost no unused components installed.';
        } elseif ( $inactive_plugins <= 3 && $extra_themes <= 3 ) {
            $status = 'info';
            $message = 'A few unused plugins/themes are installed. Review them occasionally and remove the ones you no longer need.';
        } else {
            $status = 'warn';
            $message = 'Many unused plugins and/or themes are installed. Removing those you no longer need reduces your attack surface and simplifies updates.';
        }
        return [
            'label'   => 'Unused Plugins/Themes',
            'value'   => $value,
            'status'  => $status,
            'message' => $message,
        ];
    }

    private function check_admin_username() {
        $user = get_user_by( 'login', 'admin' );
        $exists = $user instanceof WP_User;
        return [
            'label'   => 'Admin Username Secure',
            'value'   => ( $exists ? 'Default "admin" found' : 'OK' ),
            'status'  => ( $exists ? 'warn' : 'ok' ),
            'message' => ( $exists ? 'Avoid using default "admin".' : 'Good: custom admin name used.' ),
        ];
    }

    private function check_https_active() {
        $active = is_ssl();
        // 1.8.13: behind Cloudflare or a proxy PHP sees http; the proxy reports the visitor's https in X-Forwarded-Proto.
        if ( !$active && isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) && 0 === stripos( (string) get_option( 'home' ), 'https://' ) ) {
            $active = 'https' === strtolower( sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_PROTO'] ) ) );
        }
        return [
            'label'   => 'HTTPS Active',
            'value'   => ( $active ? 'Yes' : 'No' ),
            'status'  => ( $active ? 'ok' : 'crit' ),
            'message' => ( $active ? 'SSL is active.' : 'Enable SSL to protect data.' ),
        ];
    }

    private function check_force_https_redirect() {
        $home = get_option( 'home' );
        $site = get_option( 'siteurl' );
        $forced = stripos( $home, 'https://' ) === 0 && stripos( $site, 'https://' ) === 0;
        return [
            'label'   => 'HTTPS URLs Configured',
            'value'   => ( $forced ? 'Yes' : 'No' ),
            'status'  => ( $forced ? 'ok' : 'warn' ),
            'message' => ( $forced ? ( get_option( 'sfais_patch_force_ssl' ) ? 'WordPress site URLs use HTTPS and the Force HTTPS patch sends HTTP visitors to HTTPS.' : 'WordPress site URLs use HTTPS. Make sure HTTP visitors are sent to HTTPS (by your host or the Force HTTPS patch in PRO).' ) : 'WordPress site URLs are not set to HTTPS. Configure HTTPS in WordPress and ensure your server redirects HTTP→HTTPS.' ),
        ];
    }

    /* -------------------------------------------------------------
     * Helper detection methods for policy checks
     * ------------------------------------------------------------- */
    /**
     * 1.8.13: newer WordPress version offered by WordPress's own update check (update_core transient, nothing downloaded here).
     *
     * @return string|false|null newer version, false = this is the latest, null = WordPress has not checked yet.
     */
    private function wp_update_available( $wp_version ) {
        $core = get_site_transient( 'update_core' );
        if ( !is_object( $core ) || empty( $core->updates ) || !is_array( $core->updates ) ) {
            return null;
        }
        $newest = '';
        foreach ( $core->updates as $offer ) {
            if ( is_object( $offer ) && isset( $offer->response, $offer->current ) && 'upgrade' === $offer->response && version_compare( (string) $offer->current, (string) $wp_version, '>' ) && ('' === $newest || version_compare( (string) $offer->current, $newest, '>' )) ) {
                $newest = (string) $offer->current;
            }
        }
        return ( '' !== $newest ? $newest : false );
    }

    private function is_strong_passwords_enforced() {
        if ( defined( 'SFAIS_STRONG_PASSWORDS_ENFORCED' ) && SFAIS_STRONG_PASSWORDS_ENFORCED ) {
            return true;
        }
        if ( !function_exists( 'is_plugin_active' ) ) {
            if ( file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
        }
        if ( function_exists( 'is_plugin_active' ) ) {
            // 1.8.13: real plugin files (Solid Security = better-wp-security) and the NAME of the active one for the row
            $candidates = [
                'force-strong-passwords/force-strong-passwords.php'   => 'Force Strong Passwords',
                'ithemes-security-pro/ithemes-security-pro.php'       => 'Solid Security Pro',
                'better-wp-security/better-wp-security.php'           => 'Solid Security',
                'wordfence/wordfence.php'                             => 'Wordfence',
                'all-in-one-wp-security-and-firewall/wp-security.php' => 'All-In-One Security',
            ];
            foreach ( $candidates as $plugin => $name ) {
                if ( is_plugin_active( $plugin ) ) {
                    return $name;
                }
            }
        }
        return false;
    }

    private function is_two_factor_enabled() {
        if ( defined( 'SFAIS_2FA_ENFORCED' ) && SFAIS_2FA_ENFORCED ) {
            return true;
        }
        if ( !function_exists( 'is_plugin_active' ) ) {
            if ( file_exists( ABSPATH . 'wp-admin/includes/plugin.php' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
        }
        if ( function_exists( 'is_plugin_active' ) ) {
            $candidates = [
                'two-factor/two-factor.php'                                           => 'Two Factor',
                'google-authenticator/google-authenticator.php'                       => 'Google Authenticator',
                'wp-2fa/wp-2fa.php'                                                   => 'WP 2FA',
                'wordfence-login-security/wordfence-login-security.php'               => 'Wordfence Login Security',
                'wordfence/wordfence.php'                                             => 'Wordfence',
                'miniorange-2-factor-authentication/miniorange-2-factor-settings.php' => 'miniOrange 2FA',
                'better-wp-security/better-wp-security.php'                           => 'Solid Security',
                'ithemes-security-pro/ithemes-security-pro.php'                       => 'Solid Security Pro',
            ];
            foreach ( $candidates as $plugin => $name ) {
                if ( is_plugin_active( $plugin ) ) {
                    return $name;
                }
            }
        }
        return false;
    }

}
