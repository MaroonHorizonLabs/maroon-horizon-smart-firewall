<?php

/**
 * Housekeeping (1.8.15, FREE + PRO): the plugin never fills the hosting with its own files or database rows.
 *
 * - Daily clean-up (WP-cron 'mhsf_daily_housekeeping', also Settings > Storage & clean-up > Run clean-up now):
 *   quarantine (30 days, max 50 MB), scan reports (30 days, newest 5 per type), scan jobs (24 hours), leftover PRO download
 *   files (1 hour), ignore-list entries of deleted files, old log files (90 days), expired login transients, two options
 *   left over from 1.8.2 (once).
 * - Hourly clean-up ('mhsf_hourly_housekeeping'): only the expired login transients, so a botnet cannot pile up rows for a day
 *   (WordPress's own expired-transient clean-up often does not run on shared hosting without a real cron).
 * - Uninstall (last edition removed): every .htaccess block and marked file the plugin wrote, the saved file permissions, the
 *   whole data folder uploads/maroon-horizon-smart-firewall/, the remaining options, transients, user meta and cron events.
 *
 * Only the plugin's own data folder, its own marked .htaccess blocks and its own marked files are ever touched.
 *
 * @package MaroonHorizonSmartFirewall
 */
if ( !defined( 'ABSPATH' ) ) {
    exit;
}
final class MHSF_Housekeeping {
    const DAILY_HOOK = 'mhsf_daily_housekeeping';

    const HOURLY_HOOK = 'mhsf_hourly_housekeeping';

    const OPT_LAST = 'mhsf_housekeeping_last';

    // last daily run: time, counts (not autoloaded)
    const OPT_LEGACY = 'mhsf_housekeeping_legacy_done';

    // the 1.8.2 options were removed once
    const DATA_SLUG = 'maroon-horizon-smart-firewall';

    const QUAR_LOG = 'sfais-quarantine-log.json';

    // same name as SFAIS_Scanner::QUAR_LOG
    const PERM_LOG = 'sfais-permissions-log.json';

    const QUAR_MAX_AGE = 2592000;

    // 30 days
    const QUAR_MAX_BYTES = 52428800;

    // 50 MB
    const REPORT_MAX_AGE = 2592000;

    // 30 days
    const REPORT_KEEP = 5;

    // per report type
    const JOB_MAX_AGE = 86400;

    // 24 hours
    const TEMP_MAX_AGE = 3600;

    // 1 hour
    const LOG_MAX_AGE = 7776000;

    // 90 days
    const IGNORES_MAX = 5000;

    // same cap as SFAIS_Scanner::IGNORES_MAX
    const TRANSIENT_ROWS = 5000;

    // max wp_options rows removed per run
    /** Order of the counts (and of the parts of the result sentence). */
    const COUNT_KEYS = array(
        'quarantine',
        'reports',
        'jobs',
        'temp',
        'ignored',
        'logs',
        'transients',
        'legacy'
    );

    /**
     * Hooks (loaded at plugin load in both editions).
     */
    public static function init() {
        add_action( self::DAILY_HOOK, array(__CLASS__, 'cron_daily') );
        add_action( self::HOURLY_HOOK, array(__CLASS__, 'cron_hourly') );
        add_action( 'admin_init', array(__CLASS__, 'schedule') );
        add_action( 'mhsf_deactivate_cleanup', array(__CLASS__, 'unschedule') );
        // deactivation keeps all data, only the events go
        add_action( 'admin_post_mhsf_housekeeping_run', array(__CLASS__, 'handle_run_now') );
    }

    /**
     * Schedule both events when missing. The first daily run is spread over the next 6 hours (not all sites at once).
     */
    public static function schedule() {
        if ( !function_exists( 'wp_next_scheduled' ) ) {
            return;
        }
        if ( !wp_next_scheduled( self::DAILY_HOOK ) ) {
            wp_schedule_event( time() + wp_rand( 0, 6 * HOUR_IN_SECONDS ), 'daily', self::DAILY_HOOK );
        }
        if ( !wp_next_scheduled( self::HOURLY_HOOK ) ) {
            wp_schedule_event( time() + wp_rand( 60, HOUR_IN_SECONDS ), 'hourly', self::HOURLY_HOOK );
        }
    }

    public static function unschedule() {
        wp_clear_scheduled_hook( self::DAILY_HOOK );
        wp_clear_scheduled_hook( self::HOURLY_HOOK );
    }

    public static function cron_daily() {
        self::run_daily( 'cron' );
    }

    public static function cron_hourly() {
        self::purge_expired_login_transients( self::TRANSIENT_ROWS );
    }

    /* ----------------------------------------------------------------
     * DAILY CLEAN-UP
     * ---------------------------------------------------------------- */
    /**
     * Run every clean-up step (oldest first) and store the result.
     *
     * @param string $source 'cron' or 'manual' (Run clean-up now).
     * @return array{time:int,source:string,counts:array<string,int>}
     */
    public static function run_daily( $source = 'cron' ) {
        $now = time();
        $counts = array_fill_keys( self::COUNT_KEYS, 0 );
        $dir = self::data_dir();
        $steps = array(
            'quarantine' => static function () use($dir, $now) {
                return ( '' === $dir ? 0 : self::clean_quarantine( $dir, $now ) );
            },
            'reports'    => static function () use($dir, $now) {
                return ( '' === $dir ? 0 : self::clean_reports( $dir . '/reports', $now ) );
            },
            'jobs'       => static function () use($dir, $now) {
                return ( '' === $dir ? 0 : self::clean_scan_jobs( $dir . '/reports/scan-jobs', $now ) );
            },
            'temp'       => static function () use($dir, $now) {
                return ( '' === $dir ? 0 : self::clean_temp_files( $dir . '/cloud', $now ) );
            },
            'ignored'    => static function () {
                return self::clean_ignore_list();
            },
            'logs'       => static function () use($dir, $now) {
                return ( '' === $dir ? 0 : self::clean_logs( $dir . '/logs', $now ) );
            },
            'transients' => static function () {
                return self::purge_expired_login_transients( self::TRANSIENT_ROWS );
            },
            'legacy'     => static function () {
                return self::remove_legacy_options();
            },
        );
        foreach ( $steps as $key => $step ) {
            try {
                $counts[$key] = (int) $step();
            } catch ( \Throwable $e ) {
                $counts[$key] = 0;
                // one failing step never stops the others
            }
        }
        $result = array(
            'time'   => $now,
            'source' => ( 'manual' === $source ? 'manual' : 'cron' ),
            'counts' => $counts,
        );
        update_option( self::OPT_LAST, $result, false );
        if ( array_sum( $counts ) > 0 ) {
            // 1.8.16: one statement per translatable text - Freemius joins a multi-line ternary and drops the comments inside it
            if ( 'manual' === $result['source'] ) {
                /* translators: %s: what was removed, e.g. "3 old quarantine files, 2 old reports removed" */
                $sentence = sprintf( __( 'Manual clean-up: %s', 'maroon-horizon-smart-firewall' ), self::counts_text( $counts ) );
            } else {
                /* translators: %s: what was removed, e.g. "3 old quarantine files, 2 old reports removed" */
                $sentence = sprintf( __( 'Daily clean-up: %s', 'maroon-horizon-smart-firewall' ), self::counts_text( $counts ) );
            }
            do_action( 'mhsf_activity', 'housekeeping', $sentence );
        }
        return $result;
    }

    /**
     * Plain text of a counts array: "3 old quarantine files, 2 old reports removed" or "nothing to remove".
     *
     * @param array $counts Counts as stored by run_daily().
     * @return string
     */
    public static function counts_text( $counts ) {
        $counts = ( is_array( $counts ) ? $counts : array() );
        $parts = array();
        foreach ( self::COUNT_KEYS as $key ) {
            $n = ( isset( $counts[$key] ) ? (int) $counts[$key] : 0 );
            if ( $n <= 0 ) {
                continue;
            }
            $num = number_format_i18n( $n );
            switch ( $key ) {
                case 'quarantine':
                    /* translators: %s: number of files */
                    $parts[] = sprintf( _n(
                        '%s old quarantine file',
                        '%s old quarantine files',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'reports':
                    /* translators: %s: number of reports */
                    $parts[] = sprintf( _n(
                        '%s old report',
                        '%s old reports',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'jobs':
                    /* translators: %s: number of files */
                    $parts[] = sprintf( _n(
                        '%s old scan job file',
                        '%s old scan job files',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'temp':
                    /* translators: %s: number of files */
                    $parts[] = sprintf( _n(
                        '%s leftover temporary file',
                        '%s leftover temporary files',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'ignored':
                    /* translators: %s: number of entries */
                    $parts[] = sprintf( _n(
                        '%s outdated ignore-list entry',
                        '%s outdated ignore-list entries',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'logs':
                    /* translators: %s: number of files */
                    $parts[] = sprintf( _n(
                        '%s old log file',
                        '%s old log files',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'transients':
                    /* translators: %s: number of database rows */
                    $parts[] = sprintf( _n(
                        '%s expired login record',
                        '%s expired login records',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
                case 'legacy':
                    /* translators: %s: number of settings */
                    $parts[] = sprintf( _n(
                        '%s outdated setting',
                        '%s outdated settings',
                        $n,
                        'maroon-horizon-smart-firewall'
                    ), $num );
                    break;
            }
        }
        if ( empty( $parts ) ) {
            return __( 'nothing to remove', 'maroon-horizon-smart-firewall' );
        }
        /* translators: %s: comma-separated list, e.g. "3 old quarantine files, 2 old reports" */
        return sprintf( __( '%s removed', 'maroon-horizon-smart-firewall' ), implode( ', ', $parts ) );
    }

    /**
     * Settings > Storage & clean-up > Run clean-up now (admin-post, nonce + capability checked).
     */
    public static function handle_run_now() {
        if ( !current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'Sorry, you are not allowed to do that.', 'maroon-horizon-smart-firewall' ) );
        }
        check_admin_referer( 'mhsf_housekeeping_run' );
        self::run_daily( 'manual' );
        wp_safe_redirect( add_query_arg( 'mhsf_cleanup', '1', admin_url( 'admin.php?page=sfais-settings' ) ) . '#mhsf-storage' );
        exit;
    }

    /* ----------------------------------------------------------------
     * a. QUARANTINE: 30 days, then max 50 MB (oldest first)
     * ---------------------------------------------------------------- */
    /**
     * @param string $data_dir Data folder (exists).
     * @param int    $now      Unix time.
     * @return int Quarantined files deleted.
     */
    private static function clean_quarantine( $data_dir, $now ) {
        $qdir = $data_dir . '/quarantine';
        if ( !is_dir( $qdir ) || is_link( $qdir ) ) {
            return 0;
        }
        $log_file = $qdir . '/' . self::QUAR_LOG;
        $log = self::read_json_array( $log_file );
        $uploads = dirname( $data_dir );
        // Quarantine time by the log (the move keeps the file's own mtime, which can be years old).
        $logged = array();
        if ( is_array( $log ) ) {
            foreach ( $log as $e ) {
                if ( !is_array( $e ) || empty( $e['quarantine'] ) || empty( $e['date'] ) ) {
                    continue;
                }
                $ts = self::site_time_to_ts( (string) $e['date'] );
                if ( $ts > 0 ) {
                    $logged[self::quarantine_abs( $uploads, (string) $e['quarantine'] )] = $ts;
                }
            }
        }
        $files = array();
        $dirs = array();
        self::scan_tree( $qdir, $files, $dirs );
        $system = array(
            strtolower( self::QUAR_LOG ),
            '.htaccess',
            'index.php',
            'index.html'
        );
        $items = array();
        $total = 0;
        foreach ( $files as $abs ) {
            if ( dirname( $abs ) === $qdir && in_array( strtolower( basename( $abs ) ), $system, true ) ) {
                continue;
                // the log and the folder's protection files stay
            }
            if ( isset( $logged[$abs] ) ) {
                $ts = $logged[$abs];
            } else {
                // No log entry: the newest of mtime / ctime (ctime changes when the file is moved into the quarantine).
                $ts = max( (int) filemtime( $abs ), (int) filectime( $abs ) );
            }
            if ( $ts <= 0 ) {
                $ts = $now;
                // unknown age: never treated as old
            }
            $size = (int) filesize( $abs );
            $items[] = array(
                'path' => $abs,
                'time' => $ts,
                'size' => $size,
            );
            $total += $size;
        }
        usort( $items, static function ( $a, $b ) {
            return (int) $a['time'] <=> (int) $b['time'];
        } );
        $removed = array();
        $left = array();
        foreach ( $items as $it ) {
            if ( $it['time'] < $now - self::QUAR_MAX_AGE && self::delete_file( $it['path'] ) ) {
                $removed[$it['path']] = true;
                $total -= $it['size'];
                continue;
            }
            $left[] = $it;
        }
        foreach ( $left as $it ) {
            if ( $total <= self::QUAR_MAX_BYTES ) {
                break;
            }
            if ( self::delete_file( $it['path'] ) ) {
                $removed[$it['path']] = true;
                $total -= $it['size'];
            }
        }
        // Log: entries of deleted files (and of files that are gone anyway) are removed.
        if ( is_array( $log ) ) {
            $keep = array();
            foreach ( $log as $e ) {
                if ( !is_array( $e ) || empty( $e['quarantine'] ) ) {
                    continue;
                }
                $abs = self::quarantine_abs( $uploads, (string) $e['quarantine'] );
                if ( isset( $removed[$abs] ) || !file_exists( $abs ) ) {
                    continue;
                }
                $keep[] = $e;
            }
            if ( count( $keep ) !== count( $log ) ) {
                SFAIS_FS::write( $log_file, (string) wp_json_encode( $keep, JSON_PRETTY_PRINT ) );
            }
        }
        // Empty sub-folders (deepest first) - never the quarantine folder itself.
        usort( $dirs, static function ( $a, $b ) {
            return strlen( $b ) <=> strlen( $a );
        } );
        foreach ( $dirs as $d ) {
            if ( $d !== $qdir && self::dir_is_empty( $d ) ) {
                SFAIS_FS::delete( $d );
            }
        }
        return count( $removed );
    }

    /** Absolute path of a quarantine log entry ('maroon-horizon-smart-firewall/quarantine/...', relative to uploads). */
    private static function quarantine_abs( $uploads, $rel ) {
        return wp_normalize_path( rtrim( $uploads, '/' ) . '/' . ltrim( str_replace( '\\', '/', $rel ), '/' ) );
    }

    /** Site-time "Y-m-d H:i:s" (current_time('mysql')) to a Unix time, 0 when not parseable. */
    private static function site_time_to_ts( $value ) {
        $dt = date_create_immutable_from_format( 'Y-m-d H:i:s', (string) $value, wp_timezone() );
        return ( $dt ? (int) $dt->getTimestamp() : 0 );
    }

    /* ----------------------------------------------------------------
     * b. SCAN REPORTS: newest 5 per type, none older than 30 days
     * ---------------------------------------------------------------- */
    private static function clean_reports( $dir, $now ) {
        if ( !is_dir( $dir ) || is_link( $dir ) ) {
            return 0;
        }
        $by_type = array();
        foreach ( self::list_files( $dir ) as $abs ) {
            // scan-core-20261026-101500.json, scan-content-..., scan-ai_deep-... (also .zip, as in enforce_report_retention)
            if ( !preg_match( '/^scan-([a-z0-9_]+)-\\d{8}-\\d{6}\\.(?:json|zip)$/i', basename( $abs ), $m ) ) {
                continue;
            }
            $by_type[strtolower( $m[1] )][] = array(
                'path'  => $abs,
                'mtime' => (int) filemtime( $abs ),
            );
        }
        $removed = 0;
        foreach ( $by_type as $rows ) {
            usort( $rows, static function ( $a, $b ) {
                return (int) $b['mtime'] <=> (int) $a['mtime'];
            } );
            foreach ( $rows as $i => $row ) {
                if ( ($i >= self::REPORT_KEEP || $row['mtime'] < $now - self::REPORT_MAX_AGE) && self::delete_file( $row['path'] ) ) {
                    $removed++;
                }
            }
        }
        return $removed;
    }

    /* ----------------------------------------------------------------
     * c. SCAN JOBS: older than 24 hours (by the newest file of the job)
     * ---------------------------------------------------------------- */
    private static function clean_scan_jobs( $dir, $now ) {
        if ( !is_dir( $dir ) || is_link( $dir ) ) {
            return 0;
        }
        $jobs = array();
        foreach ( self::list_files( $dir ) as $abs ) {
            if ( !preg_match( '/^(sfais_(?:core|ai)_[a-z0-9\\-]+)\\.(?:json|list|json\\.tmp|tmp)$/i', basename( $abs ), $m ) ) {
                continue;
            }
            $id = $m[1];
            if ( !isset( $jobs[$id] ) ) {
                $jobs[$id] = array(
                    'mtime' => 0,
                    'paths' => array(),
                );
            }
            $jobs[$id]['paths'][] = $abs;
            $jobs[$id]['mtime'] = max( $jobs[$id]['mtime'], (int) filemtime( $abs ) );
        }
        $removed = 0;
        foreach ( $jobs as $job ) {
            if ( $job['mtime'] >= $now - self::JOB_MAX_AGE ) {
                continue;
                // a running job touches its files on every step
            }
            foreach ( $job['paths'] as $p ) {
                if ( self::delete_file( $p ) ) {
                    $removed++;
                }
            }
        }
        return $removed;
    }

    /* ----------------------------------------------------------------
     * d. PRO DATA FOLDER: unfinished downloads (.tmp-xxxx / .tmp) older than 1 hour
     * ---------------------------------------------------------------- */
    private static function clean_temp_files( $dir, $now ) {
        if ( !is_dir( $dir ) || is_link( $dir ) ) {
            return 0;
        }
        $removed = 0;
        foreach ( self::list_files( $dir ) as $abs ) {
            $name = basename( $abs );
            if ( !preg_match( '/\\.tmp-[A-Za-z0-9]+$/', $name ) && !preg_match( '/\\.tmp$/i', $name ) ) {
                continue;
            }
            if ( (int) filemtime( $abs ) < $now - self::TEMP_MAX_AGE && self::delete_file( $abs ) ) {
                $removed++;
            }
        }
        return $removed;
    }

    /* ----------------------------------------------------------------
     * e. IGNORE LIST: entries of files that no longer exist (the Scanner's own rule), cap 5,000
     * ---------------------------------------------------------------- */
    private static function clean_ignore_list() {
        $before = get_option( 'sfais_scanner_ignored', array() );
        if ( !is_array( $before ) || empty( $before ) ) {
            return 0;
        }
        if ( !class_exists( 'SFAIS_Scanner' ) && defined( 'SFAIS_PATH' ) && file_exists( SFAIS_PATH . 'includes/class-sfais-scanner.php' ) ) {
            require_once SFAIS_PATH . 'includes/class-sfais-scanner.php';
        }
        if ( !class_exists( 'SFAIS_Scanner' ) ) {
            return 0;
        }
        ( new SFAIS_Scanner() )->list_ignored();
        // drops (and saves) the entries whose file is gone
        $after = get_option( 'sfais_scanner_ignored', array() );
        $after = ( is_array( $after ) ? $after : array() );
        if ( count( $after ) > self::IGNORES_MAX ) {
            $after = array_slice(
                $after,
                -self::IGNORES_MAX,
                null,
                true
            );
            // newest last: the oldest are dropped
            update_option( 'sfais_scanner_ignored', $after, false );
        }
        return max( 0, count( $before ) - count( $after ) );
    }

    /* ----------------------------------------------------------------
     * f. LOGS: files older than 90 days (the permissions log stays while that patch is on - it is needed to undo it)
     * ---------------------------------------------------------------- */
    private static function clean_logs( $dir, $now ) {
        if ( !is_dir( $dir ) || is_link( $dir ) ) {
            return 0;
        }
        $removed = 0;
        foreach ( self::list_files( $dir ) as $abs ) {
            $name = strtolower( basename( $abs ) );
            if ( in_array( $name, array('.htaccess', 'index.php', 'index.html'), true ) ) {
                continue;
            }
            if ( strtolower( self::PERM_LOG ) === $name && get_option( 'sfais_patch_permissions' ) ) {
                continue;
            }
            if ( (int) filemtime( $abs ) < $now - self::LOG_MAX_AGE && self::delete_file( $abs ) ) {
                $removed++;
            }
        }
        return $removed;
    }

    /* ----------------------------------------------------------------
     * g. EXPIRED LOGIN TRANSIENTS (daily + hourly)
     * ---------------------------------------------------------------- */
    /**
     * Delete expired sfais_login_* / sfais_unlock_* transients (value + timeout row) from wp_options.
     * Nothing to do with a persistent object cache (transients are not stored in wp_options then).
     *
     * @param int $max_rows Max rows removed in this run.
     * @return int Rows removed.
     */
    public static function purge_expired_login_transients( $max_rows = 5000 ) {
        if ( wp_using_ext_object_cache() ) {
            return 0;
        }
        global $wpdb;
        $pairs = max( 1, (int) floor( (int) $max_rows / 2 ) );
        $now = time();
        $names = array();
        foreach ( array('sfais_login_', 'sfais_unlock_') as $prefix ) {
            $left = $pairs - (int) (count( $names ) / 2);
            if ( $left <= 0 ) {
                break;
            }
            $like = $wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%';
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- housekeeping of the plugin's own expired rows; no API lists expired transients.
            $rows = $wpdb->get_col( $wpdb->prepare(
                "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s AND option_value < %d LIMIT %d",
                $like,
                $now,
                $left
            ) );
            foreach ( (array) $rows as $timeout_name ) {
                $timeout_name = (string) $timeout_name;
                $names[] = $timeout_name;
                $names[] = '_transient_' . substr( $timeout_name, strlen( '_transient_timeout_' ) );
            }
        }
        if ( empty( $names ) ) {
            return 0;
        }
        $removed = 0;
        foreach ( array_chunk( $names, 500 ) as $chunk ) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one %s placeholder per name, all values passed to prepare().
            $done = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name IN (" . implode( ',', array_fill( 0, count( $chunk ), '%s' ) ) . ')', $chunk ) );
            if ( is_int( $done ) ) {
                $removed += $done;
            }
            foreach ( $chunk as $name ) {
                wp_cache_delete( $name, 'options' );
            }
        }
        return $removed;
    }

    /* ----------------------------------------------------------------
     * h. OPTIONS LEFT OVER FROM 1.8.2 (once)
     * ---------------------------------------------------------------- */
    private static function remove_legacy_options() {
        if ( get_option( self::OPT_LEGACY ) ) {
            return 0;
        }
        $removed = 0;
        foreach ( array('sfais_ai_model_data', 'sfais_threat_feed_subnets') as $opt ) {
            if ( delete_option( $opt ) ) {
                $removed++;
            }
        }
        update_option( self::OPT_LEGACY, 1, false );
        return $removed;
    }

    /* ----------------------------------------------------------------
     * UNINSTALL (called by the Freemius after_uninstall handler when no other edition is installed)
     * ---------------------------------------------------------------- */
    /**
     * Step 1 (before the options are deleted): undo every change outside the data folder - saved file permissions back,
     * every patch reverted, every marked .htaccess block and marked file of the plugin removed.
     */
    public static function uninstall_files() {
        // The patches' own revert code knows its markers. Permissions first (it may have made .htaccess read-only).
        if ( class_exists( 'SFAIS_Patch_Manager' ) ) {
            $pm = new SFAIS_Patch_Manager();
            foreach ( array(
                'permissions',
                'filemods',
                'dirlisting',
                'php_wpcontent',
                'force_ssl',
                'wpconfig',
                'fileedit',
                'author_enum',
                'xmlrpc',
                'versioninfo'
            ) as $patch ) {
                try {
                    $pm->revert_patch( $patch );
                    // the FREE build answers "Unknown patch request" for PRO patches
                } catch ( \Throwable $e ) {
                    continue;
                }
            }
        }
        // Whatever is still there (PRO patch blocks in a FREE build, a file that was locked, the IP Blocker block):
        // marker-exact removal, nothing outside "# BEGIN <marker>" ... "# END <marker>" is changed.
        $uploads = self::uploads_dir();
        $files = array(
            ABSPATH . '.htaccess' => array(
                'MHSF',
                'SFAIS',
                'SFAIS Force HTTPS',
                'SFAIS Protect wp-config.php'
            ),
        );
        if ( '' !== $uploads ) {
            $files[$uploads . '/.htaccess'] = array('SFAIS Uploads Protection');
        }
        if ( defined( 'WP_CONTENT_DIR' ) ) {
            $files[rtrim( wp_normalize_path( WP_CONTENT_DIR ), '/' ) . '/.htaccess'] = array('Maroon Horizon Smart Firewall - block PHP in wp-content');
        }
        foreach ( $files as $file => $markers ) {
            try {
                self::strip_htaccess_file( $file, $markers );
            } catch ( \Throwable $e ) {
                continue;
            }
        }
        // The plugin's own leftover files outside the data folder (exact names only).
        $stray = array();
        if ( defined( 'WP_CONTENT_DIR' ) ) {
            $content = rtrim( wp_normalize_path( WP_CONTENT_DIR ), '/' );
            $stray[] = $content . '/.htaccess.mhsf-backup';
            // copy made by the PRO wp-content patch
            $stray[] = $content . '/.htaccess.mhsf-tmp';
            $stray = array_merge( $stray, self::matching_files( $content, '/^mhsf-probe-[A-Za-z0-9]{16}\\.php$/' ) );
        }
        if ( defined( 'WP_PLUGIN_DIR' ) ) {
            $stray = array_merge( $stray, self::matching_files( rtrim( wp_normalize_path( WP_PLUGIN_DIR ), '/' ), '/^mhsf-probe-[A-Za-z0-9]{16}\\.php$/' ) );
        }
        if ( '' !== $uploads ) {
            $stray = array_merge( $stray, self::matching_files( $uploads, '/^mhsf-check-[a-z0-9]{10}\\.txt$/' ) );
        }
        foreach ( $stray as $f ) {
            if ( is_file( $f ) ) {
                self::delete_file( $f );
            }
        }
    }

    /**
     * Step 2 (last): the data folder, the options the old list missed, transients, user meta, cron events.
     */
    public static function uninstall_data() {
        try {
            self::delete_data_folder();
        } catch ( \Throwable $e ) {
            unset($e);
            // never stop the database clean-up
        }
        foreach ( array(
            'sfais_login_locks',
            'sfais_ai_deep_scan_interval',
            'sfais_ai_deep_manual_last_ts',
            'mhsf_pro_welcome',
            'mhsf_force_premium_activation',
            self::OPT_LAST,
            self::OPT_LEGACY,
            'mhsf_activity_log',
            'sfais_ai_model_data',
            'sfais_threat_feed_subnets'
        ) as $opt ) {
            delete_option( $opt );
            if ( is_multisite() ) {
                delete_site_option( $opt );
            }
        }
        // Every sfais_ / mhsf_ transient (value + timeout rows).
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- uninstall: the plugin's own transients by prefix.
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
            $wpdb->esc_like( '_transient_sfais_' ) . '%',
            $wpdb->esc_like( '_transient_timeout_sfais_' ) . '%',
            $wpdb->esc_like( '_transient_mhsf_' ) . '%',
            $wpdb->esc_like( '_transient_timeout_mhsf_' ) . '%'
        ) );
        delete_metadata(
            'user',
            0,
            'mhsf_appearance',
            '',
            true
        );
        // Cron: the two housekeeping events, then every remaining mhsf_ / sfais_ event (also those of the PRO edition).
        foreach ( array(self::DAILY_HOOK, self::HOURLY_HOOK) as $hook ) {
            wp_unschedule_hook( $hook );
        }
        $crons = ( function_exists( '_get_cron_array' ) ? _get_cron_array() : array() );
        foreach ( ( is_array( $crons ) ? $crons : array() ) as $events ) {
            foreach ( array_keys( (array) $events ) as $hook ) {
                $hook = (string) $hook;
                if ( 0 === strpos( $hook, 'mhsf_' ) || 0 === strpos( $hook, 'sfais_' ) ) {
                    wp_unschedule_hook( $hook );
                }
            }
        }
    }

    /**
     * Remove the plugin's marked blocks from one .htaccess file. A file locked read-only is unlocked for the write and
     * locked again with its old permissions; a file that only held our blocks is deleted.
     *
     * @param string   $file    Absolute path.
     * @param string[] $markers Marker names ("# BEGIN <marker>" / "# END <marker>" alone on their lines).
     * @return bool True when no block of ours is left.
     */
    private static function strip_htaccess_file( $file, array $markers ) {
        if ( !is_file( $file ) ) {
            return true;
        }
        $old = SFAIS_FS::read( $file );
        if ( !is_string( $old ) ) {
            return false;
        }
        $new = self::strip_marked_blocks( $old, $markers );
        if ( $new === $old ) {
            return true;
        }
        $relock = null;
        if ( !SFAIS_FS::is_writable( $file ) ) {
            clearstatcache( true, $file );
            $perms = fileperms( $file );
            if ( false === $perms || !SFAIS_FS::chmod( $file, 0644 ) ) {
                return false;
            }
            $relock = $perms & 0777;
            clearstatcache( true, $file );
        }
        if ( '' === trim( $new ) ) {
            $ok = self::delete_file( $file );
        } else {
            $ok = in_array( SFAIS_FS::write_htaccess_checked( $file, $new ), array('ok', 'unverified'), true );
        }
        if ( null !== $relock && file_exists( $file ) ) {
            SFAIS_FS::chmod( $file, $relock );
            clearstatcache( true, $file );
        }
        return $ok;
    }

    /**
     * Text without the marked blocks. Only "# BEGIN <marker>" ... "# END <marker>" (each alone on its line, exact marker)
     * and the line break after it are removed; "# BEGIN SFAIS" does not match "# BEGIN SFAIS Force HTTPS".
     *
     * @param string   $content File contents.
     * @param string[] $markers Marker names.
     * @return string
     */
    public static function strip_marked_blocks( $content, array $markers ) {
        $content = (string) $content;
        foreach ( $markers as $marker ) {
            $q = preg_quote( (string) $marker, '/' );
            $re = '/^[ \\t]*# BEGIN ' . $q . '[ \\t]*\\R.*?^[ \\t]*# END ' . $q . '[ \\t]*(?:\\R|\\z)/ms';
            $new = preg_replace( $re, '', $content );
            if ( is_string( $new ) ) {
                $content = $new;
            }
        }
        return $content;
    }

    /**
     * Delete uploads/maroon-horizon-smart-firewall/ with everything in it - only after checking that the real path is
     * that folder directly inside the uploads folder. Links inside are removed as links (never followed).
     *
     * @return bool
     */
    private static function delete_data_folder() {
        $uploads = self::uploads_dir();
        if ( '' === $uploads ) {
            return false;
        }
        $dir = $uploads . '/' . self::DATA_SLUG;
        if ( is_link( $dir ) ) {
            wp_delete_file( $dir );
            // the link only, never what it points to
            return !is_link( $dir );
        }
        if ( !is_dir( $dir ) ) {
            return true;
        }
        $real = realpath( $dir );
        $base_real = realpath( $uploads );
        if ( false === $real || false === $base_real ) {
            return false;
        }
        $real = wp_normalize_path( $real );
        $base_real = rtrim( wp_normalize_path( $base_real ), '/' );
        if ( wp_normalize_path( dirname( $real ) ) !== $base_real || self::DATA_SLUG !== basename( $real ) ) {
            return false;
        }
        $files = array();
        $dirs = array();
        self::scan_tree(
            $real,
            $files,
            $dirs,
            true
        );
        foreach ( $files as $f ) {
            self::delete_file( $f );
        }
        usort( $dirs, static function ( $a, $b ) {
            return strlen( $b ) <=> strlen( $a );
        } );
        foreach ( $dirs as $d ) {
            SFAIS_FS::delete( $d );
        }
        SFAIS_FS::delete( $real );
        // the (now empty) data folder itself
        clearstatcache();
        return !file_exists( $real );
    }

    /* ----------------------------------------------------------------
     * HELPERS
     * ---------------------------------------------------------------- */
    /** uploads folder (normalized, no trailing slash), '' when unknown. */
    private static function uploads_dir() {
        $base = ( function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : '' );
        if ( is_wp_error( $base ) || !is_string( $base ) || '' === $base ) {
            return '';
        }
        return rtrim( wp_normalize_path( $base ), '/' );
    }

    /** The plugin's data folder when it exists ('' otherwise - the clean-up never creates it). */
    private static function data_dir() {
        $uploads = self::uploads_dir();
        if ( '' === $uploads ) {
            return '';
        }
        $dir = $uploads . '/' . self::DATA_SLUG;
        return ( is_dir( $dir ) && !is_link( $dir ) ? $dir : '' );
    }

    /**
     * Files and folders below $root (folders without $root itself). Links to folders are never entered.
     *
     * @param string $root      Folder.
     * @param array  $files     Out: files (with $with_links: also every link).
     * @param array  $dirs      Out: folders.
     * @param bool   $with_links Include links in $files (uninstall: links are removed as links).
     */
    private static function scan_tree(
        $root,
        array &$files,
        array &$dirs,
        $with_links = false
    ) {
        $stack = array(rtrim( wp_normalize_path( $root ), '/' ));
        while ( $stack ) {
            $dir = array_pop( $stack );
            $entries = ( is_readable( $dir ) ? scandir( $dir ) : false );
            if ( !is_array( $entries ) ) {
                continue;
            }
            foreach ( $entries as $entry ) {
                if ( '.' === $entry || '..' === $entry ) {
                    continue;
                }
                $abs = $dir . '/' . $entry;
                if ( is_link( $abs ) ) {
                    if ( $with_links ) {
                        $files[] = $abs;
                    }
                    continue;
                }
                if ( is_dir( $abs ) ) {
                    $dirs[] = $abs;
                    $stack[] = $abs;
                } elseif ( is_file( $abs ) ) {
                    $files[] = $abs;
                }
            }
        }
    }

    /** Regular files directly in $dir (no links). */
    private static function list_files( $dir ) {
        $out = array();
        $dir = rtrim( wp_normalize_path( $dir ), '/' );
        $entries = ( is_readable( $dir ) ? scandir( $dir ) : false );
        if ( !is_array( $entries ) ) {
            return $out;
        }
        foreach ( $entries as $entry ) {
            $abs = $dir . '/' . $entry;
            if ( '.' !== $entry && '..' !== $entry && !is_link( $abs ) && is_file( $abs ) ) {
                $out[] = $abs;
            }
        }
        return $out;
    }

    /** Regular files directly in $dir whose name matches $regex. */
    private static function matching_files( $dir, $regex ) {
        $out = array();
        foreach ( self::list_files( $dir ) as $abs ) {
            if ( preg_match( $regex, basename( $abs ) ) ) {
                $out[] = $abs;
            }
        }
        return $out;
    }

    private static function dir_is_empty( $dir ) {
        $entries = ( is_readable( $dir ) ? scandir( $dir ) : false );
        return is_array( $entries ) && count( array_diff( $entries, array('.', '..') ) ) === 0;
    }

    /** Delete one file (or link); true when it is gone. */
    private static function delete_file( $path ) {
        if ( !is_link( $path ) ) {
            SFAIS_FS::delete( $path );
        }
        clearstatcache( true, $path );
        if ( file_exists( $path ) || is_link( $path ) ) {
            wp_delete_file( $path );
            clearstatcache( true, $path );
        }
        return !file_exists( $path ) && !is_link( $path );
    }

    /** JSON list from a file, null when the file is missing or not a JSON array. */
    private static function read_json_array( $path ) {
        if ( !is_file( $path ) ) {
            return null;
        }
        $raw = SFAIS_FS::read( $path );
        $data = ( is_string( $raw ) ? json_decode( $raw, true ) : null );
        return ( is_array( $data ) ? $data : null );
    }

}
