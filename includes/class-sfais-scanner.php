<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
class SFAIS_Scanner {
    const REPORT_DIR = 'maroon-horizon-smart-firewall/reports';

    const QUAR_DIR = 'maroon-horizon-smart-firewall/quarantine';

    const QUAR_LOG = 'sfais-quarantine-log.json';

    const QUAR_EXT = '.mhsfq';

    // 1.8.15 option A (Vlad): quarantined files are stored ENCODED under a random name
    const QUAR_MAGIC = 'MHSFQ1';

    const QUAR_MAX = 52428800;

    // one file up to 50 MB (= the whole quarantine limit of the daily clean-up)
    const LAST_CORE = 'sfais_last_core_report';

    const LAST_CONTENT = 'sfais_last_content_report';

    const IGNORES_OPT = 'sfais_scanner_ignored';

    const IGNORES_MAX = 5000;

    // 1.8.13: cap of the ignore list (oldest entries dropped)
    const DEEP_LAST = 'sfais_ai_deep_last_report';

    // 1.8.13: PRO Deep Scan report (only written by the PRO build)
    const CONTENT_ROWS_MAX = 500;

    // 1.8.15: rows kept in a stored content scan report (the summary keeps the true totals)
    /* ---------- Utils ---------- */
    private function ensure_dir( $dir ) {
        if ( !is_dir( $dir ) ) {
            return SFAIS_FS::mkdir_p( $dir );
        }
        return true;
    }

    private function uploads_base() {
        // 1.8.13: create + protect uploads/maroon-horizon-smart-firewall/ (deny-all .htaccess + index.php) before any report or
        // quarantined file is written there - FREE users who only run the scanner never reached mhsf_get_data_dir() before.
        static $protected = false;
        if ( !$protected && function_exists( 'mhsf_get_data_dir' ) ) {
            $protected = true;
            mhsf_get_data_dir();
        }
        $basedir = ( function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '' );
        if ( is_wp_error( $basedir ) || '' === $basedir ) {
            return '';
        }
        return rtrim( wp_normalize_path( (string) $basedir ), '/\\' );
    }

    /**
     * Format a unix timestamp in a WP-compatible way (supports older WP).
     */
    private function format_ts( $ts ) {
        $ts = (int) $ts;
        if ( $ts <= 0 ) {
            return '';
        }
        if ( function_exists( 'wp_date' ) ) {
            return wp_date( 'Y-m-d H:i:s', $ts );
        }
        if ( function_exists( 'date_i18n' ) ) {
            return date_i18n( 'Y-m-d H:i:s', $ts );
        }
        return gmdate( 'Y-m-d H:i:s', $ts );
    }

    /**
     * 1.8.13: the plugin's own data folder (uploads/maroon-horizon-smart-firewall/: reports, quarantine, logs), absolute, with a
     * trailing slash ('' when the uploads folder is unknown). No scan looks inside it (quarantined files must not be re-flagged).
     *
     * @return string
     */
    public static function own_data_prefix() {
        $basedir = ( function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '' );
        if ( is_wp_error( $basedir ) || '' === (string) $basedir ) {
            return '';
        }
        return rtrim( wp_normalize_path( (string) $basedir ), '/\\' ) . '/maroon-horizon-smart-firewall/';
    }

    /**
     * 1.8.13: true for the plugin's own data folder and everything inside it.
     *
     * @param string      $abs    Absolute path (file or folder).
     * @param string|null $prefix own_data_prefix() when already known.
     * @return bool
     */
    public static function is_own_data_path( $abs, $prefix = null ) {
        if ( null === $prefix ) {
            $prefix = self::own_data_prefix();
        }
        if ( '' === (string) $prefix ) {
            return false;
        }
        $p = rtrim( wp_normalize_path( (string) $abs ), '/' ) . '/';
        return 0 === strpos( $p, (string) $prefix );
    }

    /**
     * 1.8.13: the ignore list as a lookup index: 'sig' = [rel => MD5 or 'missing'], 'legacy' = [rel => true] (old entries
     * without a fingerprint, saved when the file could not be read).
     *
     * @return array
     */
    public static function ignore_index() {
        $raw = get_option( self::IGNORES_OPT, [] );
        $idx = [
            'sig'    => [],
            'legacy' => [],
        ];
        if ( !is_array( $raw ) ) {
            return $idx;
        }
        foreach ( $raw as $k => $v ) {
            if ( is_array( $v ) && array_key_exists( 'sig', $v ) ) {
                $idx['sig'][(string) $k] = strtolower( (string) $v['sig'] );
            } elseif ( is_string( $v ) && '' !== $v ) {
                $idx['legacy'][$v] = true;
            }
        }
        return $idx;
    }

    /**
     * 1.8.13: is this file ignored right now? An ignore only holds while the file is unchanged (same MD5 as when it was
     * ignored; 'missing' = while it is still missing). A changed file is scanned again. Legacy entries without a fingerprint
     * stay ignored (there is nothing to compare).
     *
     * @param array       $idx  ignore_index().
     * @param string      $rel  ABSPATH-relative path.
     * @param string      $abs  Absolute path.
     * @param string|null $hash MD5 of the current content when already known, 'missing' when the file is gone, '' when unreadable.
     * @return bool
     */
    public static function is_ignored_now(
        array $idx,
        $rel,
        $abs,
        $hash = null
    ) {
        $rel = (string) $rel;
        if ( isset( $idx['legacy'][$rel] ) ) {
            return true;
        }
        if ( !isset( $idx['sig'][$rel] ) ) {
            return false;
        }
        $sig = (string) $idx['sig'][$rel];
        if ( null === $hash ) {
            if ( !file_exists( $abs ) ) {
                $hash = 'missing';
            } elseif ( is_file( $abs ) && is_readable( $abs ) ) {
                $h = @md5_file( $abs );
                // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an unreadable file is simply not ignored
                $hash = ( is_string( $h ) ? $h : '' );
            } else {
                $hash = '';
            }
        }
        $hash = strtolower( (string) $hash );
        return '' !== $sig && '' !== $hash && $hash === $sig;
    }

    /**
     * 1.8.13: MD5 of a file, or '' when it can't be read.
     *
     * @param string $abs Absolute path.
     * @return string
     */
    private function file_md5( $abs ) {
        if ( !is_file( $abs ) || !is_readable( $abs ) ) {
            return '';
        }
        $h = @md5_file( $abs );
        // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        return ( is_string( $h ) ? strtolower( $h ) : '' );
    }

    /**
     * 1.8.13: keep the stored reports in step after Delete / Ignore / Quarantine: the file's rows are removed from the last core,
     * content and PRO Deep Scan report and their summary numbers are corrected, so the row does not come back on reload.
     *
     * @param array  $rels   ABSPATH-relative paths.
     * @param string $action 'ignore', 'quarantine' or 'delete'.
     * @return void
     */
    public function forget_in_reports( array $rels, $action ) {
        $set = [];
        foreach ( $rels as $r ) {
            if ( is_string( $r ) && '' !== $r ) {
                $set[$r] = true;
            }
        }
        if ( !$set ) {
            return;
        }
        $opts = [self::LAST_CORE, self::LAST_CONTENT];
        foreach ( $opts as $opt ) {
            $rep = get_option( $opt );
            if ( !is_array( $rep ) || empty( $rep['items'] ) || !is_array( $rep['items'] ) ) {
                continue;
            }
            $sum = ( isset( $rep['summary'] ) && is_array( $rep['summary'] ) ? $rep['summary'] : [] );
            $kept = [];
            $hit = false;
            foreach ( $rep['items'] as $it ) {
                if ( is_array( $it ) && isset( $it['file'] ) && is_string( $it['file'] ) && isset( $set[$it['file']] ) ) {
                    $hit = true;
                    $st = ( isset( $it['status'] ) ? strtolower( (string) $it['status'] ) : '' );
                    if ( '' !== $st && isset( $sum[$st] ) && (int) $sum[$st] > 0 ) {
                        $sum[$st] = (int) $sum[$st] - 1;
                    }
                    if ( 'ignore' === $action ) {
                        // still scanned, now counted as ignored
                        if ( isset( $sum['ignored'] ) && 'ignored' !== $st ) {
                            $sum['ignored'] = (int) $sum['ignored'] + 1;
                        }
                    } elseif ( isset( $sum['total'] ) && (int) $sum['total'] > 0 ) {
                        // quarantined / deleted: the file is no longer on the site
                        $sum['total'] = (int) $sum['total'] - 1;
                    }
                    continue;
                }
                $kept[] = $it;
            }
            if ( !$hit ) {
                continue;
            }
            $rep['items'] = $kept;
            if ( $sum ) {
                $rep['summary'] = $sum;
            }
            update_option( $opt, $rep, false );
        }
    }

    /**
     * Safely walk a directory tree without throwing SPL iterator exceptions.
     *
     * Some hosting setups contain unreadable directories under the uploads directory (as returned by wp_upload_dir())
     * (e.g. cache artifacts, permission mismatches). Using RecursiveDirectoryIterator
     * can throw UnexpectedValueException which breaks AJAX responses ("Network error").
     *
     * @param string   $root   Absolute path (file or directory).
     * @param callable $onFile Callback invoked with absolute file path.
     * @param string   $file_regex Optional regex to filter files by name/path.
     * @param callable|null $skip_path Optional callback (abs path) => bool to skip.
     * @return void
     */
    private function safe_walk(
        $root,
        callable $onFile,
        $file_regex = null,
        $skip_path = null
    ) {
        $root = wp_normalize_path( (string) $root );
        if ( $root === '' || !file_exists( $root ) ) {
            return;
        }
        // Single file.
        if ( is_file( $root ) ) {
            if ( is_callable( $skip_path ) && $skip_path( $root ) ) {
                return;
            }
            if ( is_string( $file_regex ) && $file_regex !== '' && !preg_match( $file_regex, $root ) ) {
                return;
            }
            $onFile( $root );
            return;
        }
        if ( !is_dir( $root ) ) {
            return;
        }
        $stack = [$root];
        while ( !empty( $stack ) ) {
            $dir = array_pop( $stack );
            if ( !is_dir( $dir ) ) {
                continue;
            }
            if ( is_link( $dir ) ) {
                // Avoid symlink loops.
                continue;
            }
            if ( !is_readable( $dir ) ) {
                continue;
            }
            $entries = @scandir( $dir );
            if ( !is_array( $entries ) ) {
                continue;
            }
            foreach ( $entries as $entry ) {
                if ( $entry === '.' || $entry === '..' ) {
                    continue;
                }
                $abs = wp_normalize_path( $dir . '/' . $entry );
                if ( is_callable( $skip_path ) && $skip_path( $abs ) ) {
                    continue;
                }
                if ( is_dir( $abs ) ) {
                    $stack[] = $abs;
                    continue;
                }
                if ( !is_file( $abs ) ) {
                    continue;
                }
                if ( is_string( $file_regex ) && $file_regex !== '' && !preg_match( $file_regex, $abs ) ) {
                    continue;
                }
                $onFile( $abs );
            }
        }
    }

    private function write_json( $path, $data ) {
        $this->ensure_dir( dirname( $path ) );
        $json = ( function_exists( 'wp_json_encode' ) ? wp_json_encode( $data, JSON_PRETTY_PRINT ) : json_encode( $data, JSON_PRETTY_PRINT ) );
        if ( !is_string( $json ) ) {
            $json = json_encode( $data );
        }
        return SFAIS_FS::write( $path, $json );
    }

    private function read_json( $path ) {
        if ( !file_exists( $path ) ) {
            return null;
        }
        $j = SFAIS_FS::read( $path );
        if ( !is_string( $j ) || $j === '' ) {
            return null;
        }
        $arr = json_decode( $j, true );
        return ( is_array( $arr ) ? $arr : null );
    }

    /**
     * Enforce report retention on disk to prevent uploads directory bloat.
     * Hardcoded safety: keep only the newest N reports per report type.
     *
     * @param string $dir  Absolute reports directory.
     * @param string $type Report type slug (e.g. core, content, ai_deep).
     * @param int    $limit Max files to keep.
     */
    private function enforce_report_retention( $dir, $type, $limit = 5 ) {
        $dir = (string) $dir;
        $type = ( is_string( $type ) ? preg_replace( '/[^a-zA-Z0-9_\\-]/', '', $type ) : '' );
        $limit = (int) $limit;
        if ( $limit < 1 ) {
            $limit = 1;
        }
        if ( $dir === '' || $type === '' || !is_dir( $dir ) ) {
            return;
        }
        $prefix = 'scan-' . $type . '-';
        $files = [];
        try {
            $it = new DirectoryIterator($dir);
        } catch ( Exception $e ) {
            return;
        }
        foreach ( $it as $f ) {
            if ( !$f->isFile() ) {
                continue;
            }
            $name = (string) $f->getFilename();
            if ( strpos( $name, $prefix ) !== 0 ) {
                continue;
            }
            // Keep both JSON and ZIP variants (some builds may archive reports).
            if ( !preg_match( '/\\.(json|zip)$/i', $name ) ) {
                continue;
            }
            $files[] = [
                'path'  => (string) $f->getPathname(),
                'mtime' => (int) $f->getMTime(),
            ];
        }
        if ( count( $files ) <= $limit ) {
            return;
        }
        usort( $files, static function ( $a, $b ) {
            return (int) $b['mtime'] <=> (int) $a['mtime'];
        } );
        $to_delete = array_slice( $files, $limit );
        foreach ( $to_delete as $row ) {
            if ( !empty( $row['path'] ) ) {
                SFAIS_FS::delete( $row['path'] );
            }
        }
    }

    private function rel( $abs ) {
        $abs = wp_normalize_path( $abs );
        $root = wp_normalize_path( ABSPATH );
        if ( strpos( $abs, $root ) === 0 ) {
            return ltrim( substr( $abs, strlen( $root ) ), '/' );
        }
        return $abs;
    }

    /**
     * Strictly validate a *relative* path (ABSPATH-relative).
     * Returns normalized relative path on success, or false.
     */
    private function normalize_rel_path( $relPath ) {
        if ( !is_string( $relPath ) || $relPath === '' ) {
            return false;
        }
        // Null byte protection
        if ( strpos( $relPath, "\x00" ) !== false ) {
            return false;
        }
        // Normalize slashes and trim
        $rel = wp_normalize_path( $relPath );
        $rel = ltrim( $rel, '/' );
        // Reject absolute paths, URLs, drive letters
        if ( preg_match( '#^(?:[a-zA-Z]+:|/|\\\\)#', $relPath ) ) {
            return false;
        }
        // Reject traversal
        if ( strpos( $rel, '../' ) !== false || strpos( $rel, '..\\' ) !== false || $rel === '..' ) {
            return false;
        }
        // Reject empty after trimming
        if ( $rel === '' ) {
            return false;
        }
        return $rel;
    }

    /**
     * Resolve an ABSPATH-relative path to an absolute real path (if exists) and enforce containment.
     * - If $must_exist = true, requires file to exist and realpath() to succeed.
     * - If $must_exist = false, validates parent directory containment as best-effort (for future file paths).
     */
    private function resolve_abs_from_rel( $relPath, $must_exist = true ) {
        $rel = $this->normalize_rel_path( $relPath );
        if ( $rel === false ) {
            return false;
        }
        $root_real = realpath( ABSPATH );
        if ( !$root_real ) {
            return false;
        }
        $root_real = wp_normalize_path( $root_real );
        $abs = wp_normalize_path( ABSPATH . $rel );
        if ( $must_exist ) {
            $real = realpath( $abs );
            if ( !$real ) {
                return false;
            }
            $real = wp_normalize_path( $real );
            if ( strpos( $real, $root_real . '/' ) !== 0 && $real !== $root_real ) {
                return false;
            }
            return $real;
        }
        // For non-existing targets, validate directory containment
        $parent = wp_normalize_path( dirname( $abs ) );
        $parent_real = realpath( $parent );
        if ( !$parent_real ) {
            return false;
        }
        $parent_real = wp_normalize_path( $parent_real );
        if ( strpos( $parent_real, $root_real . '/' ) !== 0 && $parent_real !== $root_real ) {
            return false;
        }
        return $abs;
    }

    /**
     * Check whether a given rel path is present in the last known scan reports
     * (core, content, or AI deep). This prevents acting on arbitrary paths sent from UI.
     */
    /**
     * 1.8.15: the reason the last scan gave for this file (kept with a quarantined file - the list said "Manual action" for all).
     *
     * @return string '' when the file is in no stored report
     */
    public function report_reason( $relPath ) {
        $item = $this->is_actionable_from_last_reports( $relPath, true );
        return ( is_array( $item ) && isset( $item['reason'] ) ? (string) $item['reason'] : '' );
    }

    private function is_actionable_from_last_reports( $relPath, $want_item = false ) {
        $rel = $this->normalize_rel_path( $relPath );
        if ( $rel === false ) {
            return false;
        }
        // Helper: search report.items[*].file for an exact match (1.8.15: the row itself when $want_item)
        $in_report = function ( $report ) use($rel, $want_item) {
            if ( !is_array( $report ) || empty( $report['items'] ) || !is_array( $report['items'] ) ) {
                return false;
            }
            foreach ( $report['items'] as $it ) {
                if ( isset( $it['file'] ) && is_string( $it['file'] ) && $it['file'] === $rel ) {
                    return ( $want_item ? $it : true );
                }
            }
            return false;
        };
        // FREE: last core report
        $core = get_option( self::LAST_CORE );
        if ( false !== ($hit = $in_report( $core )) ) {
            return $hit;
        }
        // FREE: last content report
        $content = get_option( self::LAST_CONTENT );
        if ( false !== ($hit = $in_report( $content )) ) {
            return $hit;
        }
        // Optional add-on: last Deep Scan report (premium build only).
        $ai_deep = null;
        if ( false !== ($hit = $in_report( $ai_deep )) ) {
            return $hit;
        }
        return false;
    }

    /**
     * Resolve a quarantine-relative path to an absolute real path,
     * and enforce it stays inside uploads/maroon-horizon-smart-firewall/quarantine.
     */
    private function resolve_quarantine_abs( $quarantineRel ) {
        if ( !is_string( $quarantineRel ) || $quarantineRel === '' ) {
            return false;
        }
        if ( strpos( $quarantineRel, "\x00" ) !== false ) {
            return false;
        }
        $base = $this->uploads_base();
        $qdir = wp_normalize_path( $base . '/' . self::QUAR_DIR );
        // Ensure quarantine directory exists so realpath() can be evaluated reliably.
        $this->ensure_dir( $qdir );
        $qdir_real = realpath( $qdir );
        if ( !$qdir_real ) {
            return false;
        }
        $qdir_real = wp_normalize_path( $qdir_real );
        $qRel = wp_normalize_path( ltrim( $quarantineRel, '/' ) );
        // Reject traversal for quarantine rel too
        if ( strpos( $qRel, '../' ) !== false || strpos( $qRel, '..\\' ) !== false || $qRel === '..' ) {
            return false;
        }
        $abs = wp_normalize_path( $base . '/' . $qRel );
        $real = realpath( $abs );
        if ( !$real ) {
            return false;
        }
        $real = wp_normalize_path( $real );
        if ( strpos( $real, $qdir_real . '/' ) !== 0 && $real !== $qdir_real ) {
            return false;
        }
        // 1.8.13: the quarantine log and the folder's own protection files are never restored or deleted from the UI.
        if ( $this->is_quarantine_system_file( $real, $qdir_real ) ) {
            return false;
        }
        return $real;
    }

    /**
     * 1.8.15: a content scan report keeps at most CONTENT_ROWS_MAX rows - suspicious files first, then the others (ignored,
     * unknown) in scan order. `summary` keeps the true totals; summary['rows_capped'] = number of rows left out.
     *
     * @param array $report Report.
     * @return array
     */
    private function cap_report_rows( $report ) {
        if ( !is_array( $report ) || !isset( $report['type'] ) || 'content' !== $report['type'] || empty( $report['items'] ) || !is_array( $report['items'] ) || count( $report['items'] ) <= self::CONTENT_ROWS_MAX ) {
            return $report;
        }
        $first = [];
        $other = [];
        foreach ( $report['items'] as $it ) {
            if ( is_array( $it ) && isset( $it['status'] ) && 'suspicious' === $it['status'] ) {
                $first[] = $it;
            } else {
                $other[] = $it;
            }
        }
        $all = array_merge( $first, $other );
        $dropped = count( $all ) - self::CONTENT_ROWS_MAX;
        $report['items'] = array_slice( $all, 0, self::CONTENT_ROWS_MAX );
        if ( !isset( $report['summary'] ) || !is_array( $report['summary'] ) ) {
            $report['summary'] = [];
        }
        $report['summary']['rows_capped'] = (int) ($report['summary']['rows_capped'] ?? 0) + $dropped;
        return $report;
    }

    /* ---------- Reports ---------- */
    public function save_report( $report, $save_as_last = true ) {
        $report = $this->cap_report_rows( $report );
        // 1.8.15
        $base = $this->uploads_base();
        $dir = $base . '/' . self::REPORT_DIR;
        $this->ensure_dir( $dir );
        $ts = current_time( 'mysql' );
        $fname = 'scan-' . $report['type'] . '-' . gmdate( 'Ymd-His' ) . '.json';
        $report['timestamp'] = $ts;
        if ( $save_as_last && isset( $report['type'] ) ) {
            $prev = get_option( ( $report['type'] === 'core' ? self::LAST_CORE : self::LAST_CONTENT ) );
            if ( is_array( $prev ) && !empty( $prev['items'] ) ) {
                foreach ( $report['items'] as &$item ) {
                    foreach ( $prev['items'] as $p ) {
                        if ( $p['file'] === $item['file'] && $p['status'] !== $item['status'] ) {
                            $item['reason'] .= ' (Changed from ' . $p['status'] . ' → ' . $item['status'] . ')';
                        }
                    }
                }
            }
        }
        $this->write_json( $dir . '/' . $fname, $report );
        // Hard cap: keep only the newest 5 report archives per type.
        if ( isset( $report['type'] ) ) {
            $this->enforce_report_retention( $dir, (string) $report['type'], 5 );
        }
        if ( $save_as_last ) {
            // 1.8.13: never autoloaded (reports can be large and are only needed on the plugin screens).
            if ( $report['type'] === 'core' ) {
                update_option( self::LAST_CORE, $report, false );
            } elseif ( $report['type'] === 'content' ) {
                update_option( self::LAST_CONTENT, $report, false );
            }
        }
        return true;
    }

    public function last_report( $type = null ) {
        if ( $type === 'core' ) {
            return get_option( self::LAST_CORE );
        }
        if ( $type === 'content' ) {
            return get_option( self::LAST_CONTENT );
        }
        return null;
    }

    /* ---------- Core checksum scan ----------
     * 1.8.13: the old synchronous scan_core() (AJAX sfais_scan_core) was removed - the UI only uses the async job
     * (sfais_scan_core_start/_tick/_cancel in the functions class); it also stored every clean row in an autoloaded option.
     */
    /* ---------- Uploads & themes scan (LOCAL ONLY) ---------- */
    public function scan_paths( $paths, $use_ai = false, $save_as_last = true ) {
        // 1.8.13: an ignore holds only while the file is unchanged (fingerprint check in is_ignored_now()).
        $ign_idx = self::ignore_index();
        $own_data = self::own_data_prefix();
        $items = [];
        $total = 0;
        $suspicious = 0;
        $clean = 0;
        $ignored_count = 0;
        $unknown = 0;
        $pattern = '/\\b(eval\\s*\\(|base64_decode\\s*\\(|gzinflate\\s*\\(|shell_exec\\s*\\(|system\\s*\\(|assert\\s*\\(|exec\\s*\\(|passthru\\s*\\(|proc_open\\s*\\()/i';
        $scan_file = function ( $file ) use(
            &$items,
            &$total,
            &$suspicious,
            &$clean,
            &$ignored_count,
            &$unknown,
            $pattern,
            $ign_idx
        ) {
            $total++;
            $rel = $this->rel( $file );
            if ( self::is_ignored_now( $ign_idx, $rel, $file ) ) {
                $items[] = [
                    'file'   => $rel,
                    'status' => 'ignored',
                    'reason' => 'Manually ignored',
                ];
                $ignored_count++;
                return;
            }
            if ( !is_readable( $file ) ) {
                $items[] = [
                    'file'   => $rel,
                    'status' => 'unknown',
                    'reason' => 'Unreadable',
                ];
                $unknown++;
                return;
            }
            $code = SFAIS_FS::read( $file );
            if ( !is_string( $code ) ) {
                $items[] = [
                    'file'   => $rel,
                    'status' => 'unknown',
                    'reason' => 'Read failed',
                ];
                $unknown++;
                return;
            }
            $has_pattern = (bool) preg_match_all( $pattern, $code, $found );
            if ( $has_pattern ) {
                // 1.8.15: say WHICH functions were found (also kept as the quarantine reason) - was always "Dangerous function pattern"
                $names = array_unique( array_map( static function ( $m ) {
                    return strtolower( preg_replace( '/\\s*\\($/', '', $m ) ) . '()';
                }, $found[1] ) );
                $items[] = [
                    'file'   => $rel,
                    'status' => 'suspicious',
                    'reason' => 'High-risk PHP: ' . implode( ', ', array_slice( $names, 0, 4 ) ),
                ];
                $suspicious++;
                return;
            }
            // Keep reports compact: the UI only renders non-clean rows.
            $clean++;
        };
        foreach ( $paths as $p ) {
            $p = wp_normalize_path( $p );
            if ( !file_exists( $p ) ) {
                continue;
            }
            // Walk PHP files safely (prevents iterator exceptions from breaking AJAX).
            $this->safe_walk(
                $p,
                function ( $abs ) use($scan_file) {
                    $scan_file( $abs );
                },
                '/\\.php[0-9]*$/i',
                // 1.8.13: never scan the plugin's own data folder (reports, quarantine).
                static function ( $abs ) use($own_data) {
                    return self::is_own_data_path( $abs, $own_data );
                }
            );
        }
        $summary = [
            'total'      => $total,
            'suspicious' => $suspicious,
            'clean'      => $clean,
            'ignored'    => $ignored_count,
            'unknown'    => $unknown,
        ];
        $report = [
            'type'    => 'content',
            'summary' => $summary,
            'items'   => $items,
        ];
        // 1.8.15: capped here too, so the screen shows the same rows as the stored report.
        $report = $this->cap_report_rows( $report );
        $this->save_report( $report, $save_as_last );
        return [
            'success' => true,
            'message' => 'Content scan completed.',
            'report'  => $report,
        ];
    }

    /* ---------- Quarantine / delete / ignore ---------- */
    /**
     * 1.8.13: name of a file inside the quarantine. PHP files become .phq (as before); server config files (.htaccess,
     * .user.ini, php.ini) get ".quarantined" appended so they can never act as live config inside the quarantine tree.
     *
     * @param string $target Absolute target path (mirror of the original path).
     * @return string
     */
    /**
     * 1.8.15 option A: the file's bytes, gzip-compressed and base64-encoded behind a marker line. Nothing in it can run, it can't
     * be opened as the original from the web, and host virus scanners don't see the original code.
     */
    private static function quarantine_encode( $data ) {
        $z = ( function_exists( 'gzdeflate' ) ? gzdeflate( (string) $data, 6 ) : false );
        return self::QUAR_MAGIC . (( false !== $z ? ' gz' : ' raw' )) . "\n" . chunk_split( base64_encode( ( false !== $z ? $z : (string) $data ) ), 76, "\n" );
    }

    /** @return string|false the original bytes, false when the file is not in the encoded format */
    private static function quarantine_decode( $blob ) {
        $blob = (string) $blob;
        if ( 0 !== strpos( $blob, self::QUAR_MAGIC . ' ' ) ) {
            return false;
        }
        $nl = strpos( $blob, "\n" );
        $head = substr( $blob, 0, ( false === $nl ? 0 : $nl ) );
        $raw = base64_decode( (string) substr( $blob, ( false === $nl ? 0 : $nl + 1 ) ), false );
        if ( false === $raw ) {
            return false;
        }
        if ( substr( $head, -3 ) === ' gz' ) {
            // a damaged copy gives false (no warning to the screen)
            // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
            $raw = ( function_exists( 'gzinflate' ) ? @gzinflate( $raw ) : false );
        }
        return ( is_string( $raw ) ? $raw : false );
    }

    /** absolute path of a new random quarantine file (flat folder - the name says nothing about the original) */
    private function quarantine_new_target( $qdir ) {
        do {
            $name = bin2hex( random_bytes( 12 ) ) . self::QUAR_EXT;
        } while ( file_exists( $qdir . '/' . $name ) );
        return wp_normalize_path( $qdir . '/' . $name );
    }

    /**
     * 1.8.15: store one file encoded in the quarantine, verified, then remove the original.
     *
     * @return array{success:bool,message:string,entry?:array}
     */
    private function quarantine_store(
        $abs,
        $relNorm,
        $reason,
        $date = null
    ) {
        $size = ( is_file( $abs ) ? filesize( $abs ) : false );
        if ( false === $size || $size > self::QUAR_MAX ) {
            return [
                'success' => false,
                'message' => 'This file is too big for the quarantine (more than 50 MB). Delete it or ignore it instead.',
            ];
        }
        $data = SFAIS_FS::read( $abs );
        if ( !is_string( $data ) || strlen( $data ) !== (int) $size ) {
            return [
                'success' => false,
                'message' => 'The file could not be read.',
            ];
        }
        $base = $this->uploads_base();
        $qdir = wp_normalize_path( $base . '/' . self::QUAR_DIR );
        $this->ensure_dir( $qdir );
        $target = $this->quarantine_new_target( $qdir );
        if ( !SFAIS_FS::write( $target, self::quarantine_encode( $data ) ) ) {
            return [
                'success' => false,
                'message' => 'Failed to move file to quarantine.',
            ];
        }
        $check = self::quarantine_decode( (string) SFAIS_FS::read( $target ) );
        if ( !is_string( $check ) || hash( 'sha256', $check ) !== hash( 'sha256', $data ) ) {
            SFAIS_FS::delete( $target );
            return [
                'success' => false,
                'message' => 'Failed to move file to quarantine (check after writing did not match).',
            ];
        }
        SFAIS_FS::chmod( $target, 0600 );
        // owner only (some hosts refuse - the deny-all folder still protects it)
        $perms = fileperms( $abs );
        if ( !SFAIS_FS::delete( $abs ) || file_exists( $abs ) ) {
            SFAIS_FS::delete( $target );
            return [
                'success' => false,
                'message' => 'File not writable.',
            ];
        }
        return [
            'success' => true,
            'message' => 'Moved to quarantine.',
            'entry'   => [
                'date'       => ( $date ? (string) $date : current_time( 'mysql' ) ),
                'original'   => $relNorm,
                'quarantine' => str_replace( wp_normalize_path( $base . '/' ), '', $target ),
                'reason'     => (string) $reason,
                'sha256'     => hash( 'sha256', $data ),
                'size'       => (int) $size,
                'perms'      => ( false !== $perms ? substr( sprintf( '%o', $perms ), -4 ) : '' ),
                'format'     => 'mhsfq1',
            ],
        ];
    }

    /**
     * 1.8.15: quarantine files from 1.8.14 and older (plain copies, e.g. *.phq or a *.htaccess.quarantined) are converted to the
     * encoded format once - they keep their log date, original path and reason.
     */
    private function quarantine_migrate_legacy() {
        $base = $this->uploads_base();
        $qdir = wp_normalize_path( $base . '/' . self::QUAR_DIR );
        if ( !is_dir( $qdir ) ) {
            return;
        }
        $logPath = $qdir . '/' . self::QUAR_LOG;
        $log = ( $this->read_json( $logPath ) ?: [] );
        $by_q = [];
        foreach ( $log as $i => $e ) {
            if ( is_array( $e ) && !empty( $e['quarantine'] ) ) {
                $by_q[(string) $e['quarantine']] = $i;
            }
        }
        $changed = false;
        $prefix = rtrim( wp_normalize_path( self::QUAR_DIR ), '/' ) . '/';
        $this->safe_walk( $qdir, function ( $abs ) use(
            $qdir,
            $prefix,
            $base,
            &$log,
            &$by_q,
            &$changed
        ) {
            $abs = wp_normalize_path( (string) $abs );
            if ( !is_file( $abs ) || $this->is_quarantine_system_file( $abs, $qdir ) || substr( $abs, -strlen( self::QUAR_EXT ) ) === self::QUAR_EXT ) {
                return;
            }
            $qrel = $prefix . ltrim( str_replace( $qdir, '', $abs ), '/' );
            $i = $by_q[$qrel] ?? null;
            $e = ( null !== $i ? (array) $log[$i] : [] );
            $orig = ( !empty( $e['original'] ) ? (string) $e['original'] : $this->infer_original_from_quarantine_rel( $qrel ) );
            if ( '' === $orig ) {
                return;
            }
            $r = $this->quarantine_store(
                $abs,
                $orig,
                (string) ($e['reason'] ?? 'Quarantined before 1.8.15'),
                $e['date'] ?? null
            );
            if ( empty( $r['success'] ) ) {
                return;
            }
            if ( null !== $i ) {
                $log[$i] = $r['entry'];
            } else {
                $log[] = $r['entry'];
            }
            $changed = true;
        } );
        if ( $changed ) {
            $this->write_json( $logPath, array_values( $log ) );
        }
    }

    private function quarantine_name( $target ) {
        $target = (string) preg_replace( '/\\.php[0-9]*$/i', '.phq', (string) $target );
        $base = strtolower( basename( $target ) );
        if ( in_array( $base, ['.htaccess', '.user.ini', 'php.ini'], true ) ) {
            $target .= '.quarantined';
        }
        return $target;
    }

    /**
     * 1.8.13: the quarantine log and protection files in the quarantine root (never listed, restored or deleted).
     *
     * @param string $abs  Absolute path.
     * @param string $qdir Absolute quarantine folder.
     * @return bool
     */
    private function is_quarantine_system_file( $abs, $qdir ) {
        $abs = rtrim( wp_normalize_path( (string) $abs ), '/' );
        $qdir = rtrim( wp_normalize_path( (string) $qdir ), '/' );
        if ( $abs === $qdir ) {
            return true;
        }
        if ( wp_normalize_path( dirname( $abs ) ) !== $qdir ) {
            return false;
        }
        return in_array( strtolower( basename( $abs ) ), [
            strtolower( self::QUAR_LOG ),
            '.htaccess',
            'index.php',
            'index.html'
        ], true );
    }

    public function quarantine_move( $relPath, $reason = 'Suspicious' ) {
        $relNorm = $this->normalize_rel_path( $relPath );
        if ( $relNorm === false ) {
            return [
                'success' => false,
                'message' => 'Invalid file path.',
            ];
        }
        // Enforce: only files in last reports can be quarantined.
        if ( !$this->is_actionable_from_last_reports( $relNorm ) ) {
            return [
                'success' => false,
                'message' => 'Action not permitted for this file. Please run a scan and try again.',
            ];
        }
        $abs = $this->resolve_abs_from_rel( $relNorm, true );
        if ( $abs === false || !is_file( $abs ) ) {
            return [
                'success' => false,
                'message' => 'File does not exist.',
            ];
        }
        if ( !SFAIS_FS::is_writable( $abs ) ) {
            return [
                'success' => false,
                'message' => 'File not writable.',
            ];
        }
        // 1.8.15 option A (Vlad): stored encoded under a random name, 0600, with hash / size / permissions in the log.
        $r = $this->quarantine_store( $abs, $relNorm, $reason );
        if ( empty( $r['success'] ) ) {
            return [
                'success' => false,
                'message' => (string) $r['message'],
            ];
        }
        $logPath = $this->uploads_base() . '/' . self::QUAR_DIR . '/' . self::QUAR_LOG;
        $log = ( $this->read_json( $logPath ) ?: [] );
        $log[] = $r['entry'];
        $this->write_json( $logPath, $log );
        // 1.8.13: remove the file's rows from all stored reports and correct their `summary` (was: top-level keys, content only).
        $this->forget_in_reports( [$relNorm], 'quarantine' );
        return [
            'success' => true,
            'message' => 'Moved to quarantine.',
        ];
    }

    public function delete_permanently( $relPath ) {
        $relNorm = $this->normalize_rel_path( $relPath );
        if ( $relNorm === false ) {
            return [
                'success' => false,
                'message' => 'Invalid file path.',
            ];
        }
        // Enforce: only files in last reports can be deleted.
        if ( !$this->is_actionable_from_last_reports( $relNorm ) ) {
            return [
                'success' => false,
                'message' => 'Action not permitted for this file. Please run a scan and try again.',
            ];
        }
        $abs = $this->resolve_abs_from_rel( $relNorm, true );
        if ( $abs === false || !file_exists( $abs ) || !is_file( $abs ) ) {
            return [
                'success' => false,
                'message' => 'Cannot delete: file missing.',
            ];
        }
        if ( !SFAIS_FS::is_writable( $abs ) ) {
            return [
                'success' => false,
                'message' => 'Cannot delete: file not writable.',
            ];
        }
        if ( !SFAIS_FS::delete( $abs ) ) {
            return [
                'success' => false,
                'message' => 'Delete failed.',
            ];
        }
        // 1.8.13: keep the stored reports in step (the row must not come back on reload).
        $this->forget_in_reports( [$relNorm], 'delete' );
        return [
            'success' => true,
            'message' => 'File deleted permanently.',
        ];
    }

    public function ignore_file( $relPath ) {
        $res = $this->ignore_files( [$relPath] );
        if ( !empty( $res['ignored'] ) ) {
            return [
                'success' => true,
                'message' => 'File will be ignored in future scans while it stays unchanged.',
            ];
        }
        $msg = ( !empty( $res['failed'][0]['message'] ) ? (string) $res['failed'][0]['message'] : 'Failed' );
        return [
            'success' => false,
            'message' => $msg,
        ];
    }

    /**
     * Ignore several files at once (1.8.13: one option write + one report update for bulk ignore).
     * Each entry stores the file's MD5 ('missing' for a missing file), so a file that changes later is scanned again.
     *
     * @param array $rels ABSPATH-relative paths.
     * @return array { ignored: string[], failed: array[] }
     */
    public function ignore_files( array $rels ) {
        $ign = get_option( self::IGNORES_OPT, [] );
        if ( !is_array( $ign ) ) {
            $ign = [];
        }
        $done = [];
        $failed = [];
        foreach ( $rels as $relPath ) {
            $relNorm = $this->normalize_rel_path( $relPath );
            if ( $relNorm === false ) {
                $failed[] = [
                    'file'    => (string) $relPath,
                    'message' => 'Invalid file path.',
                ];
                continue;
            }
            // Enforce: only files in last reports can be ignored.
            if ( !$this->is_actionable_from_last_reports( $relNorm ) ) {
                $failed[] = [
                    'file'    => $relNorm,
                    'message' => 'Action not permitted for this file. Please run a scan and try again.',
                ];
                continue;
            }
            $abs = $this->resolve_abs_from_rel( $relNorm, true );
            $sig = null;
            if ( $abs === false || !file_exists( $abs ) ) {
                $sig = 'missing';
            } else {
                $h = $this->file_md5( $abs );
                $sig = ( '' !== $h ? $h : null );
            }
            // Re-add at the end (newest last), so the cap below drops the oldest entries.
            unset($ign[$relNorm]);
            foreach ( $ign as $k => $v ) {
                if ( is_string( $v ) && $v === $relNorm ) {
                    unset($ign[$k]);
                }
            }
            if ( $sig !== null ) {
                $ign[$relNorm] = [
                    'sig'  => $sig,
                    'time' => current_time( 'mysql' ),
                ];
            } else {
                $ign[] = $relNorm;
                // unreadable: no fingerprint possible
            }
            $done[] = $relNorm;
        }
        if ( $done ) {
            if ( count( $ign ) > self::IGNORES_MAX ) {
                $ign = array_slice(
                    $ign,
                    -self::IGNORES_MAX,
                    null,
                    true
                );
            }
            update_option( self::IGNORES_OPT, $ign, false );
            $this->forget_in_reports( $done, 'ignore' );
        }
        return [
            'ignored' => $done,
            'failed'  => $failed,
        ];
    }

    /**
     * 1.8.13: the ignore list for the Scanner tab (newest first). Entries whose file no longer exists are dropped (and the
     * list is saved) - except "missing" ignores of a file that is still missing (that is what they are for).
     *
     * @return array { success: true, items: [ {file, time, missing} ] }
     */
    public function list_ignored() {
        $ign = get_option( self::IGNORES_OPT, [] );
        if ( !is_array( $ign ) ) {
            $ign = [];
        }
        $keep = [];
        $items = [];
        $changed = false;
        foreach ( $ign as $k => $v ) {
            if ( is_array( $v ) && array_key_exists( 'sig', $v ) ) {
                $rel = (string) $k;
                $sig = strtolower( (string) $v['sig'] );
                $time = ( isset( $v['time'] ) ? (string) $v['time'] : '' );
            } elseif ( is_string( $v ) && '' !== $v ) {
                $rel = $v;
                $sig = '';
                $time = '';
            } else {
                $changed = true;
                continue;
            }
            $relNorm = $this->normalize_rel_path( $rel );
            if ( false === $relNorm ) {
                $changed = true;
                continue;
            }
            $exists = file_exists( wp_normalize_path( ABSPATH . $relNorm ) );
            if ( ( 'missing' === $sig ? $exists : !$exists ) ) {
                // file gone (or a "missing" file is back): the ignore no longer applies
                $changed = true;
                continue;
            }
            $keep[$k] = $v;
            $items[] = [
                'file'    => $relNorm,
                'time'    => $time,
                'missing' => 'missing' === $sig,
            ];
        }
        if ( $changed ) {
            update_option( self::IGNORES_OPT, $keep, false );
        }
        return [
            'success' => true,
            'items'   => array_reverse( $items ),
        ];
    }

    /**
     * 1.8.13: remove one file from the ignore list (Un-ignore button).
     *
     * @param string $relPath ABSPATH-relative path.
     * @return array
     */
    public function unignore_file( $relPath ) {
        $relNorm = $this->normalize_rel_path( $relPath );
        if ( false === $relNorm ) {
            return [
                'success' => false,
                'message' => 'Invalid file path.',
            ];
        }
        $ign = get_option( self::IGNORES_OPT, [] );
        if ( !is_array( $ign ) ) {
            $ign = [];
        }
        $found = false;
        if ( isset( $ign[$relNorm] ) ) {
            unset($ign[$relNorm]);
            $found = true;
        }
        foreach ( $ign as $k => $v ) {
            if ( is_string( $v ) && $v === $relNorm ) {
                unset($ign[$k]);
                $found = true;
            }
        }
        if ( !$found ) {
            return [
                'success' => false,
                'message' => 'This file is not on the ignore list.',
            ];
        }
        update_option( self::IGNORES_OPT, $ign, false );
        return [
            'success' => true,
            'message' => 'Removed from the ignore list. The next scan checks this file again.',
        ];
    }

    /* ---------- Quarantine Management ---------- */
    public function list_quarantine() {
        $this->quarantine_migrate_legacy();
        // 1.8.15: older plain copies -> encoded format (once)
        $base = $this->uploads_base();
        $qdir = $base . '/' . self::QUAR_DIR;
        $this->ensure_dir( $qdir );
        $logPath = $qdir . '/' . self::QUAR_LOG;
        $entries = $this->read_json( $logPath );
        if ( !is_array( $entries ) ) {
            $entries = [];
        }
        // Index log entries by quarantine rel path.
        $by_quarantine = [];
        foreach ( $entries as $e ) {
            if ( is_array( $e ) && !empty( $e['quarantine'] ) ) {
                $by_quarantine[(string) $e['quarantine']] = $e;
            }
        }
        $items = [];
        $seen = [];
        $qdir_norm = wp_normalize_path( $qdir );
        $prefix = rtrim( wp_normalize_path( self::QUAR_DIR ), '/' ) . '/';
        // Always discover quarantined files from disk (source of truth).
        // This avoids relying on log correctness and prevents "empty quarantine" UI.
        $this->safe_walk( $qdir_norm, function ( $abs ) use(
            $qdir_norm,
            $prefix,
            $by_quarantine,
            &$items,
            &$seen
        ) {
            $abs = wp_normalize_path( (string) $abs );
            if ( $abs === '' || !is_file( $abs ) ) {
                return;
            }
            // 1.8.13: every quarantined file is listed (also .js, .htaccess.quarantined, ...), only the log and the
            // folder's protection files are skipped (was: *.phq only, so other files could never be restored or deleted).
            if ( $this->is_quarantine_system_file( $abs, $qdir_norm ) ) {
                return;
            }
            $rel_under = ltrim( str_replace( $qdir_norm, '', $abs ), '/' );
            if ( $rel_under === '' ) {
                return;
            }
            $qrel = $prefix . $rel_under;
            if ( isset( $seen[$qrel] ) ) {
                return;
            }
            $e = ( isset( $by_quarantine[$qrel] ) && is_array( $by_quarantine[$qrel] ) ? $by_quarantine[$qrel] : [] );
            $orig = ( isset( $e['original'] ) ? (string) $e['original'] : '' );
            $reason = ( isset( $e['reason'] ) ? (string) $e['reason'] : '' );
            $date = ( isset( $e['date'] ) ? (string) $e['date'] : '' );
            if ( $orig === '' ) {
                $orig = $this->infer_original_from_quarantine_rel( $qrel );
            }
            if ( $date === '' ) {
                $ts = @filemtime( $abs );
                $date = ( $ts ? $this->format_ts( $ts ) : '' );
            }
            $items[] = [
                'date'       => $date,
                'original'   => $orig,
                'quarantine' => $qrel,
                'reason'     => $reason,
            ];
            $seen[$qrel] = true;
        } );
        // Newest first (best-effort from date string)
        usort( $items, function ( $a, $b ) {
            $ta = ( isset( $a['date'] ) ? strtotime( (string) $a['date'] ) : 0 );
            $tb = ( isset( $b['date'] ) ? strtotime( (string) $b['date'] ) : 0 );
            if ( $ta === $tb ) {
                return strcmp( (string) ($a['original'] ?? ''), (string) ($b['original'] ?? '') );
                // 1.8.15: stable order
            }
            return ( $ta > $tb ? -1 : 1 );
        } );
        return [
            'success' => true,
            'items'   => $items,
        ];
    }

    /**
     * Infer an original relative path from a quarantine rel path.
     * This supports manual moves or cases where the quarantine log was not written.
     */
    private function infer_original_from_quarantine_rel( $quarantineRel ) {
        if ( !is_string( $quarantineRel ) || $quarantineRel === '' ) {
            return '';
        }
        $qrel = ltrim( wp_normalize_path( $quarantineRel ), '/' );
        $prefix = rtrim( wp_normalize_path( self::QUAR_DIR ), '/' ) . '/';
        if ( strpos( $qrel, $prefix ) !== 0 ) {
            return '';
        }
        $under = substr( $qrel, strlen( $prefix ) );
        if ( $under === false ) {
            return '';
        }
        // 1.8.13: ".htaccess.quarantined" -> ".htaccess" (same for .user.ini / php.ini)
        $under = (string) preg_replace( '/\\.quarantined$/i', '', $under );
        // Reverse .phq back to .php (best-effort)
        $orig = preg_replace( '/\\.phq$/i', '.php', $under );
        return ( is_string( $orig ) ? $orig : $under );
    }

    public function restore_from_quarantine( $quarantineRel ) {
        $qAbs = $this->resolve_quarantine_abs( $quarantineRel );
        if ( $qAbs === false || !is_file( $qAbs ) ) {
            return [
                'success' => false,
                'message' => 'File not found in quarantine.',
            ];
        }
        $base = $this->uploads_base();
        $logPath = $base . '/' . self::QUAR_DIR . '/' . self::QUAR_LOG;
        $log = ( $this->read_json( $logPath ) ?: [] );
        $entry = null;
        foreach ( $log as $e ) {
            if ( isset( $e['quarantine'] ) && $e['quarantine'] === $quarantineRel ) {
                $entry = $e;
                break;
            }
        }
        if ( !$entry || empty( $entry['original'] ) ) {
            // Allow restore even if the quarantine log is missing/corrupted by inferring the original path.
            $inferred = $this->infer_original_from_quarantine_rel( $quarantineRel );
            if ( empty( $inferred ) ) {
                return [
                    'success' => false,
                    'message' => 'Log entry not found.',
                ];
            }
            $entry = [
                'original'   => $inferred,
                'quarantine' => $quarantineRel,
            ];
        }
        $origRel = $this->normalize_rel_path( $entry['original'] );
        if ( $origRel === false ) {
            return [
                'success' => false,
                'message' => 'Invalid original path in quarantine log.',
            ];
        }
        // Restore to the exact original destination
        $dest = $this->resolve_abs_from_rel( $origRel, false );
        if ( $dest === false ) {
            return [
                'success' => false,
                'message' => 'Restore destination is not permitted.',
            ];
        }
        // 1.8.15: the encoded copy is decoded and checked against the hash taken when it was quarantined
        $plain = self::quarantine_decode( (string) SFAIS_FS::read( $qAbs ) );
        if ( false !== $plain && !empty( $entry['sha256'] ) && hash( 'sha256', $plain ) !== $entry['sha256'] ) {
            return [
                'success' => false,
                'message' => 'Not restored: the quarantined copy does not match the original any more.',
            ];
        }
        // 1.8.13: never overwrite a file that exists there now (e.g. a newer version) - unless it is identical.
        if ( file_exists( $dest ) ) {
            $now_md5 = $this->file_md5( $dest );
            $quar_md5 = ( false !== $plain ? md5( $plain ) : $this->file_md5( $qAbs ) );
            if ( !is_file( $dest ) || '' === $now_md5 || $now_md5 !== $quar_md5 ) {
                return [
                    'success' => false,
                    'message' => sprintf( 'Not restored: a different file now exists at %s. Move or rename that file first, then try again.', $origRel ),
                ];
            }
        }
        $this->ensure_dir( dirname( $dest ) );
        if ( false !== $plain ) {
            if ( !SFAIS_FS::write( $dest, $plain ) ) {
                return [
                    'success' => false,
                    'message' => 'Restore failed.',
                ];
            }
            if ( !empty( $entry['perms'] ) && preg_match( '/^[0-7]{3,4}$/', (string) $entry['perms'] ) ) {
                SFAIS_FS::chmod( $dest, octdec( (string) $entry['perms'] ) );
            }
            SFAIS_FS::delete( $qAbs );
        } elseif ( !SFAIS_FS::move( $qAbs, $dest ) ) {
            return [
                'success' => false,
                'message' => 'Restore failed.',
            ];
        }
        // Remove entry from log
        $log = array_filter( $log, function ( $e ) use($quarantineRel) {
            return isset( $e['quarantine'] ) && $e['quarantine'] !== $quarantineRel;
        } );
        $this->write_json( $logPath, array_values( $log ) );
        return [
            'success'  => true,
            'message'  => 'File restored successfully.',
            'original' => $origRel,
        ];
    }

    public function delete_from_quarantine( $quarantineRel ) {
        $qAbs = $this->resolve_quarantine_abs( $quarantineRel );
        // 1.8.13: report what really happened (was always "deleted", even when nothing was deleted).
        if ( $qAbs === false || !is_file( $qAbs ) ) {
            return [
                'success' => false,
                'message' => 'File not found in quarantine.',
            ];
        }
        $deleted = SFAIS_FS::delete( $qAbs );
        clearstatcache( true, $qAbs );
        if ( !$deleted || file_exists( $qAbs ) ) {
            return [
                'success' => false,
                'message' => 'The file could not be deleted from quarantine. Please check the folder permissions.',
            ];
        }
        $base = $this->uploads_base();
        $logPath = $base . '/' . self::QUAR_DIR . '/' . self::QUAR_LOG;
        $log = ( $this->read_json( $logPath ) ?: [] );
        $original = '';
        foreach ( $log as $e ) {
            if ( isset( $e['quarantine'], $e['original'] ) && $e['quarantine'] === $quarantineRel ) {
                $original = (string) $e['original'];
            }
        }
        $log = array_filter( $log, function ( $e ) use($quarantineRel) {
            return isset( $e['quarantine'] ) && $e['quarantine'] !== $quarantineRel;
        } );
        $this->write_json( $logPath, array_values( $log ) );
        return [
            'success'  => true,
            'message'  => 'File permanently deleted from quarantine.',
            'original' => $original,
        ];
    }

}
