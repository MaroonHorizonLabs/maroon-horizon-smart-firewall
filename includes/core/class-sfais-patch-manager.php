<?php
if (!defined('ABSPATH')) exit;

class SFAIS_Patch_Manager {

    public function bootstrap_patches() {
        // Runtime effects for active patches
        if (get_option('sfais_patch_versioninfo')) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string', 9999); // page + feed generator lines
            // 1.8.13: also the WordPress version in script/style links (?ver=6.x -> short site-specific hash, cache-busting kept)
            add_filter('script_loader_src', [$this, 'mask_wp_version_in_src'], 9999);
            add_filter('style_loader_src', [$this, 'mask_wp_version_in_src'], 9999);
        }

        // Directory listing patch: index-files-only (no .htaccess, no runtime hook)

        if (get_option('sfais_patch_xmlrpc')) {
            add_filter('xmlrpc_enabled', '__return_false', 9999);
            // 1.8.13: really off - the filter above only stopped logins; pingback.ping and system.listMethods still answered.
            add_filter('xmlrpc_methods', '__return_empty_array', 9999);
            add_filter('wp_headers', [$this, 'remove_pingback_header'], 9999);
            add_action('wp', [$this, 'remove_pingback_header_sent'], 9999);
            remove_action('wp_head', 'rsd_link');
            if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
                $this->block_xmlrpc_request();
            }
        }
    }

    /**
     * 1.8.13: xmlrpc.php answers 403 (runs at init, before the XML-RPC server starts).
     */
    private function block_xmlrpc_request() {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo esc_html('403 Forbidden - XML-RPC is disabled on this site.');
        exit;
    }

    /** 1.8.13: no X-Pingback header while XML-RPC is off. */
    public function remove_pingback_header($headers) {
        if (is_array($headers)) {
            unset($headers['X-Pingback']);
        }
        return $headers;
    }

    public function remove_pingback_header_sent() {
        if (function_exists('header_remove') && !headers_sent()) {
            header_remove('X-Pingback');
        }
    }

    /**
     * 1.8.13: ?ver=<WordPress version> on scripts/styles becomes a short hash of the version + the site's salt.
     * Only a ver value that equals the WordPress version is touched; it still changes after every update (cache-busting).
     */
    public function mask_wp_version_in_src($src) {
        $wp_ver = (string) get_bloginfo('version');
        if (!is_string($src) || $src === '' || $wp_ver === '' || strpos($src, 'ver=' . $wp_ver) === false) {
            return $src;
        }
        $hash = substr(wp_hash('mhsf-ver-' . $wp_ver), 0, 8);
        $new  = preg_replace('/([?&](?:amp;)?)ver=' . preg_quote($wp_ver, '/') . '(?=&|#|$)/', '${1}ver=' . $hash, $src);
        return is_string($new) ? $new : $src;
    }

    public function toggle($patch, $action_type) {
        return ($action_type === 'apply')
            ? $this->apply_patch($patch)
            : $this->revert_patch($patch);
    }

    /* ----------------------------------------------------------------
     * APPLY PATCH
     * ---------------------------------------------------------------- */
    public function apply_patch($patch) {
        switch ($patch) {
            /* ------------------ HIDE WORDPRESS VERSION INFO ------------------ */
            case 'versioninfo':
                remove_action('wp_head', 'wp_generator');
                add_filter('the_generator', '__return_empty_string', 9999);
                update_option('sfais_patch_versioninfo', 1);
                return ['status'=>true,'message'=>'✅ WordPress version info hidden successfully.'];

            /* ------------------ PREVENT DIRECTORY LISTING -------------------- */
            case 'dirlisting':
                $result = $this->apply_dirlisting_index_protection();

                // Save full structured report for UI (per-directory)
                update_option('sfais_patch_dirlisting_last_report', $result);

                if (!empty($result['status'])) {
                    update_option('sfais_patch_dirlisting', 1);
                } else {
                    // Do NOT mark as active if nothing was protected/added.
                    delete_option('sfais_patch_dirlisting');
                }

                return [
                    'status'  => !empty($result['status']),
                    'message' => $this->format_dirlisting_apply_message($result),
                ];

            /* ------------------ DISABLE XML-RPC ------------------------------ */
            case 'xmlrpc':
                add_filter('xmlrpc_enabled', '__return_false', 9999);
                update_option('sfais_patch_xmlrpc', 1);
                return ['status'=>true,'message'=>'✅ XML-RPC has been disabled: xmlrpc.php now answers 403 Forbidden.'];

            /* ------------------ FIX FILE PERMISSIONS (SAFE / NON-RECURSIVE) -- */
            case 'permissions':
                $report = $this->fix_permissions();

                // Store last run report for UI (even if we won't render it, it can be useful later)
                update_option('sfais_patch_permissions_last_report', $report);

                $changed = intval($report['changed'] ?? 0);
                $failed  = intval($report['failed'] ?? 0);
                $skipped = intval($report['skipped'] ?? 0);

                // ✅ Treat "already hardened" as success:
                // If nothing failed and either we changed perms OR confirmed they were already correct.
                // 1.8.13: 'skipped' = already hardened only; a missing file or wp-config.php one folder up is not success.
                $is_hardened = ($failed === 0 && ($changed > 0 || $skipped > 0));

                if ($is_hardened) {
                    update_option('sfais_patch_permissions', 1);
                } else {
                    delete_option('sfais_patch_permissions');
                }

                return [
                    'status'  => $is_hardened,
                    'message' => $this->format_permissions_apply_message($report),
                ];

            /* ------------------ PROTECT UPLOADS FOLDER + DISABLE FILE MODS ---- */
            case 'filemods':
                $res = $this->apply_protect_uploads();
                $optional = ' Optional hardening: set <code>DISALLOW_FILE_MODS</code> in <code>wp-config.php</code> to disable WordPress file modifications (core/plugin/theme updates).';

                if ($res === 'ok' || $res === 'unverified') {
                    update_option('sfais_patch_filemods', 1);
                    return [
                        'status'  => true,
                        'message' => ($res === 'ok'
                            ? '✅ Uploads folder protected (.htaccess rules added safely; tested: files in uploads still load).'
                            : '✅ Uploads folder protected (.htaccess rules added). The automatic test could not reach your site - please open one image from your Media Library once to check it still loads.')
                            . $optional,
                    ];
                }

                // Do NOT mark as active if protection could not be applied.
                // 1.8.13: ...unless our (older) rule is still in the file after a failed update - the switch says what is there.
                if ($this->uploads_block_present() && $res !== 'nginx') {
                    update_option('sfais_patch_filemods', 1);
                } else {
                    delete_option('sfais_patch_filemods');
                }

                if ($res === 'nginx') {
                    // 1.8.13: Nginx ignores .htaccess - say so instead of a false "protected".
                    return [
                        'status'  => false,
                        'message' => '⚠️ This server (Nginx) ignores <code>.htaccess</code> files, so a rule there would not protect your uploads folder. Nothing was changed. Ask your host to add this line to the Nginx configuration: <code>' . esc_html($this->uploads_nginx_rule()) . '</code>',
                    ];
                }

                if ($res === 'restored') {
                    return [
                        'status'  => false,
                        'message' => '⚠️ Your server answered with an error after the new ' . $this->uploads_htaccess_hint() . ' was written, so the previous file was put back at once. No changes were applied.',
                    ];
                }

                return [
                    'status'  => false,
                    'message' => '⚠️ Failed to protect uploads folder (cannot write ' . $this->uploads_htaccess_hint() . '). No changes were applied.'
                ];

            default:
                return ['status'=>false,'message'=>'Unknown patch request.'];
        }
    }

    /* ----------------------------------------------------------------
     * REVERT PATCH
     * ---------------------------------------------------------------- */
    public function revert_patch($patch) {
        switch ($patch) {
            /* ------------------ HIDE WORDPRESS VERSION INFO ------------------ */
            case 'versioninfo':
                remove_filter('the_generator', '__return_empty_string', 9999);
                remove_filter('script_loader_src', [$this, 'mask_wp_version_in_src'], 9999);
                remove_filter('style_loader_src', [$this, 'mask_wp_version_in_src'], 9999);
                delete_option('sfais_patch_versioninfo');
                return ['status'=>true,'message'=>'🔄 WordPress version info restored.'];

            /* ------------------ PREVENT DIRECTORY LISTING -------------------- */
            case 'dirlisting':
                $result = $this->revert_dirlisting_index_protection();

                // Always clear stored report + flag so UI doesn't show old details
                delete_option('sfais_patch_dirlisting');
                delete_option('sfais_patch_dirlisting_last_report');

                // IMPORTANT: Do NOT output per-directory lines on revert.
                $cannot = 0;
                $err    = 0;
                if (is_array($result) && !empty($result['counts']) && is_array($result['counts'])) {
                    $cannot = intval($result['counts']['cannot_write'] ?? 0);
                    $err    = intval($result['counts']['error'] ?? 0);
                }

                if (($cannot + $err) > 0) {
                    return [
                        'status'  => true,
                        'message' => '⚠️ Reverted, but some plugin-created index.html files could not be removed due to permissions.',
                    ];
                }

                return [
                    'status'  => true,
                    'message' => '🔄 Directory browsing protection reverted.',
                ];

            /* ------------------ DISABLE XML-RPC ------------------------------ */
            case 'xmlrpc':
                remove_filter('xmlrpc_enabled', '__return_false', 9999);
                remove_filter('xmlrpc_methods', '__return_empty_array', 9999);
                delete_option('sfais_patch_xmlrpc');
                return ['status'=>true,'message'=>'🔄 XML-RPC re-enabled (if not disabled elsewhere).'];

            /* ------------------ FIX FILE PERMISSIONS ------------------------- */
            case 'permissions':
                $result = $this->revert_fix_permissions();

                // Always clear UI report and flag so the UI doesn't mislead.
                // 1.8.13: ...except when saved permissions could not be put back - then the patch is still in effect.
                if (empty($result['keep_active'])) {
                    delete_option('sfais_patch_permissions');
                }
                delete_option('sfais_patch_permissions_last_report');
                unset($result['keep_active']);

                return $result;

            /* ------------------ PROTECT UPLOADS FOLDER + FILE MODS ------------ */
            case 'filemods':
                // 1.8.13: report it when the rule could not be removed (the patch then stays on).
                if (!$this->revert_protect_uploads()) {
                    return [
                        'status'  => false,
                        'message' => '⚠️ Could not remove the rule from ' . $this->uploads_htaccess_hint() . ' (file not writable). The patch stays on - make the file writable and try again.',
                    ];
                }
                delete_option('sfais_patch_filemods');
                return ['status'=>true,'message'=>'🔄 Uploads protection reverted. WordPress file modification settings were not changed.'];

            default:
                return ['status'=>false,'message'=>'Unknown patch request.'];
        }
    }

    /* ----------------------------------------------------------------
     * Prevent Directory Listing (Index Files Only; No .htaccess)
     * ---------------------------------------------------------------- */

    private function apply_dirlisting_index_protection() {
        $dirs = [];

        // Derive content directory without assuming it is named 'wp-content'.
        $content_dir = '';
        if ( defined( 'WP_PLUGIN_DIR' ) ) {
            $content_dir = dirname( WP_PLUGIN_DIR );
        }

        $uploads_basedir = function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '';
        if ( is_wp_error( $uploads_basedir ) ) {
            $uploads_basedir = '';
        }

        $theme_root = function_exists( 'get_theme_root' ) ? (string) get_theme_root() : '';

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

        $marker   = "\n<!-- Added by Maroon Horizon Smart Firewall -->\n";
        $template = "<!doctype html><meta charset=\"utf-8\"><title></title>{$marker}";

        $results = [];
        $counts = [
            'protected'     => 0,
            'added'         => 0,
            'cannot_write'  => 0,
            'missing'       => 0,
            'error'         => 0,
        ];

        foreach ($dirs as $dir) {
            $label = $this->dir_to_public_label($dir);

            if (!is_dir($dir)) {
                $results[] = ['dir'=>$label,'status'=>'missing','detail'=>'Directory not found.'];
                $counts['missing']++;
                continue;
            }

            $base       = rtrim($dir, '/\\');
            $index_php  = $base . '/index.php';
            $index_htm  = $base . '/index.htm';
            $index_html = $base . '/index.html';

            if (file_exists($index_php)) {
                $results[] = ['dir'=>$label,'status'=>'protected','detail'=>'Protected (index.php found).'];
                $counts['protected']++;
                continue;
            }
            if (file_exists($index_htm)) {
                $results[] = ['dir'=>$label,'status'=>'protected','detail'=>'Protected (index.htm found).'];
                $counts['protected']++;
                continue;
            }
            if (file_exists($index_html)) {
                $results[] = ['dir'=>$label,'status'=>'protected','detail'=>'Protected (index.html found).'];
                $counts['protected']++;
                continue;
            }

            if (!SFAIS_FS::is_writable($dir)) {
                $results[] = ['dir'=>$label,'status'=>'cannot_write','detail'=>'Could not write (permission denied).'];
                $counts['cannot_write']++;
                continue;
            }

            $ok = SFAIS_FS::write($index_html, $template);
            if (!$ok) {
                $results[] = ['dir'=>$label,'status'=>'error','detail'=>'Write failed (unknown error).'];
                $counts['error']++;
                continue;
            }

            if (file_exists($index_html)) {
                $results[] = ['dir'=>$label,'status'=>'added','detail'=>'Added index.html.'];
                $counts['added']++;
            } else {
                $results[] = ['dir'=>$label,'status'=>'error','detail'=>'Write attempted but file not found afterwards.'];
                $counts['error']++;
            }
        }

        $success = (($counts['protected'] + $counts['added']) > 0);

        return [
            'status'  => $success,
            'mode'    => 'index_files_only',
            'counts'  => $counts,
            'results' => $results,
        ];
    }

    private function revert_dirlisting_index_protection() {
        $dirs = [];

        // Derive content directory without assuming it is named 'wp-content'.
        $content_dir = '';
        if ( defined( 'WP_PLUGIN_DIR' ) ) {
            $content_dir = dirname( WP_PLUGIN_DIR );
        }

        $uploads_basedir = function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : wp_upload_dir( null, false )['basedir'] ?? '';
        if ( is_wp_error( $uploads_basedir ) ) {
            $uploads_basedir = '';
        }

        $theme_root = function_exists( 'get_theme_root' ) ? (string) get_theme_root() : '';

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

        $marker = 'Added by Maroon Horizon Smart Firewall';

        $results = [];
        $counts = [
            'kept'          => 0,
            'removed'       => 0,
            'cannot_write'  => 0,
            'missing'       => 0,
            'error'         => 0,
        ];

        foreach ($dirs as $dir) {
            $label = $this->dir_to_public_label($dir);

            if (!is_dir($dir)) {
                $results[] = ['dir'=>$label,'status'=>'missing','detail'=>'Directory not found.'];
                $counts['missing']++;
                continue;
            }

            $base       = rtrim($dir, '/\\');
            $index_php  = $base . '/index.php';
            $index_htm  = $base . '/index.htm';
            $index_html = $base . '/index.html';

            if (file_exists($index_php) || file_exists($index_htm)) {
                $results[] = ['dir'=>$label,'status'=>'kept','detail'=>'Kept existing index file (not managed by this patch).'];
                $counts['kept']++;
                continue;
            }

            if (!file_exists($index_html)) {
                $results[] = ['dir'=>$label,'status'=>'kept','detail'=>'No index.html found.'];
                $counts['kept']++;
                continue;
            }

            $content = SFAIS_FS::read($index_html);
            if ($content === false || strpos($content, $marker) === false) {
                $results[] = ['dir'=>$label,'status'=>'kept','detail'=>'Kept index.html (not created by this plugin).'];
                $counts['kept']++;
                continue;
            }

            if (!SFAIS_FS::is_writable($index_html)) {
                $results[] = ['dir'=>$label,'status'=>'cannot_write','detail'=>'Could not remove (permission denied).'];
                $counts['cannot_write']++;
                continue;
            }

            $ok = SFAIS_FS::delete($index_html);
            if ($ok) {
                $results[] = ['dir'=>$label,'status'=>'removed','detail'=>'Removed index.html (created by plugin).'];
                $counts['removed']++;
            } else {
                $results[] = ['dir'=>$label,'status'=>'error','detail'=>'Remove failed (unknown error).'];
                $counts['error']++;
            }
        }

        return [
            'status'  => true,
            'mode'    => 'index_files_only',
            'counts'  => $counts,
            'results' => $results,
        ];
    }

    /**
     * APPLY message ONLY (includes per-directory lines).
     * Revert message is intentionally handled in revert_patch() without details.
     */
    private function format_dirlisting_apply_message($report) {
        if (!is_array($report) || empty($report['results']) || !is_array($report['results'])) {
            return '⚠️ No report available.';
        }

        $lines = [];
        foreach ($report['results'] as $row) {
            $dir    = isset($row['dir']) ? $row['dir'] : '';
            $detail = isset($row['detail']) ? $row['detail'] : '';
            if ($dir === '' || $detail === '') continue;
            $lines[] = esc_html($dir) . ' — ' . esc_html($detail);
        }

        $ok = !empty($report['status']);

        $headline = $ok
            ? '✅ Directory browsing protection applied using index files:'
            : '⚠️ Could not apply directory browsing protection (no directories were protected or writable):';

        $html = $headline;
        if (!empty($lines)) {
            $html .= '<br>' . implode('<br>', $lines);
        }

        return $html;
    }

    private function dir_to_public_label($dir) {
        $dir = rtrim($dir, '/\\') . '/';

        $abs = rtrim(ABSPATH, '/\\') . '/';
        if (strpos($dir, $abs) === 0) {
            $rel = '/' . ltrim(substr($dir, strlen($abs)), '/');
            $rel = '/' . ltrim($rel, '/');
            return $rel;
        }
return $dir;
    }

    /* ----------------------------------------------------------------
     * Protect Uploads Folder (.htaccess) — SAFE (marker-based)
     * ---------------------------------------------------------------- */

    /** 1.8.13: 'apache' (Apache/LiteSpeed), 'nginx' or 'other' - same test as the Dashboard's Server Type check. */
    private function server_type() {
        $server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
        if ( strpos( $server, 'apache' ) !== false || strpos( $server, 'litespeed' ) !== false ) {
            return 'apache';
        }
        return ( strpos( $server, 'nginx' ) !== false ) ? 'nginx' : 'other';
    }

    private function uploads_dir() {
        $dir = function_exists( 'mhsf_get_uploads_basedir' ) ? mhsf_get_uploads_basedir() : ( wp_upload_dir( null, false )['basedir'] ?? '' );
        return ( is_wp_error( $dir ) || ! is_string( $dir ) ) ? '' : rtrim( $dir, '/\\' );
    }

    /** Public path of the uploads folder ("/wp-content/uploads"), '' when unknown. */
    private function uploads_url_path() {
        $uploads_info = wp_upload_dir( null, false );
        if ( is_array( $uploads_info ) && ! empty( $uploads_info['baseurl'] ) ) {
            $u_path = (string) wp_parse_url( (string) $uploads_info['baseurl'], PHP_URL_PATH );
            return rtrim( $u_path, '/' );
        }
        return '';
    }

    private function uploads_htaccess_hint() {
        $u_path = $this->uploads_url_path();
        return ( '' !== $u_path )
            ? '<code>' . esc_html( $u_path . '/.htaccess' ) . '</code>'
            : '<code>.htaccess</code> in the uploads directory';
    }

    /** 1.8.13: the rule for hosts on Nginx (which ignores .htaccess). */
    private function uploads_nginx_rule() {
        $u_path = $this->uploads_url_path();
        $u_path = ( '' !== $u_path ) ? $u_path : '/wp-content/uploads';
        return 'location ~* ^' . $u_path . '/.*\.(php[0-9]?|phtml|pht|phps|phar)$ { deny all; }';
    }

    /** True when our marked block is (still) in uploads/.htaccess. */
    private function uploads_block_present() {
        $dir = $this->uploads_dir();
        if ( '' === $dir || ! file_exists( $dir . '/.htaccess' ) ) {
            return false;
        }
        $contents = SFAIS_FS::read( $dir . '/.htaccess' );
        return is_string( $contents ) && strpos( $contents, '# BEGIN SFAIS Uploads Protection' ) !== false;
    }

    /**
     * @return string 'ok' | 'unverified' | 'restored' | 'failed' (from SFAIS_FS::write_htaccess_checked) or 'nginx'.
     */
    private function apply_protect_uploads() {
        $dir = $this->uploads_dir();
        if ( '' === $dir ) {
            return 'failed';
        }
        // 1.8.13: Nginx ignores .htaccess - nothing is written and the owner gets the Nginx line instead of a false "protected".
        if ( 'nginx' === $this->server_type() ) {
            return 'nginx';
        }
        if ( ! is_dir( $dir ) || ! SFAIS_FS::is_writable( $dir ) ) {
            return 'failed';
        }

        $ht = $dir . '/.htaccess';

        // Ensure we can write if the file exists.
        if (file_exists($ht) && !SFAIS_FS::is_writable($ht)) {
            return 'failed';
        }

        $begin = '# BEGIN SFAIS Uploads Protection';
        $end   = '# END SFAIS Uploads Protection';

        // Block PHP execution + disable indexes (Apache 2.2 + 2.4, LiteSpeed).
        // 1.8.13: no mod_rewrite here - a "RewriteEngine On" in uploads/.htaccess stops Apache using the root rules there,
        // so IPs blocked by the IP Blocker could still download uploads. An old block is replaced (same markers).
        $block = $begin . "\n"
            . "Options -Indexes\n"
            . "<FilesMatch \"\\.(?i:php[0-9]?|phtml|pht|phps|phar)$\">\n"
            . "<IfModule mod_authz_core.c>\n"
            . "  Require all denied\n"
            . "</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n"
            . "  Order allow,deny\n"
            . "  Deny from all\n"
            . "</IfModule>\n"
            . "</FilesMatch>\n"
            . $end . "\n";

        $new = $this->build_marked_block_contents( $ht, $begin, $end, $block );
        if ( false === $new ) {
            return 'failed';
        }

        // 1.8.13: checked write - a small test file in uploads is loaded after writing; on a 5xx answer the previous
        // .htaccess is put back at once (an uploads .htaccess only affects files in uploads, so the root test file is not enough).
        $baseurl = function_exists( 'mhsf_get_uploads_baseurl' ) ? mhsf_get_uploads_baseurl() : ( wp_upload_dir( null, false )['baseurl'] ?? '' );
        $test    = $dir . '/mhsf-check-' . strtolower( wp_generate_password( 10, false ) ) . '.txt';
        if ( is_wp_error( $baseurl ) || '' === (string) $baseurl || ! SFAIS_FS::write( $test, "ok\n" ) ) {
            return 'failed';
        }
        $result = SFAIS_FS::write_htaccess_checked( $ht, $new, trailingslashit( (string) $baseurl ) . basename( $test ) );
        SFAIS_FS::delete( $test );

        return $result;
    }

    /** 1.8.13: the patch is on but uploads/.htaccess still has the old mod_rewrite block (switching off and on updates it). */
    public function uploads_rules_outdated() {
        if ( ! get_option( 'sfais_patch_filemods' ) || ! $this->uploads_block_present() ) {
            return false;
        }
        $contents = (string) SFAIS_FS::read( $this->uploads_dir() . '/.htaccess' );
        $start    = strpos( $contents, '# BEGIN SFAIS Uploads Protection' );
        $stop     = strpos( $contents, '# END SFAIS Uploads Protection' );
        $block    = ( false !== $start && false !== $stop ) ? substr( $contents, $start, $stop - $start ) : '';
        return false !== stripos( $block, 'RewriteEngine' );
    }

    /** @return bool false when our rule is still in uploads/.htaccess (1.8.13: reported, not hidden). */
    private function revert_protect_uploads() {
        $dir = $this->uploads_dir();
        if ( '' === $dir ) {
            return false;
        }
        $ht  = $dir . '/.htaccess';

        if ( ! file_exists( $ht ) ) {
            return true;
        }

        $begin = '# BEGIN SFAIS Uploads Protection';
        $end   = '# END SFAIS Uploads Protection';

        $contents = SFAIS_FS::read( $ht );
        if ( ! is_string( $contents ) ) {
            return false;
        }
        if ( strpos( $contents, $begin ) === false ) {
            return true;
        }
        if ( ! SFAIS_FS::is_writable( $ht ) ) {
            return false;
        }

        return $this->remove_marked_block($ht, $begin, $end);
    }

    /** 1.8.13: new file contents with our block added or replaced (written by the caller), false when unreadable. */
    private function build_marked_block_contents($filepath, $begin_marker, $end_marker, $block) {
        $contents = '';
        if (file_exists($filepath)) {
            $contents = SFAIS_FS::read($filepath);
            if ($contents === false) {
                return false;
            }
        }

        // Normalize line endings
        $contents = str_replace(array("\r\n", "\r"), "\n", (string) $contents);

        $pattern = '/^' . preg_quote($begin_marker, '/') . '.*?^' . preg_quote($end_marker, '/') . '\s*$/ms';

        if (preg_match($pattern, $contents)) {
            $new = preg_replace($pattern, rtrim($block), $contents, 1);
        } else {
            $new = rtrim($contents);
            if ($new !== '') {
                $new .= "\n\n";
            }
            $new .= rtrim($block) . "\n";
        }

        return is_string( $new ) ? $new : false;
    }

    private function remove_marked_block($filepath, $begin_marker, $end_marker) {
        $contents = SFAIS_FS::read($filepath);
        if ($contents === false) {
            return false;
        }

        $contents = str_replace(array("\r\n", "\r"), "\n", (string) $contents);

        $pattern = '/^' . preg_quote($begin_marker, '/') . '.*?^' . preg_quote($end_marker, '/') . '\s*$/ms';
        $new     = preg_replace($pattern, '', $contents, 1);
        $new     = trim((string) $new);

        if ($new === '') {
            // Only remove the file if it is now empty (meaning we only had our block).
            return SFAIS_FS::delete($filepath); // 1.8.13: a failed delete is reported
        }

        return SFAIS_FS::write($filepath, $new . "\n");
    }

    /* ----------------------------------------------------------------
     * Fix File Permissions (SAFE: only wp-config.php & root .htaccess)
     * ---------------------------------------------------------------- */

    private function permissions_log_file() {
        $logs_dir = function_exists( 'mhsf_get_data_dir' ) ? mhsf_get_data_dir( 'logs' ) : '';
        if ( is_wp_error( $logs_dir ) || '' === $logs_dir ) {
            return '';
        }
        if ( ! is_dir( $logs_dir ) ) {
            SFAIS_FS::mkdir_p( $logs_dir, 0755 );
        }
        return trailingslashit( $logs_dir ) . 'sfais-permissions-log.json';
    }

    /** 1.8.13: WordPress also loads wp-config.php from the folder above (when that folder is not another WordPress). */
    private function wpconfig_is_one_folder_up() {
        $up = dirname( ABSPATH );
        return ! file_exists( ABSPATH . 'wp-config.php' )
            && file_exists( $up . '/wp-config.php' )
            && ! file_exists( $up . '/wp-settings.php' );
    }

    private function fix_permissions() {
        $log_file = $this->permissions_log_file();
        if ( '' === $log_file ) {
            return [
                'status'  => false,
                'changed' => 0,
                'skipped' => 0,
                'failed'  => 1,
                'results' => [],
                'errors'  => [ 'uploads_dir_unavailable' ],
            ];
        }

        // 1.8.13: merge with the earlier log - the FIRST original mode of a file is kept (a second apply used to overwrite it).
        $log = [];
        if ( file_exists( $log_file ) ) {
            $prev = json_decode( (string) SFAIS_FS::read( $log_file ), true );
            if ( is_array( $prev ) ) {
                $log = $prev;
            }
        }

        $targets = [
            [
                'key'     => 'wp-config.php',
                'path'    => ABSPATH . 'wp-config.php',
                'desired' => 0440,
            ],
            [
                'key'     => '.htaccess',
                'path'    => ABSPATH . '.htaccess',
                'desired' => 0444,
            ],
        ];

        $results = [];
        $changed = 0;
        $skipped = 0; // already hardened
        $missing = 0;
        $outside = 0;
        $failed  = 0;

        foreach ($targets as $t) {
            $path = $t['path'];
            $key  = $t['key'];
            $want = $t['desired'];

            // 1.8.13: wp-config.php one folder above WordPress is said, not counted as "skipped" (= success).
            if ( 'wp-config.php' === $key && $this->wpconfig_is_one_folder_up() ) {
                $results[] = [
                    'file'   => $key,
                    'status' => 'outside',
                    'detail' => 'Not changed (wp-config.php is one folder above WordPress).',
                ];
                $outside++;
                continue;
            }

            if (!file_exists($path)) {
                $results[] = [
                    'file'   => $key,
                    'status' => 'missing',
                    'detail' => 'Skipped (file not present on this server).',
                ];
                $missing++;
                continue;
            }

            if (!is_readable($path)) {
                $results[] = [
                    'file'   => $key,
                    'status' => 'failed',
                    'detail' => 'Failed (file is not readable by PHP).',
                ];
                $failed++;
                continue;
            }

            $oldPerms = $this->get_perm_string($path);
            if ($oldPerms === '') {
                $results[] = [
                    'file'   => $key,
                    'status' => 'failed',
                    'detail' => 'Failed (could not read current permissions).',
                ];
                $failed++;
                continue;
            }

            // 1.8.13: never loosen - only permission bits are removed (0644 -> 0440, 0600 -> 0400); a stricter mode stays.
            $old     = intval( $oldPerms, 8 ) & 0777;
            $target  = $old & $want;
            $wantStr = sprintf('%04o', $target);

            // Already at (or stricter than) the desired perms
            if ($target === $old) {
                $results[] = [
                    'file'   => $key,
                    'status' => 'skipped',
                    'detail' => 'No change needed (already ' . $oldPerms . ').',
                ];
                $skipped++;
                continue;
            }

            // 1.8.13: the original mode is saved BEFORE the change, so a revert is always possible.
            $logged_now = false;
            if ( ! isset( $log[ $path ] ) ) {
                $log[ $path ] = $oldPerms;
                if ( ! SFAIS_FS::write( $log_file, wp_json_encode( $log, JSON_PRETTY_PRINT ) ) ) {
                    unset( $log[ $path ] );
                    $results[] = [
                        'file'   => $key,
                        'status' => 'failed',
                        'detail' => 'Not changed (the revert log could not be saved).',
                    ];
                    $failed++;
                    continue;
                }
                $logged_now = true;
            }

            // Attempt chmod (do NOT require SFAIS_FS::is_writable(); chmod is not the same as write)
            $ok = SFAIS_FS::chmod($path, $target);
            clearstatcache( true, $path );

            // 1.8.13: PHP must still read the file (the site would stop) - otherwise the old mode goes back at once.
            if ( $ok && ! is_readable( $path ) ) {
                SFAIS_FS::chmod( $path, $old );
                clearstatcache( true, $path );
                $ok = false;
            }

            $newPerms = $this->get_perm_string($path);
            if ($ok && $newPerms === $wantStr) {
                $results[] = [
                    'file'   => $key,
                    'status' => 'changed',
                    'detail' => 'Changed ' . $oldPerms . ' → ' . $wantStr . '.',
                ];
                $changed++;
            } else {
                if ( $logged_now ) {
                    unset( $log[ $path ] );
                    if ( empty( $log ) ) {
                        SFAIS_FS::delete( $log_file );
                    } else {
                        SFAIS_FS::write( $log_file, wp_json_encode( $log, JSON_PRETTY_PRINT ) );
                    }
                }
                $results[] = [
                    'file'   => $key,
                    'status' => 'failed',
                    'detail' => 'Failed to change ' . $oldPerms . ' → ' . $wantStr . ' (hosting ownership / permission policy).',
                ];
                $failed++;
            }
        }

        return [
            'status'  => ($changed > 0),
            'changed' => $changed,
            'skipped' => $skipped,
            'missing' => $missing,
            'outside' => $outside,
            'failed'  => $failed,
            'results' => $results,
        ];
    }

    /**
     * @return array status/message; 'keep_active' => true when saved permissions could not be put back (1.8.13: the
     *               switch then stays on, honestly, and the log keeps what is left to undo).
     */
    protected function revert_fix_permissions() {
        $basedir = $this->uploads_dir();
        if ( '' === $basedir ) {
            return [
                'status'  => false,
                'message' => '⚠️ Uploads directory is not available. Cannot safely revert permissions.',
            ];
        }

        $log_file = $this->permissions_log_file();
        $legacy1  = trailingslashit( $basedir ) . 'mhsf/logs/sfais-permissions-log.json';
        $legacy2  = trailingslashit( $basedir ) . 'sfais/sfais-permissions-log.json';

        if ( '' === $log_file || ! file_exists( $log_file ) ) {
            if ( file_exists( $legacy1 ) ) {
                $log_file = $legacy1;
            } elseif ( file_exists( $legacy2 ) ) {
                $log_file = $legacy2;
            }
        }

        if ( '' === $log_file || ! file_exists( $log_file ) ) {
            // 1.8.13: nothing to undo is not an error (was a red message while the switch went off).
            return [
                'status'  => true,
                'message' => '🔄 Patch reverted. No changes were undone because Maroon Horizon Smart Firewall did not modify file permissions on this site.',
            ];
        }

        $json = SFAIS_FS::read($log_file);
        $log  = json_decode((string) $json, true);

        if (!is_array($log)) {
            return [
                'status'  => false,
                'message' => '⚠️ Permission log corrupted or unreadable. Cannot safely revert permissions. The switch was turned off; the files keep their current permissions.',
            ];
        }

        // 1.8.13: only the files this patch can change are restored (never a path from a changed log file).
        $allowed = [ ABSPATH . 'wp-config.php', dirname( ABSPATH ) . '/wp-config.php', ABSPATH . '.htaccess' ];

        $restored = 0;
        $failed   = 0;
        $left     = [];

        foreach ($log as $path => $perm) {
            if ( ! is_string( $path ) || ! in_array( $path, $allowed, true ) || ! file_exists( $path ) ) {
                // If a target file is gone, we treat it as skipped
                continue;
            }

            $oct = intval((string)$perm, 8);
            $wantStr = sprintf('%04o', $oct);

            // Attempt restore (do NOT require SFAIS_FS::is_writable())
            $ok = SFAIS_FS::chmod($path, $oct);
            clearstatcache( true, $path );
            $new = $this->get_perm_string($path);

            if ($ok && $new === $wantStr) {
                $restored++;
            } else {
                $failed++;
                $left[ $path ] = $perm;
            }
        }

        if ( empty( $left ) ) {
            SFAIS_FS::delete($log_file);
        } else {
            SFAIS_FS::write( $log_file, wp_json_encode( $left, JSON_PRETTY_PRINT ) );
        }

        if ($failed > 0 && $restored > 0) {
            return [
                'status'      => false,
                'keep_active' => true,
                'message'     => '⚠️ Reverted partially: some original permissions were restored, but others could not be changed due to hosting restrictions. The patch stays on so you can try again.',
            ];
        }

        if ($failed > 0 && $restored === 0) {
            return [
                'status'      => false,
                'keep_active' => true,
                'message'     => '⚠️ Revert failed: hosting restrictions prevented restoring the saved permissions. The patch stays on so you can try again.',
            ];
        }

        return [
            'status'  => true,
            'message' => '🔄 Original permissions for core files restored successfully.',
        ];
    }

    private function get_perm_string($path) {
        if (!file_exists($path) || !is_readable($path)) {
            return '';
        }

        $p = fileperms($path);
        if ($p === false) return '';
        return substr(sprintf('%o', $p), -4);
    }

    private function format_permissions_apply_message($report) {
        if (!is_array($report)) {
            return '⚠️ No report available.';
        }

        $changed = intval($report['changed'] ?? 0);
        $failed  = intval($report['failed'] ?? 0);
        $skipped = intval($report['skipped'] ?? 0);
        $missing = intval($report['missing'] ?? 0);
        $outside = intval($report['outside'] ?? 0);

        // ✅ Cleaner messaging: no per-file lines.
        if ($failed === 0 && ($changed > 0 || $skipped > 0)) {
            if ($changed > 0) {
                $headline = '✅ File permission hardening applied to core files.';
            } else {
                $headline = '✅ Core file permissions are already hardened.';
            }
        } elseif ($changed > 0 && $failed > 0) {
            $headline = '⚠️ Applied partially: some core files were secured, but some could not be changed.';
        } else {
            $headline = '⚠️ No changes were applied (files were missing or hosting blocked permission changes).';
        }

        // 1.8.13: "Skipped" only counted files that are already hardened - now said as such, missing files separately.
        $html = $headline . '<br>'
            . '<span style="color:#555;">Changed: ' . intval($changed) . ', Already hardened: ' . intval($skipped) . ', Not present: ' . intval($missing) . ', Failed: ' . intval($failed) . '.</span>';

        if ( $outside > 0 ) {
            $html .= '<br>wp-config.php is one folder above WordPress, so this patch did not change it. You can set it to 0440 in your hosting file manager.';
        }

        return $html;
    }

    private function set_config_constant( $name, $value ) {
        $cfg   = ABSPATH . 'wp-config.php';
        $name  = (string) $name;
        $value = (bool) $value;

        // Defensive validation: only allow typical constant names.
        if ( $name === '' || ! preg_match( '/^[A-Z0-9_]+$/', $name ) ) {
            return false;
        }

        if ( ! file_exists( $cfg ) ) {
            return false;
        }

        // Prefer WP_Filesystem via SFAIS_FS.
        $contents = SFAIS_FS::read( $cfg );
        if ( $contents === false ) {
            return false;
        }

        $qname   = preg_quote( $name, '/' );
        $pattern = "/define\(\s*(['\"]){$qname}\1\s*,\s*(true|false)\s*\)\s*;?/i";

        $replacement = "define('{$name}', " . ( $value ? 'true' : 'false' ) . ");";

        if ( preg_match( $pattern, $contents ) ) {
            $new_contents = preg_replace( $pattern, $replacement, $contents, 1 );
        } else {
            $insert = $replacement . "\n";
            $pos    = strpos( $contents, "/* That's all, stop editing" );

            if ( $pos !== false ) {
                $new_contents = substr( $contents, 0, $pos ) . $insert . substr( $contents, $pos );
            } else {
                $new_contents = rtrim( $contents ) . "\n\n" . $insert;
            }
        }

        // Preserve existing permissions when possible (avoid loosening wp-config.php).
        $chmod = null;
        if ( is_readable( $cfg ) ) {
            $perms = fileperms( $cfg );
            if ( $perms !== false ) {
                $chmod = ( $perms & 0777 );
            }
        }

        return SFAIS_FS::write( $cfg, $new_contents, is_int( $chmod ) ? $chmod : null );
    }
}
