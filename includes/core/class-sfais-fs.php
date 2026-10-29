<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Filesystem helper.
 *
 * Centralizes filesystem access via WP_Filesystem for better compatibility
 * (e.g., different ownership/ACL situations) and to reduce direct filesystem
 * warnings in automated checks.
 */
final class SFAIS_FS {

    /** @var object|null */
    private static $fs = null;

    /**
     * Return a direct filesystem handler (no credentials UI).
     *
     * Loads the required WP core classes lazily and immediately instantiates the
     * handler (no include-for-side-effects).
     *
     * @return WP_Filesystem_Direct
     */
    private static function direct() {
        if ( ! class_exists( 'WP_Filesystem_Direct' ) ) {
            require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
            require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
        }

        return new WP_Filesystem_Direct( null );
    }


    /**
     * Returns a WP_Filesystem instance.
     *
     * Uses WP_Filesystem() when possible. Falls back to WP_Filesystem_Direct
     * when the global handler cannot be initialized.
     *
     * @return object
     */
    public static function fs() {
        if ( is_object( self::$fs ) ) {
            return self::$fs;
        }

        // In admin-ajax contexts, avoid WP_Filesystem() because it can print
        // credential HTML and break JSON responses. Use a direct handler instead.
        if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
            self::$fs = self::direct();
            return self::$fs;
        }

        global $wp_filesystem;
        if ( is_object( $wp_filesystem ) ) {
            self::$fs = $wp_filesystem;
            return self::$fs;
        }

        // Initialize the configured filesystem handler for non-AJAX contexts.
        if ( ! function_exists( 'WP_Filesystem' ) ) {
            $file_inc = ABSPATH . 'wp-admin/includes/file.php';
            if ( file_exists( $file_inc ) ) {
                require_once $file_inc;
                // Immediately initialize after include (no include-for-side-effects).
                if ( function_exists( 'WP_Filesystem' ) ) {
                    WP_Filesystem();
                }
            }
        } else {
            WP_Filesystem();
        }

        if ( is_object( $wp_filesystem ) ) {
            self::$fs = $wp_filesystem;
            return self::$fs;
        }

        // Fallback.
        self::$fs = self::direct();
        return self::$fs;
    }

    public static function mkdir_p( $dir, $chmod = null ) : bool {
        $dir = untrailingslashit( (string) $dir );
        if ( $dir === '' ) {
            return false;
        }

        if ( is_dir( $dir ) ) {
            return true;
        }

        // wp_mkdir_p() may not be loaded in all contexts (it lives in file.php).
        if ( function_exists( 'wp_mkdir_p' ) ) {
            if ( wp_mkdir_p( $dir ) ) {
                return true;
            }
        } else {
            $file_inc = ABSPATH . 'wp-admin/includes/file.php';
            if ( file_exists( $file_inc ) ) {
                require_once $file_inc;
                // Immediately attempt mkdir after include (no include-for-side-effects).
                if ( function_exists( 'wp_mkdir_p' ) && wp_mkdir_p( $dir ) ) {
                    return true;
                }
            }
        }

        $fs   = self::fs();
        $mode = is_int( $chmod ) ? $chmod : ( defined( 'FS_CHMOD_DIR' ) ? FS_CHMOD_DIR : 0755 );

        if ( method_exists( $fs, 'mkdir' ) ) {
            return (bool) $fs->mkdir( $dir, $mode, true );
        }

        return false;
    }

    /**
     * Read file contents.
     *
     * @return string|false
     */
    public static function read( $path ) {
        $path = (string) $path;
        if ( $path === '' ) {
            return false;
        }

        // Primary: WP_Filesystem (preferred for compatibility).
        $fs = self::fs();
        if ( is_object( $fs ) && method_exists( $fs, 'get_contents' ) ) {
            $contents = $fs->get_contents( $path );
            if ( is_string( $contents ) ) {
                return $contents;
            }
        }

        /**
         * Fallback: WP_Filesystem_Direct read.
         *
         * Some environments initialize WP_Filesystem with a non-direct method that
         * cannot operate in AJAX/admin contexts without credentials. Deep Scan and
         * AI Threat Detection must still be able to read local PHP/JS/.htaccess.
         */
        if ( is_readable( $path ) ) {
            $direct = self::direct();
            if ( is_object( $direct ) && method_exists( $direct, 'get_contents' ) ) {
                $raw = $direct->get_contents( $path );
                if ( is_string( $raw ) ) {
                    return $raw;
                }
            }
        }

        return false;
    }

    /** 1.8.17: true only while a Security Patch is applied or reverted (see write()). */
    private static $htaccess_unlock = false;

    public static function allow_htaccess_unlock( $on ) {
        self::$htaccess_unlock = (bool) $on;
    }

    public static function write( $path, $contents, $chmod = null ) : bool {
        $path = (string) $path;
        if ( $path === '' ) {
            return false;
        }

        // 1.8.17: while a Security Patch is switched (allow_htaccess_unlock), a .htaccess locked read-only (e.g. 0444 by "Fix File
        // Permissions") is unlocked for this one write and locked again with its old permissions. Patches said ".htaccess could not
        // be updated". Everything else (IP Blocker: "Blocked: WordPress only" on a locked file - Vlad 1.8.10) keeps respecting the lock.
        if ( self::$htaccess_unlock && '.htaccess' === basename( $path ) && file_exists( $path ) && ! self::is_writable( $path ) ) {
            $relock = self::unlock( $path );
            if ( null === $relock ) {
                return false;
            }
            $ok = self::write_raw( $path, $contents, $relock );
            self::chmod( $path, $relock );
            clearstatcache( true, $path );
            return $ok;
        }
        return self::write_raw( $path, $contents, $chmod );
    }

    /**
     * 1.8.17: make a read-only file owner-writable. Returns its old permissions (to lock it again with chmod) or null.
     */
    public static function unlock( $path ) {
        $path = (string) $path;
        clearstatcache( true, $path );
        $perms = file_exists( $path ) ? fileperms( $path ) : false;
        if ( false === $perms ) {
            return null;
        }
        $old = $perms & 0777;
        if ( ! self::chmod( $path, $old | 0200 ) ) {
            return null;
        }
        clearstatcache( true, $path );
        if ( ! self::is_writable( $path ) ) {
            self::chmod( $path, $old );
            clearstatcache( true, $path );
            return null;
        }
        return $old;
    }

    /**
     * 1.8.17: can the plugin change this .htaccess? True when it is writable, or locked read-only but the plugin may unlock
     * it for a moment (write() does that). A missing file counts when its folder is writable.
     */
    public static function htaccess_writable( $path ) : bool {
        $path = (string) $path;
        if ( ! file_exists( $path ) ) {
            return self::is_writable( dirname( $path ) );
        }
        if ( self::is_writable( $path ) ) {
            return true;
        }
        $old = self::unlock( $path );
        if ( null === $old ) {
            return false;
        }
        self::chmod( $path, $old );   // only a test - locked again at once
        clearstatcache( true, $path );
        return true;
    }

    private static function write_raw( $path, $contents, $chmod = null ) : bool {

        $dir = dirname( $path );
        if ( $dir && ! is_dir( $dir ) ) {
            self::mkdir_p( $dir );
        }

        $fs   = self::fs();
        $mode = is_int( $chmod ) ? $chmod : ( defined( 'FS_CHMOD_FILE' ) ? FS_CHMOD_FILE : 0644 );

        // Primary: current WP_Filesystem handler.
        if ( method_exists( $fs, 'put_contents' ) ) {
            $ok = (bool) $fs->put_contents( $path, (string) $contents, $mode );
            if ( $ok ) {
                return true;
            }
        }

        // Fallback: direct handler (no credentials UI) for admin/AJAX contexts.
        // This is still WP_Filesystem-based and avoids raw PHP filesystem calls.
        $direct = self::direct();
        if (
            $dir && is_dir( $dir )
            && is_object( $direct )
            && method_exists( $direct, 'is_writable' )
            && $direct->is_writable( $dir )
            && method_exists( $direct, 'put_contents' )
        ) {
            return (bool) $direct->put_contents( $path, (string) $contents, $mode );
        }


        return false;
    }

    public static function delete( $path, $recursive = false ) : bool {
        $path = (string) $path;
        if ( $path === '' ) {
            return false;
        }

        $fs = self::fs();
        if ( method_exists( $fs, 'delete' ) ) {
            $ok = (bool) $fs->delete( $path, (bool) $recursive );
            if ( $ok ) {
                return true;
            }
        }

        // Fallback: direct handler.
        $direct = self::direct();
        if ( is_object( $direct ) && method_exists( $direct, 'delete' ) ) {
            return (bool) $direct->delete( $path, (bool) $recursive );
        }

        return false;
    }

    public static function move( $source, $dest, $overwrite = true ) : bool {
        $source = (string) $source;
        $dest   = (string) $dest;

        if ( $source === '' || $dest === '' ) {
            return false;
        }

        $dir = dirname( $dest );
        if ( $dir && ! is_dir( $dir ) ) {
            self::mkdir_p( $dir );
        }

        $fs = self::fs();
        if ( method_exists( $fs, 'move' ) ) {
            $ok = (bool) $fs->move( $source, $dest, (bool) $overwrite );
            if ( $ok ) {
                return true;
            }
        }

        // Fallback: direct handler.
        $direct = self::direct();
        if ( is_object( $direct ) && method_exists( $direct, 'move' ) ) {
            return (bool) $direct->move( $source, $dest, (bool) $overwrite );
        }

        return false;
    }

    public static function chmod( $path, $mode, $recursive = false ) : bool {
        $path = (string) $path;
        if ( $path === '' ) {
            return false;
        }

        $fs = self::fs();
        if ( method_exists( $fs, 'chmod' ) ) {
            return (bool) $fs->chmod( $path, (int) $mode, (bool) $recursive );
        }

        return false;
    }

    /**
     * Check whether a path is writable, using WP_Filesystem where possible.
     *
     * @param string $path Absolute path.
     * @return bool
     */
    public static function is_writable( $path ) : bool {
        $path = (string) $path;
        if ( $path === '' ) {
            return false;
        }

        $fs = self::fs();
        if ( is_object( $fs ) && method_exists( $fs, 'is_writable' ) ) {
            return (bool) $fs->is_writable( $path );
        }

        if ( function_exists( 'wp_is_writable' ) ) {
            return (bool) wp_is_writable( $path );
        }

        return false;
    }

    /**
     * Write the site's root .htaccess and make sure the site still answers (1.8.9).
     *
     * One bad line in .htaccess takes the whole site down with HTTP 500. After writing, a small static core file is
     * loaded through the web server; if the server answers with a 5xx error, the previous contents are put back at once.
     *
     * @param string $path      Absolute path of the .htaccess file.
     * @param string $contents  New contents.
     * @param string $check_url 1.8.13: optional URL of a file inside the folder of this .htaccess (uploads, wp-content);
     *                          a folder's .htaccess only affects its own files, so the root test file proves nothing there.
     * @return string 'ok' (written and the site answers), 'unverified' (written, the server could not call itself),
     *                'restored' (the site broke, the previous file is back) or 'failed' (not written).
     */
    public static function write_htaccess_checked( $path, $contents, $check_url = '' ) : string {
        $path    = (string) $path;
        $existed = file_exists( $path );
        $old     = $existed ? self::read( $path ) : '';
        if ( ! is_string( $old ) ) {
            return 'failed';
        }
        if ( $existed && (string) $contents === $old ) {
            return 'ok';
        }
        if ( ! self::write( $path, (string) $contents ) ) {
            return 'failed';
        }

        $code = self::site_answer_code( (string) $check_url );
        if ( $code === 0 ) {
            return 'unverified';
        }
        if ( $code < 500 ) {
            return 'ok';
        }

        // The change broke the server's configuration: put the previous file back.
        if ( $existed ) {
            self::write( $path, $old );
        } else {
            self::delete( $path );
        }
        return 'restored';
    }

    /**
     * HTTP status of a static core file loaded through the web server (0 = the server could not call itself).
     * 401/403/3xx all mean the server could read its configuration; only 5xx means it is broken.
     */
    private static function site_answer_code( $check_url = '' ) : int {
        if ( ! function_exists( 'wp_remote_get' ) || ! function_exists( 'site_url' ) ) {
            return 0;
        }
        $base = ( '' !== (string) $check_url ) ? (string) $check_url : site_url( '/wp-includes/images/blank.gif' );
        $url  = add_query_arg( 'mhsf_check', (string) wp_rand( 100000, 999999 ), $base );
        $res = wp_remote_get(
            $url,
            array(
                'timeout'     => 8,
                'redirection' => 0,
                // Only the status code of the site's own static file is read (nothing is sent or trusted);
                // local certificates are often self-signed, as in WordPress core's own loopback checks.
                'sslverify'   => false,
                'headers'     => array( 'Cache-Control' => 'no-cache' ),
            )
        );
        if ( is_wp_error( $res ) ) {
            return 0;
        }
        return (int) wp_remote_retrieve_response_code( $res );
    }

}