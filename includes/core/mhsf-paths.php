<?php
/**
 * Path helpers for Maroon Horizon Smart Firewall.
 *
 * All plugin-created artifacts must be stored under:
 *   wp_upload_dir()['basedir'] . '/maroon-horizon-smart-firewall/'
 *
 * @package MaroonHorizonSmartFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! function_exists( 'mhsf_get_uploads_basedir' ) ) {
	/**
	 * Get WordPress uploads basedir.
	 *
	 * @return string|WP_Error
	 */
	function mhsf_get_uploads_basedir() {
		static $cache = null;
		if ( null !== $cache ) {
			return $cache;
		}

		$uploads = wp_upload_dir( null, false );
		if ( ! is_array( $uploads ) ) {
			$cache = new WP_Error( 'mhsf_upload_dir_failed', 'wp_upload_dir() did not return an array.' );
			mhsf_maybe_admin_notice_uploads_error( $cache );
			return $cache;
		}

		$basedir = isset( $uploads['basedir'] ) ? (string) $uploads['basedir'] : '';
		$basedir = wp_normalize_path( $basedir );

		if ( '' === $basedir ) {
			$cache = new WP_Error( 'mhsf_upload_dir_missing_basedir', 'wp_upload_dir() is missing basedir.' );
			mhsf_maybe_admin_notice_uploads_error( $cache );
			return $cache;
		}

		$cache = rtrim( $basedir, '/\\' );
		return $cache;
	}
}

if ( ! function_exists( 'mhsf_get_uploads_baseurl' ) ) {
	/**
	 * Get WordPress uploads baseurl.
	 *
	 * @return string|WP_Error
	 */
	function mhsf_get_uploads_baseurl() {
		static $cache = null;
		if ( null !== $cache ) {
			return $cache;
		}

		$uploads = wp_upload_dir( null, false );
		if ( ! is_array( $uploads ) ) {
			$cache = new WP_Error( 'mhsf_upload_url_failed', 'wp_upload_dir() did not return an array.' );
			mhsf_maybe_admin_notice_uploads_error( $cache );
			return $cache;
		}

		$baseurl = isset( $uploads['baseurl'] ) ? (string) $uploads['baseurl'] : '';
		if ( '' === $baseurl ) {
			$cache = new WP_Error( 'mhsf_upload_url_missing_baseurl', 'wp_upload_dir() is missing baseurl.' );
			mhsf_maybe_admin_notice_uploads_error( $cache );
			return $cache;
		}

		$cache = rtrim( $baseurl, '/\\' );
		return $cache;
	}
}

if ( ! function_exists( 'mhsf_get_data_dir' ) ) {
	/**
	 * Get plugin data directory under uploads/{plugin-slug}/ and ensure it exists.
	 *
	 * @param string $subpath Optional subpath under the slug folder.
	 * @return string|WP_Error
	 */
	function mhsf_get_data_dir( $subpath = '' ) {
		$basedir = mhsf_get_uploads_basedir();
		if ( is_wp_error( $basedir ) ) {
			return $basedir;
		}

		// wp_mkdir_p() lives in wp-admin/includes/file.php and may not be loaded
		// in frontend/cron contexts.
		if ( ! function_exists( 'wp_mkdir_p' ) ) {
			$file_inc = ABSPATH . 'wp-admin/includes/file.php';
			if ( file_exists( $file_inc ) ) {
				require_once $file_inc;
			}
		}
		if ( ! function_exists( 'wp_mkdir_p' ) ) {
			$err = new WP_Error( 'mhsf_mkdirp_unavailable', 'wp_mkdir_p() is unavailable in this context.' );
			mhsf_maybe_admin_notice_uploads_error( $err );
			return $err;
		}

		$slug_dir = trailingslashit( $basedir ) . 'maroon-horizon-smart-firewall/';
		$slug_dir = wp_normalize_path( $slug_dir );

		if ( ! wp_mkdir_p( $slug_dir ) ) {
			$err = new WP_Error( 'mhsf_upload_dir_create_failed', 'Failed to create plugin uploads directory.' );
			mhsf_maybe_admin_notice_uploads_error( $err );
			return $err;
		}
		mhsf_protect_dir( $slug_dir );   // 1.8.3: reports, logs, quarantine and PRO data are never reachable from the web

		$subpath = (string) $subpath;
		$subpath = str_replace( '\\', '/', $subpath );
		$subpath = ltrim( $subpath, '/' );

		if ( '' === $subpath ) {
			return rtrim( $slug_dir, '/\\' );
		}

		// Prevent directory traversal. Keep minimal and safe.
		if ( false !== strpos( $subpath, '..' ) ) {
			return new WP_Error( 'mhsf_invalid_subpath', 'Invalid subpath.' );
		}

		$full = $slug_dir . $subpath;
		$full = wp_normalize_path( $full );

		// If subpath implies directories, ensure they exist.
		$maybe_dir = $full;
		if ( '/' !== substr( $subpath, -1 ) && false !== strpos( $subpath, '/' ) ) {
			$maybe_dir = dirname( $full );
		}
		if ( ! wp_mkdir_p( $maybe_dir ) ) {
			$err = new WP_Error( 'mhsf_upload_subdir_create_failed', 'Failed to create plugin uploads subdirectory.' );
			mhsf_maybe_admin_notice_uploads_error( $err );
			return $err;
		}

		return rtrim( $full, '/\\' );
	}
}

if ( ! function_exists( 'mhsf_protect_dir' ) ) {
	/**
	 * Close a plugin data folder to the web (1.8.3): deny-all .htaccess (Apache 2.2 + 2.4, LiteSpeed) + empty index.php.
	 * Written once; an existing file is never overwritten. (nginx ignores .htaccess - the folder holds no public files.)
	 *
	 * @param string $dir Folder.
	 */
	function mhsf_protect_dir( $dir ) {
		$dir = rtrim( (string) $dir, '/\\' );
		if ( '' === $dir || ! is_dir( $dir ) ) {
			return;
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			@file_put_contents( $dir . '/.htaccess', "# Maroon Horizon Smart Firewall - private data, never served\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Order deny,allow\n  Deny from all\n</IfModule>\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			@file_put_contents( $dir . '/index.php', "<?php\n// Silence is golden.\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents, WordPress.PHP.NoSilencedErrors.Discouraged
		}
	}
}

if ( ! function_exists( 'mhsf_get_data_url' ) ) {
	/**
	 * Get plugin data URL under uploads/{plugin-slug}/.
	 *
	 * @param string $subpath Optional subpath under the slug folder.
	 * @return string|WP_Error
	 */
	function mhsf_get_data_url( $subpath = '' ) {
		$baseurl = mhsf_get_uploads_baseurl();
		if ( is_wp_error( $baseurl ) ) {
			return $baseurl;
		}

		$url = trailingslashit( $baseurl ) . 'maroon-horizon-smart-firewall/';
		$subpath = (string) $subpath;
		$subpath = str_replace( '\\', '/', $subpath );
		$subpath = ltrim( $subpath, '/' );

		if ( '' !== $subpath ) {
			$url .= $subpath;
		}

		return rtrim( $url, '/\\' );
	}
}

if ( ! function_exists( 'mhsf_maybe_admin_notice_uploads_error' ) ) {
	/**
	 * Show a safe admin notice for uploads path failures (admin only).
	 *
	 * @param WP_Error $error Error.
	 * @return void
	 */
	function mhsf_maybe_admin_notice_uploads_error( $error ) {
		if ( ! is_admin() || ! is_wp_error( $error ) ) {
			return;
		}

		static $queued = false;
		if ( $queued ) {
			return;
		}
		$queued = true;

		add_action(
			'admin_notices',
			static function() use ( $error ) {
				if ( ! current_user_can( 'manage_options' ) ) {
					return;
				}
				echo '<div class="notice notice-error"><p>';
				echo esc_html__( 'Maroon Horizon Smart Firewall:', 'maroon-horizon-smart-firewall' ) . ' ' . esc_html( $error->get_error_message() );
				echo '</p></div>';
			}
		);
	}
}
