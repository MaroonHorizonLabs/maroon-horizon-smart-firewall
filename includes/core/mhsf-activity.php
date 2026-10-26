<?php
/**
 * 1.8.15 Activity log for the Dashboard's "Recent activity" (Vlad 26 Oct: at least the last 100 events, with a scroll bar).
 *
 * One option (mhsf_activity_log, not autoloaded), newest first, at most MHSF_ACTIVITY_MAX entries - the oldest drop out, so it
 * never grows. Events come from:
 *  - do_action( 'mhsf_activity', $type, $text ) anywhere in the plugin (score changes, Login Guard lockouts, feed updates, clean-up);
 *  - the plugin's own AJAX answers (patches, IP Blocker, quarantine, ignore, scans): their JSON answer is read at shutdown, so the
 *    log says exactly what the admin saw under the button - no change to the button code.
 * Login Guard lockouts are grouped per hour, so an attack can't push every other entry out.
 *
 * @package MaroonHorizonSmartFirewall
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'MHSF_ACTIVITY_MAX' ) ) {
	define( 'MHSF_ACTIVITY_MAX', 200 );
}

if ( ! function_exists( 'mhsf_activity_add' ) ) {
	/**
	 * Add one entry (plain text; tags and leading icons are removed).
	 *
	 * @param string $type Short type key (patch, ip, scan, quarantine, check, login, feed, housekeeping, ...).
	 * @param string $text One plain sentence.
	 */
	function mhsf_activity_add( $type, $text ) {
		$type = sanitize_key( (string) $type );
		$text = trim( preg_replace( '/\s+/u', ' ', wp_strip_all_tags( (string) $text ) ) );
		$text = trim( preg_replace( '/^[^\p{L}\p{N}"\'(]+/u', '', $text ) );   // leading emoji / symbols from button answers
		if ( '' === $text ) {
			return;
		}
		if ( function_exists( 'mb_substr' ) ) {
			$text = mb_substr( $text, 0, 220 );
		}
		$log = mhsf_activity_get();
		$now = time();

		// Login Guard: one line per hour with a count
		if ( 'login' === $type && isset( $log[0]['type'] ) && 'login' === $log[0]['type'] && gmdate( 'YmdH', (int) $log[0]['t'] ) === gmdate( 'YmdH', $now ) ) {
			$n          = (int) ( $log[0]['n'] ?? 1 ) + 1;
			$log[0]['n'] = $n;
			$log[0]['t'] = $now;
			/* translators: %d: number of IP addresses locked in this hour */
			$log[0]['text'] = sprintf( _n( 'Login Guard locked %d IP address this hour (too many failed logins)', 'Login Guard locked %d IP addresses this hour (too many failed logins)', $n, 'maroon-horizon-smart-firewall' ), $n );
		} else {
			// the same text again within a minute (double click, two tabs) is one entry
			if ( isset( $log[0]['text'] ) && $log[0]['text'] === $text && $now - (int) $log[0]['t'] < 60 ) {
				return;
			}
			array_unshift( $log, array( 't' => $now, 'type' => $type, 'text' => $text ) );
		}
		update_option( 'mhsf_activity_log', array_slice( $log, 0, MHSF_ACTIVITY_MAX ), false );
	}
	add_action( 'mhsf_activity', 'mhsf_activity_add', 10, 2 );
}

if ( ! function_exists( 'mhsf_activity_get' ) ) {
	/**
	 * Newest first. The first call after an update starts the log with the times the plugin already stored.
	 *
	 * @return array<int,array{t:int,type:string,text:string}>
	 */
	function mhsf_activity_get() {
		$log = get_option( 'mhsf_activity_log', null );
		if ( is_array( $log ) ) {
			return $log;
		}
		$seed = array();
		$off  = (int) ( (float) get_option( 'gmt_offset' ) * HOUR_IN_SECONDS );
		foreach ( array( 'sfais_last_core_report' => 'core', 'sfais_last_content_report' => 'content' ) as $opt => $kind ) {
			$r = get_option( $opt );
			if ( is_array( $r ) && ! empty( $r['timestamp'] ) ) {
				$s = isset( $r['summary'] ) ? (array) $r['summary'] : array();
				$t = (int) strtotime( (string) $r['timestamp'] ) - $off;   // stored as site-local time
				if ( 'core' === $kind ) {
					$i = (int) ( $s['modified'] ?? 0 ) + (int) ( $s['missing'] ?? 0 );
					/* translators: %d: issues */
					$seed[] = array( 't' => $t, 'type' => 'scan', 'text' => sprintf( _n( 'Core files checked · %d issue', 'Core files checked · %d issues', $i, 'maroon-horizon-smart-firewall' ), $i ) );
				} else {
					/* translators: %d: files */
					$seed[] = array( 't' => $t, 'type' => 'scan', 'text' => sprintf( __( 'Uploads & themes scanned · %d suspicious', 'maroon-horizon-smart-firewall' ), (int) ( $s['suspicious'] ?? 0 ) ) );
				}
			}
		}
		usort( $seed, static function ( $a, $b ) { return $b['t'] <=> $a['t']; } );
		update_option( 'mhsf_activity_log', $seed, false );
		return $seed;
	}
}

if ( ! function_exists( 'mhsf_activity_watch_ajax' ) ) {
	/**
	 * The plugin's AJAX actions whose answer goes into the log (action => type).
	 *
	 * @return array<string,string>
	 */
	function mhsf_activity_actions() {
		return array(
			'sfais_toggle_patch'          => 'patch',
			'sfais_toggle_manual_flag'    => 'check',
			'sfais_block_ip_ajax'         => 'ip',
			'sfais_unblock_ip_ajax'       => 'ip',
			'sfais_toggle_htaccess_lock'  => 'ip',
			'sfais_quarantine_move'       => 'quarantine',
			'sfais_quarantine_delete'     => 'quarantine',
			'sfais_quarantine_restore'    => 'quarantine',
			'sfais_quarantine_remove'     => 'quarantine',
			'sfais_quarantine_ignore'     => 'scan',
			'sfais_quarantine_ignore_bulk' => 'scan',
			'sfais_scanner_unignore'      => 'scan',
			'sfais_scan_uploads'          => 'scan',
			'sfais_scan_core_tick'        => 'scan',
			'sfais_scan_ai_deep_tick'     => 'scan',
			'sfais_threat_feed_ajax'      => 'feed',
			'sfais_ai_model_sync'         => 'feed',
		);
	}

	/** Start reading the answer of a watched action (runs before the action's own handler). */
	function mhsf_activity_watch_ajax() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		ob_start();
		add_action( 'shutdown', 'mhsf_activity_read_ajax', 0 );
	}

	/** At shutdown the JSON answer is still in the buffer (PHP flushes buffers after shutdown functions). */
	function mhsf_activity_read_ajax() {
		$out = (string) ob_get_contents();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- the handler already checked the nonce; only the action name is read here.
		$action = isset( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : '';
		$map    = mhsf_activity_actions();
		if ( '' === $out || ! isset( $map[ $action ] ) ) {
			return;
		}
		$json = json_decode( $out, true );
		if ( ! is_array( $json ) || empty( $json['success'] ) ) {
			return;   // only what really happened
		}
		$d    = isset( $json['data'] ) && is_array( $json['data'] ) ? $json['data'] : array();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- read-only, after the handler checked the nonce.
		$file = isset( $_POST['file'] ) ? sanitize_text_field( wp_unslash( $_POST['file'] ) ) : '';
		$text = '';
		switch ( $action ) {
			case 'sfais_scan_core_tick':
			case 'sfais_scan_ai_deep_tick':
				if ( ( $d['status'] ?? '' ) !== 'done' ) {
					return;
				}
				$s = isset( $d['report']['summary'] ) ? (array) $d['report']['summary'] : ( isset( $d['summary'] ) ? (array) $d['summary'] : array() );
				if ( 'sfais_scan_core_tick' === $action ) {
					$i = (int) ( $s['modified'] ?? 0 ) + (int) ( $s['missing'] ?? 0 );
					/* translators: %d: issues */
					$text = sprintf( _n( 'Core files checked · %d issue', 'Core files checked · %d issues', $i, 'maroon-horizon-smart-firewall' ), $i );
				} else {
					/* translators: %d: files */
					$text = sprintf( __( 'Deep Scan finished · %d suspicious', 'maroon-horizon-smart-firewall' ), (int) ( $s['suspicious'] ?? 0 ) );
				}
				break;
			case 'sfais_scan_uploads':
				$s = isset( $d['report']['summary'] ) ? (array) $d['report']['summary'] : ( isset( $d['summary'] ) ? (array) $d['summary'] : array() );
				/* translators: %d: files */
				$text = sprintf( __( 'Uploads & themes scanned · %d suspicious', 'maroon-horizon-smart-firewall' ), (int) ( $s['suspicious'] ?? 0 ) );
				break;
			case 'sfais_toggle_manual_flag':
				$labels = array( 'backup_found' => 'Backup Found', 'backup_age' => 'Backup Age', 'strong_passwords' => 'Strong Password Policy', 'two_factor' => 'Two-Factor Authentication (2FA)' );
				$flag   = (string) ( $d['flag'] ?? '' );
				$name   = $labels[ $flag ] ?? $flag;
				/* translators: %s: check name */
				$text = ! empty( $d['enabled'] ) ? sprintf( __( 'Marked as confirmed: %s', 'maroon-horizon-smart-firewall' ), $name ) : sprintf( __( 'Confirmation removed: %s', 'maroon-horizon-smart-firewall' ), $name );
				break;
			case 'sfais_quarantine_move':
			case 'sfais_quarantine_delete':
			case 'sfais_quarantine_restore':
			case 'sfais_quarantine_remove':
			case 'sfais_quarantine_ignore':
			case 'sfais_scanner_unignore':
				// short texts for the narrow activity card; the path without "wp-content/"
				$file  = ! empty( $d['original'] ) ? (string) $d['original'] : ( ! empty( $d['data']['original'] ) ? (string) $d['data']['original'] : $file );   // 1.8.15: quarantine names are random
				$short = wp_basename( preg_replace( array( '#\.phq$#', '#\.quarantined$#' ), array( '.php', '' ), $file ) );   // the file name only - the Scanner shows the path
				$what  = array(
					'sfais_quarantine_move'    => __( 'Quarantined', 'maroon-horizon-smart-firewall' ),
					'sfais_quarantine_delete'  => __( 'Deleted', 'maroon-horizon-smart-firewall' ),
					'sfais_quarantine_restore' => __( 'Restored from quarantine', 'maroon-horizon-smart-firewall' ),
					'sfais_quarantine_remove'  => __( 'Deleted from quarantine', 'maroon-horizon-smart-firewall' ),
					'sfais_quarantine_ignore'  => __( 'Ignored in scans', 'maroon-horizon-smart-firewall' ),
					'sfais_scanner_unignore'   => __( 'Un-ignored', 'maroon-horizon-smart-firewall' ),
				);
				$text = $what[ $action ] . ': ' . $short;
				break;
			case 'sfais_quarantine_ignore_bulk':
				$n = isset( $d['count'] ) ? (int) $d['count'] : ( isset( $d['ignored'] ) ? (int) $d['ignored'] : 0 );
				/* translators: %d: files */
				$text = $n ? sprintf( _n( 'Ignored %d file in scans', 'Ignored %d files in scans', $n, 'maroon-horizon-smart-firewall' ), $n ) : __( 'Ignored files in scans', 'maroon-horizon-smart-firewall' );
				break;
			default:
				$text = (string) ( $d['message'] ?? '' );
				if ( '' === $text && isset( $d['data']['message'] ) ) {
					$text = (string) $d['data']['message'];
				}
		}
		mhsf_activity_add( $map[ $action ], $text );
	}

	foreach ( array_keys( mhsf_activity_actions() ) as $mhsf_activity_action ) {
		add_action( 'wp_ajax_' . $mhsf_activity_action, 'mhsf_activity_watch_ajax', 0 );
	}
	unset( $mhsf_activity_action );
}
