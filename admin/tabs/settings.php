<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

call_user_func( static function() {
// Get plugin version from header
$plugin_data = get_file_data(
    SFAIS_PATH . 'maroon-horizon-smart-firewall.php',
    ['Version' => 'Version']
);
$version = $plugin_data['Version'] ?? 'Unknown';

// Freemius instance (may be false if SDK missing)
$fs = function_exists( 'mhsf_fs' ) ? mhsf_fs() : false;
$is_premium_code = defined( 'SFAIS_IS_PREMIUM_CODE' ) && SFAIS_IS_PREMIUM_CODE;
$is_entitled     = defined( 'SFAIS_HAS_PRO_LICENSE' ) && SFAIS_HAS_PRO_LICENSE;
$mhsf_is_pro_entitled          = $is_premium_code && $is_entitled;

// Prefer Freemius internal admin pages without forcing a billing cycle.
$sfais_pricing_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-pricing' );




// Use a local bridge page that avoids showing the Freemius opt-in screen.
// It will silently set anonymous-mode (Skip) if the site isn't connected yet,
// then redirect to the Freemius account screen.
$sfais_account_url = admin_url( 'admin.php?page=maroon-horizon-smart-firewall-manage-account' );

// Edition label & color
$edition_label = 'Free Edition';
if ( $is_premium_code ) {
    $edition_label = apply_filters( 'mhsf_edition_label_premium', 'Premium Edition' );
    if ( ! $is_entitled ) {
        $edition_label = apply_filters( 'mhsf_edition_label_premium_not_activated', 'Premium Edition (Not Activated)' );
    }
}
$edition_color = $is_premium_code ? '#2e7d32' : '#0277bd';

$nonce = wp_create_nonce( 'sfais_settings_nonce' );
?>
<div id="sfais-tab-settings">

  <h2 style="display:flex;align-items:center;gap:8px;">
    <span class="dashicons dashicons-admin-generic" style="color:#1565c0;"></span>
    Settings
  </h2>
  <p class="sfais-kicker" style="max-width:700px;color:var(--mh-muted,#555);margin-top:6px;">
    Manage MH Smart Firewall preferences, license, and updates.
  </p>

  <!-- 🔹 Plugin Info -->
  <div class="sfais-card" style="margin-top:15px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-info" style="color:#1976d2;"></span>
      Plugin Information
    </h3>
    <p style="margin-top:4px;">
      <strong>MH Smart Firewall</strong><br>
      Version <strong><?php echo esc_html( $version ); ?></strong><br>
      Status:
      <span style="color:<?php echo esc_attr( $edition_color ); ?>;font-weight:600;">
        <?php echo esc_html( $edition_label ); ?>
      </span>
    </p>
    <p style="font-size:12px;color:var(--mh-muted,#555);margin-top:6px;">
      Keep your plugin up to date to ensure the latest firewall rules and vulnerability patches.
    </p>
  </div>

  <!-- 🔹 Appearance (1.8.7): per user - Auto follows the computer's light/dark mode -->
  <?php $mhsf_app = class_exists( 'SFAIS_Admin_UI' ) ? SFAIS_Admin_UI::appearance() : 'auto'; ?>
  <div class="sfais-card" id="mhsf-appearance" style="margin-top:20px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-admin-appearance" style="color:#7a3b78;"></span>
      <?php esc_html_e( 'Appearance', 'maroon-horizon-smart-firewall' ); ?>
    </h3>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:6px 0 0;">
      <input type="hidden" name="action" value="mhsf_set_appearance">
      <?php wp_nonce_field( 'mhsf_set_appearance' ); ?>
      <div class="mhsf-seg" role="group" aria-label="<?php esc_attr_e( 'Appearance', 'maroon-horizon-smart-firewall' ); ?>">
        <?php foreach ( array( 'auto' => __( 'Auto', 'maroon-horizon-smart-firewall' ), 'light' => __( 'Light', 'maroon-horizon-smart-firewall' ), 'dark' => __( 'Dark', 'maroon-horizon-smart-firewall' ) ) as $mhsf_k => $mhsf_l ) : ?>
          <button type="submit" name="mhsf_appearance" value="<?php echo esc_attr( $mhsf_k ); ?>" aria-pressed="<?php echo $mhsf_app === $mhsf_k ? 'true' : 'false'; ?>"><?php echo esc_html( $mhsf_l ); ?></button>
        <?php endforeach; ?>
      </div>
    </form>
    <p class="mhsf-muted" style="font-size:12.5px;margin:10px 0 0;">
      <?php esc_html_e( 'Auto follows your computer\'s light or dark mode. This only changes how the Smart Firewall screens look for you - nothing else on the site.', 'maroon-horizon-smart-firewall' ); ?>
    </p>
  </div>

  <!-- 🔹 Login Guard: locked addresses (1.8.4) -->
  <?php $sfais_locks = class_exists( 'SFAIS_Login_Guard' ) ? SFAIS_Login_Guard::locked_list() : array(); ?>
  <div class="sfais-card" id="sfais-login-guard" style="margin-top:20px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-lock" style="color:var(--mh-crit,#c62828);"></span>
      <?php esc_html_e( 'Login Guard', 'maroon-horizon-smart-firewall' ); ?>
    </h3>
    <p style="margin-top:4px;">
      <?php esc_html_e( 'Five failed logins from one address lock that address out of the login page for 30 minutes.', 'maroon-horizon-smart-firewall' ); ?>
    </p>
    <?php
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only (result of the nonce-checked unlock).
    if ( isset( $_GET['sfais_unlocked_n'] ) ) :
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $sfais_n = (int) $_GET['sfais_unlocked_n'];
        ?>
      <div class="notice notice-success inline" style="margin:8px 0;"><p>
        <?php
        /* translators: %d: number of unlocked addresses */
        echo esc_html( sprintf( _n( '%d address unlocked.', '%d addresses unlocked.', $sfais_n, 'maroon-horizon-smart-firewall' ), $sfais_n ) );
        ?>
      </p></div>
    <?php endif; ?>
    <?php if ( empty( $sfais_locks ) ) : ?>
      <p style="color:var(--mh-ok,#2e7d32);"><?php esc_html_e( 'No address is locked out right now.', 'maroon-horizon-smart-firewall' ); ?></p>
    <?php else : ?>
      <table class="widefat striped" style="margin:8px 0;">
        <thead><tr>
          <th><?php esc_html_e( 'Locked address', 'maroon-horizon-smart-firewall' ); ?></th>
          <th><?php esc_html_e( 'Unlocks by itself in', 'maroon-horizon-smart-firewall' ); ?></th>
          <th></th>
        </tr></thead>
        <tbody>
        <?php foreach ( $sfais_locks as $sfais_ip => $sfais_until ) : ?>
          <tr>
            <td><code><?php echo esc_html( $sfais_ip ); ?></code></td>
            <td><?php echo esc_html( human_time_diff( time(), (int) $sfais_until ) ); ?></td>
            <td style="text-align:right;">
              <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
                <input type="hidden" name="action" value="sfais_login_unlock">
                <input type="hidden" name="sfais_ip" value="<?php echo esc_attr( $sfais_ip ); ?>">
                <?php wp_nonce_field( 'sfais_login_unlock' ); ?>
                <button type="submit" class="button"><?php esc_html_e( 'Unlock', 'maroon-horizon-smart-firewall' ); ?></button>
              </form>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
        <input type="hidden" name="action" value="sfais_login_unlock">
        <input type="hidden" name="sfais_ip" value="all">
        <?php wp_nonce_field( 'sfais_login_unlock' ); ?>
        <button type="submit" class="button"><?php esc_html_e( 'Unlock all', 'maroon-horizon-smart-firewall' ); ?></button>
      </form>
    <?php endif; ?>
    <p style="font-size:12px;color:var(--mh-muted,#555);margin-top:10px;">
      <?php esc_html_e( 'Locked out yourself? On the login page use "Administrator? Get an unlock link by e-mail". No e-mail access? Add this line to wp-config.php over FTP, log in, then remove it again:', 'maroon-horizon-smart-firewall' ); ?>
      <code>define( 'MHSF_LOGIN_GUARD_OFF', true );</code>
    </p>
  </div>

  <!-- 🔹 Storage & clean-up (1.8.15): the limits of the daily clean-up, its last result and Run clean-up now -->
  <?php
    $mhsf_hk_last = get_option( 'mhsf_housekeeping_last', array() );
    $mhsf_hk_time = ( is_array( $mhsf_hk_last ) && ! empty( $mhsf_hk_last['time'] ) ) ? (int) $mhsf_hk_last['time'] : 0;
    $mhsf_hk_text = ( $mhsf_hk_time > 0 && class_exists( 'MHSF_Housekeeping' ) )
        ? MHSF_Housekeeping::counts_text( isset( $mhsf_hk_last['counts'] ) ? $mhsf_hk_last['counts'] : array() )
        : '';
  ?>
  <div class="sfais-card" id="mhsf-storage" style="margin-top:20px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-database" style="color:#00796b;"></span>
      <?php esc_html_e( 'Storage & clean-up', 'maroon-horizon-smart-firewall' ); ?>
    </h3>
    <p style="margin-top:4px;">
      <?php esc_html_e( 'Smart Firewall keeps its own data small: quarantined files are deleted after 30 days (max 50 MB), scan reports after 30 days (newest 5 kept), old scan jobs after 24 hours. Everything is removed when you delete the plugin.', 'maroon-horizon-smart-firewall' ); ?>
    </p>
    <p style="font-size:12.5px;color:var(--mh-muted,#555);margin:6px 0 10px;">
      <?php
      if ( $mhsf_hk_time > 0 ) {
          /* translators: 1: site date and time, 2: what was removed, e.g. "3 old reports removed" or "nothing to remove" */
          echo esc_html( sprintf( __( 'Last clean-up: %1$s (%2$s)', 'maroon-horizon-smart-firewall' ), wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $mhsf_hk_time ), $mhsf_hk_text ) );
      } else {
          esc_html_e( 'Last clean-up: not run yet', 'maroon-horizon-smart-firewall' );
      }
      ?>
    </p>
    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:0;">
      <input type="hidden" name="action" value="mhsf_housekeeping_run">
      <?php wp_nonce_field( 'mhsf_housekeeping_run' ); ?>
      <button type="submit" class="button"><?php esc_html_e( 'Run clean-up now', 'maroon-horizon-smart-firewall' ); ?></button>
    </form>
    <?php
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only (result of the nonce-checked clean-up).
    if ( isset( $_GET['mhsf_cleanup'] ) && $mhsf_hk_time > 0 ) :
        ?>
      <div class="notice notice-success inline" style="margin:8px 0 0;"><p>
        <?php
        /* translators: %s: what was removed, e.g. "3 old reports removed" or "nothing to remove" */
        echo esc_html( sprintf( __( 'Clean-up finished: %s.', 'maroon-horizon-smart-firewall' ), $mhsf_hk_text ) );
        ?>
      </p></div>
    <?php endif; ?>
  </div>

  <!-- 🔹 Privacy (1.8.5, Vlad option A: no opt-in in FREE) -->
  <?php
    $mhsf_connected = ( $fs && is_object( $fs ) && method_exists( $fs, 'is_registered' ) && $fs->is_registered() );
  ?>
  <div class="sfais-card" style="margin-top:20px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-shield" style="color:#1565c0;"></span>
      <?php esc_html_e( 'Privacy', 'maroon-horizon-smart-firewall' ); ?>
    </h3>
    <?php if ( $mhsf_connected ) : ?>
      <p style="margin:0 0 8px 0;color:var(--mh-muted,#555);">
        <?php esc_html_e( 'This site is connected to your license account (Freemius) for license checks and PRO updates.', 'maroon-horizon-smart-firewall' ); ?>
      </p>
      <p style="margin:0 0 10px 0;"><a href="<?php echo esc_url( $sfais_account_url ); ?>" class="button"><?php esc_html_e( 'Account details', 'maroon-horizon-smart-firewall' ); ?></a></p>
    <?php elseif ( $is_premium_code ) : ?>
      <p style="margin:0 0 8px 0;color:var(--mh-muted,#555);">
        <?php esc_html_e( 'Nothing is shared until you activate your PRO license. The license then connects this site to your license account (Freemius) for license checks and PRO updates.', 'maroon-horizon-smart-firewall' ); ?>
      </p>
    <?php else : ?>
      <p style="margin:0 0 8px 0;color:var(--mh-ok,#2e7d32);font-weight:600;">
        <?php esc_html_e( 'This free version shares no data.', 'maroon-horizon-smart-firewall' ); ?>
      </p>
      <p style="margin:0 0 8px 0;color:var(--mh-muted,#555);">
        <?php esc_html_e( 'It does not connect your site to any account and sends no usage or diagnostic data. The only outside requests are the ones you start: the Quick File Integrity Check asks WordPress.org for the official checksums, and "Upgrade to PRO" opens the secure Freemius checkout.', 'maroon-horizon-smart-firewall' ); ?>
      </p>
    <?php endif; ?>
  </div>

  <!-- 🔹 License & Account (Freemius) -->
  <div class="sfais-card" style="margin-top:20px;max-width:700px;">
    <h3 style="display:flex;align-items:center;gap:6px;">
      <span class="dashicons dashicons-admin-network" style="color:#9c27b0;"></span>
      License & Account
    </h3>

    <?php if ( ! $fs ) : ?>
      <p style="margin-bottom:10px;color:var(--mh-crit,#c62828);">
        License service is currently unavailable. Freemius SDK could not be initialized.
        Please verify the <code>/vendor/freemius/</code> folder exists inside the plugin.
      </p>
    <?php else : ?>

<?php if ( $mhsf_is_pro_entitled ) : ?>
  <?php
    $mhsf_ctx = array(
      'account_url' => $sfais_account_url,
      'pricing_url' => $sfais_pricing_url,
    );

    $mhsf_allowed = array(
      'p'      => array( 'style' => true ),
      'div'    => array( 'style' => true ),
      'a'      => array( 'href' => true, 'class' => true, 'style' => true, 'target' => true, 'rel' => true ),
      'strong' => array(),
      'span'   => array( 'class' => true, 'style' => true, 'aria-hidden' => true ),
      'br'     => array(),
    );

    $pro_html = apply_filters( 'mhsf_pro_settings_license_html', '', $mhsf_ctx );
    if ( ! empty( $pro_html ) ) {
        echo wp_kses( $pro_html, $mhsf_allowed );
    } else {
        // Defensive fallback: should not occur in the WP.org FREE build.
        echo '<p style="margin-bottom:10px;color:var(--mh-ok,#2e7d32);">' . esc_html__( 'Account is active. Use the portal to manage your subscription.', 'maroon-horizon-smart-firewall' ) . '</p>';
        echo '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:10px;">'
            . '<a href="' . esc_url( $sfais_account_url ) . '" class="button button-primary">' . esc_html__( 'Open Account Portal', 'maroon-horizon-smart-firewall' ) . '</a>'
            . '</div>';
    }
  ?>

<?php else : ?>
        <p style="margin-bottom:10px;color:var(--mh-muted,#555);">
          Activate a <strong>PRO plan</strong> to unlock the Maroon Horizon Threat Feed (curated daily by Maroon Horizon AI), daily malware signatures,
          and cloud-powered protection updates.<?php /* 1.8.13: was 'real-time malware signatures' - they arrive once a day */ ?>
        </p>
        <ul style="margin:0 0 10px 18px;color:var(--mh-muted,#555);font-size:13px;">
          <li>Malware signatures reviewed daily by Maroon Horizon AI</li>
          <li>Daily, digitally signed Threat Feed updates</li>
          <li>Deep Scan with malware signatures and scheduled e-mail reports</li>
          <li>PRO security patches (file editing, wp-content PHP, Force HTTPS, wp-config, author enumeration)</li>
        </ul>

        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px;">
          <a href="<?php echo esc_url( $sfais_pricing_url ); ?>"
             class="button button-primary">
            🚀 Upgrade to PRO
          </a><?php if ( $fs && method_exists( $fs, 'is_registered' ) && $fs->is_registered() ) : ?><a href="<?php echo esc_url( $sfais_account_url ); ?>"
             class="button">
            🔑 Already purchased? Manage Account
          </a><?php else : // 1.8.5: Freemius offers no license entry in the FREE version - PRO is downloaded from the customer account ?><a href="https://users.freemius.com/" target="_blank" rel="noopener noreferrer"
             class="button">
            🔑 Already purchased? Download PRO
          </a><?php endif; ?>
        </div>
        <?php if ( ! ( $fs && method_exists( $fs, 'is_registered' ) && $fs->is_registered() ) ) : ?>
        <p style="font-size:12px;color:var(--mh-muted,#555);margin-top:8px;">
          <?php esc_html_e( 'Bought PRO on our website? Log in to your account with the e-mail from your purchase, download PRO, then go to Plugins > Add New Plugin > Upload Plugin. When PRO is activated it switches this free version off and keeps your settings; enter your license key there.', 'maroon-horizon-smart-firewall' ); ?>
        </p>
        <?php endif; ?>

        <p style="font-size:11px;color:var(--mh-muted,#555);margin-top:8px;">
          After upgrading, return to this page and your PRO status will update automatically.
        </p>
      <?php endif; ?>

    <?php endif; ?>
  </div>

  <?php if ( function_exists( 'mhsf_data_sources_url' ) ) : // PRO only (file stripped from the free build) ?>
    <p class="description" style="margin-top:18px;">
      <a href="<?php echo esc_url( mhsf_data_sources_url() ); ?>"><?php esc_html_e( 'Data sources & licences', 'maroon-horizon-smart-firewall' ); ?></a>
    </p>
  <?php endif; ?>
</div>

<?php
});