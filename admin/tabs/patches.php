<?php

if ( !defined( 'ABSPATH' ) ) {
    exit;
}
call_user_func( static function () {
    $patch_manager = new SFAIS_Patch_Manager();
    $mhsf_entitled = false;
    $mhsf_outdated_wpcontent = false;
    $mhsf_outdated_ssl = false;
    $mhsf_lapsed_revert = false;
    ?>

<h2>Security Patches</h2>
<p class="sfais-kicker" style="max-width:700px;margin-top:6px;">
  Apply or revert individual hardening patches to strengthen your WordPress installation.
</p>

<!-- AJAX notices (no page refresh) -->
<div id="sfais-patches-notice" style="margin: 12px 0;"></div>

<?php 
    /**
     * Helper: render a patch card with an AJAX form.
     *
     * @param array $args
     */
    /**
     * Allowed HTML for patch descriptions and extra blocks (admin-only UI).
     * Even when markup is internally generated, WP.org reviewers and Plugin Check
     * expect output to be sanitized with an allowlist.
     */
    $sfais_allowed_patch_desc_html = array(
        'br'     => array(),
        'code'   => array(),
        'strong' => array(),
        'em'     => array(),
        'span'   => array(
            'class' => true,
            'style' => true,
        ),
        'a'      => array(
            'href'   => true,
            'target' => true,
            'rel'    => true,
        ),
    );
    $sfais_allowed_patch_extra_html = array(
        'div'    => array(
            'class' => true,
            'id'    => true,
            'style' => true,
        ),
        'br'     => array(),
        'code'   => array(),
        'strong' => array(),
        'em'     => array(),
        'span'   => array(
            'class' => true,
            'id'    => true,
            'style' => true,
        ),
        'a'      => array(
            'href'   => true,
            'target' => true,
            'rel'    => true,
        ),
    );
    # Dynamic location hints (do not assume default wp-content paths).
    $mhsf_uploads_info = wp_upload_dir( null, false );
    $mhsf_uploads_url_path = '';
    if ( is_array( $mhsf_uploads_info ) && !empty( $mhsf_uploads_info['baseurl'] ) ) {
        $mhsf_uploads_url_path = (string) wp_parse_url( (string) $mhsf_uploads_info['baseurl'], PHP_URL_PATH );
    }
    $mhsf_uploads_url_path = ( $mhsf_uploads_url_path ? trailingslashit( $mhsf_uploads_url_path ) : '' );
    $mhsf_uploads_code = ( $mhsf_uploads_url_path ? '<code>' . esc_html( $mhsf_uploads_url_path ) . '</code>' : '<code>' . esc_html__( 'uploads directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    $mhsf_content_uri = (string) content_url( '/' );
    $mhsf_content_url_path = ( $mhsf_content_uri ? (string) wp_parse_url( $mhsf_content_uri, PHP_URL_PATH ) : '' );
    $mhsf_content_url_path = ( $mhsf_content_url_path ? trailingslashit( $mhsf_content_url_path ) : '' );
    $mhsf_content_code = ( $mhsf_content_url_path ? '<code>' . esc_html( $mhsf_content_url_path ) . '</code>' : '<code>' . esc_html__( 'content directory', 'maroon-horizon-smart-firewall' ) . '</code>' );
    $render_patch_card = function ( $args ) use(
        $mhsf_entitled,
        $mhsf_lapsed_revert,
        $sfais_allowed_patch_desc_html,
        $sfais_allowed_patch_extra_html
    ) {
        $title = $args['title'] ?? '';
        $desc = $args['desc'] ?? '';
        $icon = $args['icon'] ?? 'dashicons-shield-alt';
        $icon_color = $args['icon_color'] ?? '#1976d2';
        $patch_key = $args['patch_key'] ?? '';
        $opt_key = $args['opt_key'] ?? '';
        $is_pro_only = !empty( $args['pro_only'] );
        $extra_html = $args['extra_html'] ?? '';
        $active = ( $opt_key ? (bool) get_option( $opt_key ) : false );
        $wrap_classes = 'sfais-card mhsf-patch-card' . (( $is_pro_only && !$mhsf_entitled ? ' sfais-pro-card' : '' ));
        echo '<div class="' . esc_attr( $wrap_classes ) . '">';
        echo '  <h3 style="display:flex;align-items:center;gap:8px;">';
        echo '    <span class="dashicons ' . esc_attr( $icon ) . '" style="color:' . esc_attr( $icon_color ) . ';font-size:20px;"></span>';
        echo '    ' . esc_html( $title );
        echo '  </h3>';
        echo '  <p>' . wp_kses( (string) $desc, $sfais_allowed_patch_desc_html ) . '</p>';
        if ( !empty( $extra_html ) ) {
            echo wp_kses( (string) $extra_html, $sfais_allowed_patch_extra_html );
        }
        // 1.8.13: licence ended while the patch is on - its rules stay, so it can still be reverted (never applied)
        $lapsed = $is_pro_only && !$mhsf_entitled && $mhsf_lapsed_revert && $active;
        if ( $lapsed ) {
            echo '  <div class="mhsf-lapsed-note">' . esc_html__( 'Active - PRO licence needed to change; you can remove it.', 'maroon-horizon-smart-firewall' ) . '</div>';
        }
        if ( $is_pro_only && !$mhsf_entitled && !$lapsed ) {
            echo '  <span class="mhsf-lock"><span class="dashicons dashicons-lock" aria-hidden="true" style="font-size:15px;width:15px;height:15px;vertical-align:-2px;"></span> ' . esc_html__( 'Available in PRO', 'maroon-horizon-smart-firewall' ) . '</span>';
            echo '</div>';
            return;
        }
        echo '  <form method="post" action="" class="sfais-patch-form" data-patch="' . esc_attr( $patch_key ) . '" data-opt="' . esc_attr( $opt_key ) . '">';
        wp_nonce_field( 'sfais_patch_action_verify', 'sfais_patch_nonce' );
        echo '    <input type="hidden" name="sfais_active_tab" value="patches">';
        echo '    <input type="hidden" name="sfais_patch" value="' . esc_attr( $patch_key ) . '">';
        // Button + status
        // 1.8.7: one switch per patch (same button + AJAX as before, drawn as a switch; its text stays for screen readers)
        // 1.8.17: show the REAL state - "Fix File Permissions" stayed "Active" while wp-config.php was 0644 again
        $drift = ( $active && 'permissions' === $patch_key && function_exists( 'mhsf_permissions_drift' ) ? mhsf_permissions_drift() : array() );
        if ( $active && $drift ) {
            $drift_txt = array();
            foreach ( $drift as $drift_file => $drift_perm ) {
                $drift_txt[] = $drift_file . ' ' . $drift_perm;
            }
            /* translators: %s: files with their permissions, e.g. "wp-config.php 0644" */
            echo '    <span class="sfais-status is-on is-drift" data-status>' . esc_html( sprintf( __( 'Active - but writable again (%s): apply again', 'maroon-horizon-smart-firewall' ), implode( ', ', $drift_txt ) ) ) . '</span>';
            echo '    <button type="submit" class="mhsf-switch" role="switch" aria-checked="true" aria-label="' . esc_attr( $title ) . '" name="sfais_patch_action" value="revert">🔄 Revert Patch</button>';
            echo '    <button type="submit" class="button button-small mhsf-reapply" name="sfais_reapply" value="apply">' . esc_html__( 'Apply again', 'maroon-horizon-smart-firewall' ) . '</button>';
        } elseif ( $active ) {
            echo '    <span class="sfais-status is-on" data-status>Active</span>';
            echo '    <button type="submit" class="mhsf-switch" role="switch" aria-checked="true" aria-label="' . esc_attr( $title ) . '" name="sfais_patch_action" value="revert">🔄 Revert Patch</button>';
        } else {
            echo '    <span class="sfais-status" data-status>Inactive</span>';
            echo '    <button type="submit" class="mhsf-switch" role="switch" aria-checked="false" aria-label="' . esc_attr( $title ) . '" name="sfais_patch_action" value="apply">🛡️ Apply Patch</button>';
        }
        // Inline spinner placeholder (JS will toggle)
        echo '    <span class="sfais-patch-spinner" data-spinner style="display:none;margin-left:10px;">Working...</span>';
        echo '  </form>';
        echo '</div>';
    };
    ?>

<?php 
    // ✅ FREE patches
    $render_patch_card( [
        'title'      => 'Hide WordPress Version Info',
        'desc'       => 'Hides your WordPress version from attackers: removes the <code>&lt;meta name="generator"&gt;</code> tag and the generator line in feeds, and replaces the version in script and style links (<code>?ver=</code>) with a short code that still changes after updates. <code>readme.html</code> is a WordPress core file; this patch does not delete it.<br>You can verify this effect in the <strong>Dashboard</strong> → “Hide WordPress Version Info”.',
        'icon'       => 'dashicons-shield-alt',
        'icon_color' => '#1976d2',
        'patch_key'  => 'versioninfo',
        'opt_key'    => 'sfais_patch_versioninfo',
    ] );
    /**
     * Prevent Directory Browsing – show last report inline (credible per-directory output)
     */
    $dirlisting_report = get_option( 'sfais_patch_dirlisting_last_report' );
    $dirlisting_extra = '';
    if ( is_array( $dirlisting_report ) && !empty( $dirlisting_report['results'] ) && is_array( $dirlisting_report['results'] ) ) {
        $dirlisting_extra .= '<div class="mhsf-sub" style="margin-top:10px;padding:10px;border:1px solid;border-radius:10px;">';
        $dirlisting_extra .= '<div style="font-weight:600;margin-bottom:6px;">Last check:</div>';
        $dirlisting_extra .= '<div style="font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;font-size:12.5px;line-height:1.6;">';
        foreach ( $dirlisting_report['results'] as $row ) {
            if ( !is_array( $row ) ) {
                continue;
            }
            $dir = ( isset( $row['dir'] ) ? $row['dir'] : '' );
            $detail = ( isset( $row['detail'] ) ? $row['detail'] : '' );
            if ( $dir === '' || $detail === '' ) {
                continue;
            }
            $dirlisting_extra .= esc_html( $dir ) . ' — ' . esc_html( $detail ) . '<br>';
        }
        $dirlisting_extra .= '</div>';
        $dirlisting_extra .= '</div>';
    }
    $render_patch_card( [
        'title'      => 'Prevent Directory Browsing',
        'desc'       => 'Adds a minimal index file to 4 top-level folders only (wp-content, uploads, themes, plugins), so their file lists can’t be browsed. Subfolders are not covered. This patch does not modify <code>.htaccess</code> and never overwrites existing index files.',
        'icon'       => 'dashicons-visibility',
        'icon_color' => '#ff6f00',
        'patch_key'  => 'dirlisting',
        'opt_key'    => 'sfais_patch_dirlisting',
        'extra_html' => $dirlisting_extra,
    ] );
    $render_patch_card( [
        'title'      => 'Disable XML-RPC',
        'desc'       => 'Disables <code>xmlrpc.php</code> (it answers 403 Forbidden) and removes the X-Pingback header and the RSD link, to prevent botnets and brute-force attacks via remote WordPress API calls. Most sites don’t need XML-RPC; disabling it reduces automated login abuse.<br><span class="mhsf-muted">Note: Jetpack and the WordPress mobile app need XML-RPC.</span>',
        'icon'       => 'dashicons-networking',
        'icon_color' => '#0288d1',
        'patch_key'  => 'xmlrpc',
        'opt_key'    => 'sfais_patch_xmlrpc',
    ] );
    // 1.8.13: rules written by an older version (mod_rewrite) - switching the patch off and on once replaces them
    $mhsf_outdated_note = '<div style="margin-top:8px;"><strong>' . esc_html__( 'Rules from an earlier version are still in use. Switch this patch off and on once to update them.', 'maroon-horizon-smart-firewall' ) . '</strong></div>';
    $render_patch_card( [
        'extra_html' => ( method_exists( $patch_manager, 'uploads_rules_outdated' ) && $patch_manager->uploads_rules_outdated() ? $mhsf_outdated_note : '' ),
        'title'      => 'Protect Uploads (Block PHP)',
        'desc'       => 'Adds a safe, marker-based <code>.htaccess</code> rule inside your ' . $mhsf_uploads_code . ' directory to block PHP execution and disable directory listing (Apache/LiteSpeed).<br>
    <span class="mhsf-muted">
      Note: Nginx servers ignore <code>.htaccess</code>. There the patch is not applied and shows the line to give your host.
    </span><br>
    <span class="mhsf-muted">
      Optional hardening: To disable WordPress core/plugin/theme installs and updates, set <code>DISALLOW_FILE_MODS</code> in <code>wp-config.php</code>.
    </span>',
        'icon'       => 'dashicons-upload',
        'icon_color' => '#43a047',
        'patch_key'  => 'filemods',
        'opt_key'    => 'sfais_patch_filemods',
    ] );
    /**
     * Fix File Permissions – DO NOT show last run report inline (per your request)
     */
    $render_patch_card( [
        'title'      => 'Fix File Permissions',
        'desc'       => 'Safely hardens permissions for only two core files: <code>wp-config.php</code> (to 0440) and the root <code>.htaccess</code> (to 0444, if present). It only removes access, so a stricter setting such as 0400 is kept. This patch is non-recursive and does not touch plugins, themes, uploads, or backups.<br>
    It creates a small log file so you can revert to the previous permissions later. On servers without <code>.htaccess</code> (e.g., many Nginx setups), that file will be skipped automatically. A <code>wp-config.php</code> one folder above WordPress is not changed.',
        'icon'       => 'dashicons-admin-tools',
        'icon_color' => '#9c27b0',
        'patch_key'  => 'permissions',
        'opt_key'    => 'sfais_patch_permissions',
    ] );
    // ✅ Premium patches (AJAX works when Premium package is active; otherwise disabled card)
    $render_patch_card( [
        'title'      => 'Disable File Editing in Admin',
        'desc'       => 'Disables the built-in Theme and Plugin Editor to prevent malicious code injection via dashboard access.',
        'icon'       => 'dashicons-lock',
        'icon_color' => '#1565c0',
        'patch_key'  => 'fileedit',
        'opt_key'    => 'sfais_patch_fileedit',
        'pro_only'   => true,
    ] );
    $render_patch_card( [
        'extra_html' => ( $mhsf_outdated_wpcontent ? $mhsf_outdated_note : '' ),
        'title'      => 'Block PHP Execution in wp-content',
        'desc'       => 'Stops any PHP file from executing inside ' . $mhsf_content_code . ' (outside plugins, themes and mu-plugins) with a rule in <code>.htaccess</code> (Apache/LiteSpeed). The patch tests itself; on servers that ignore <code>.htaccess</code> (e.g. Nginx) it is not applied and shows the line to give your host.',
        'icon'       => 'dashicons-media-code',
        'icon_color' => '#ef6c00',
        'patch_key'  => 'php_wpcontent',
        'opt_key'    => 'sfais_patch_php_wpcontent',
        'pro_only'   => true,
    ] );
    $render_patch_card( [
        'extra_html' => ( $mhsf_outdated_ssl ? $mhsf_outdated_note : '' ),
        'title'      => 'Force HTTPS (SSL)',
        'desc'       => 'Redirects HTTP to HTTPS, even if your hosting already redirects to SSL. This closes edge cases where the HTTP version can still be reached via old links, proxies or misconfigurations, keeps a single canonical <code>https://</code> URL for SEO, and acts as a safety net if hosting-level redirects are removed or stop working. Uses <code>.htaccess</code> when possible (every request); the PHP fallback covers front-end pages, wp-admin and login, but not AJAX, cron, REST API or XML-RPC requests. It is only switched on after your site answered on <code>https://</code> with a valid certificate.',
        'icon'       => 'dashicons-lock',
        'icon_color' => '#43a047',
        'patch_key'  => 'force_ssl',
        'opt_key'    => 'sfais_patch_force_ssl',
        'pro_only'   => true,
    ] );
    $render_patch_card( [
        'title'      => 'Protect wp-config.php',
        'desc'       => 'Blocks direct external access to <code>wp-config.php</code> using dedicated rules in <code>.htaccess</code> when possible, with a PHP-level fallback guard on servers where .htaccess cannot be used.',
        'icon'       => 'dashicons-admin-network',
        'icon_color' => '#512da8',
        'patch_key'  => 'wpconfig',
        'opt_key'    => 'sfais_patch_wpconfig',
        'pro_only'   => true,
    ] );
    $render_patch_card( [
        'title'      => 'Hide Author Enumeration',
        'desc'       => 'Prevents bots from discovering valid usernames via <code>?author=1</code> style URLs, author archive pages, the REST API (<code>/wp-json/wp/v2/users</code>), the users sitemap and oEmbed data. When enabled, author archive requests return a clean 404 instead of exposing usernames, reducing the attack surface for targeted brute-force attacks. Note: multi-author sites lose their author archive pages.',
        'icon'       => 'dashicons-admin-users',
        'icon_color' => '#c2185b',
        'patch_key'  => 'author_enum',
        'opt_key'    => 'sfais_patch_author_enum',
        'pro_only'   => true,
    ] );
} );