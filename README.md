# MH Smart Firewall – Security, Malware Scanner & Login Protection

Firewall, malware scan & IP blocking for WordPress, with Quick Scan Overall Security Rating, hardening, quarantine and integrity checks.

**Free WordPress security plugin by [Maroon Horizon Ltd](https://mh.ie)** (formerly *Maroon Horizon Smart Firewall*). This repository holds the same code as the free plugin on WordPress.org – every release here is the WordPress.org release, file for file.

- WordPress.org: https://wordpress.org/plugins/maroon-horizon-smart-firewall/
- Website: https://mh.ie/maroon-horizon-smart-firewall/
- Requires WordPress 6.0+ and PHP 7.4+ · tested up to WordPress 7.1

## What you get in the free plugin (local-only)

- Advanced Security Check (Quick Scan) with an Overall Security Rating and easy-to-follow explanations – the free version can reach 100/100 on its own.
- Manual IP blocking and IP management (server rule in .htaccess plus the WordPress firewall; automatic Cloudflare support).
- Login Guard (login protection): 5 failed logins lock that address out for 30 minutes, with a safe e-mail unlock link for administrators.
- Security patch toggles for common hardening actions (hide the WordPress version, prevent directory browsing, disable XML-RPC, protect uploads, fix file permissions).
- Malware scanning of uploads and theme directories using local pattern detection (no external signatures).
- Quarantine management (restore / delete) – quarantined files are stored encoded, so they can't run.
- Quick file integrity check of WordPress core files against the official WordPress.org checksums.
- Recent activity log (the last 200 security events) and automatic clean-up, so the plugin never fills your hosting.

Malware scans run on your server and scanned file contents are not uploaded. Outbound requests (if any) are listed under "External services" in [readme.txt](readme.txt).

## Install

Install it from WordPress: **Plugins → Add New** → search "MH Smart Firewall" → Install → Activate. Updates come from WordPress.org.

## PRO

The commercial PRO plugin (daily signed Threat Feed curated by Maroon Horizon AI, malware signatures, more patches) is a separate product and is not part of this repository: https://mh.ie/maroon-horizon-smart-firewall/

## Support

Questions and bug reports: the [WordPress.org support forum](https://wordpress.org/support/plugin/maroon-horizon-smart-firewall/).

## Licence

GPLv2 or later – see [LICENSE.txt](LICENSE.txt). Included: the Freemius SDK (GPL, `vendor/freemius`) and the Manrope font (SIL Open Font Licence, `admin/fonts/OFL.txt`).

© Maroon Horizon Ltd
