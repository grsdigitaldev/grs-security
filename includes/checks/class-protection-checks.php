<?php
/**
 * Controlli sulle protezioni attive del plugin e sul monitoraggio.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Integrity;
use GRSDigital\Security\Ip;
use GRSDigital\Security\Login_Url;
use GRSDigital\Security\Plugin;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Protezioni attive e monitoraggio".
 */
class Protection_Checks {

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		return array(
			self::login_guard(),
			self::ip_source(),
			self::firewall(),
			self::integrity_enabled(),
			self::integrity_results(),
			self::login_url(),
			self::alerts(),
		);
	}

	/**
	 * Limite tentativi di login.
	 *
	 * @return array
	 */
	private static function login_guard() {
		$applied = Settings::fix_enabled( 'login_guard' );
		return Scanner::result(
			array(
				'id'           => 'login_guard',
				'category'     => 'monitoring',
				'title'        => __( 'Login attempt limit', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $applied
					/* translators: 1: attempts, 2: minutes */
					? sprintf( __( 'After %1$d failed attempts the IP is blocked for %2$d minutes (the block doubles if the attack continues).', 'grs-security' ), (int) Settings::get( 'login_max_attempts' ), (int) Settings::get( 'login_lockout' ) )
					: __( 'No limit on login attempts: a bot can try passwords nonstop.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Temporarily blocks IPs that enter the wrong password too many times (also via XML-RPC and Application Passwords). You can set trusted IPs in the settings.', 'grs-security' ),
			)
		);
	}

	/**
	 * Sorgente dell'IP coerente con proxy/CDN.
	 *
	 * @return array
	 */
	private static function ip_source() {
		$source = (string) Settings::get( 'ip_source', 'REMOTE_ADDR' );
		$cf     = '' !== Ip::from_server( 'HTTP_CF_CONNECTING_IP' );
		$xff    = '' !== Ip::from_server( 'HTTP_X_FORWARDED_FOR' );
		$status = 'ok';
		$msg    = __( 'The visitor IP address source matches the server configuration.', 'grs-security' );
		if ( 'REMOTE_ADDR' === $source && $cf ) {
			$status = 'warning';
			$msg    = __( 'The site seems to be behind Cloudflare but the IP is read from REMOTE_ADDR: all visitors appear with the Cloudflare IP and a block could hit everyone.', 'grs-security' );
		} elseif ( 'REMOTE_ADDR' === $source && $xff ) {
			$status = 'warning';
			$msg    = __( 'The request goes through a proxy (X-Forwarded-For header present): check the IP source in the settings.', 'grs-security' );
		} elseif ( 'REMOTE_ADDR' !== $source && '' === Ip::from_server( $source ) ) {
			$status = 'warning';
			$msg    = __( 'The configured IP source is not present in this request: REMOTE_ADDR is used.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'ip_source',
				'category'     => 'monitoring',
				'title'        => __( 'Correct IP detection', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'In GRS DEVs > Security, Settings tab, choose the correct IP source (Cloudflare, proxy or direct connection). Use a proxy header only if the site really is behind that proxy: otherwise the IP can be spoofed.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ),
			)
		);
	}

	/**
	 * Firewall applicativo.
	 *
	 * @return array
	 */
	private static function firewall() {
		$applied = Settings::fix_enabled( 'firewall' );
		$mode    = Settings::get( 'firewall_mode', 'block' );
		return Scanner::result(
			array(
				'id'           => 'firewall',
				'category'     => 'monitoring',
				'title'        => __( 'Application firewall', 'grs-security' ),
				'status'       => $applied ? ( 'block' === $mode ? 'ok' : 'warning' ) : 'warning',
				'weight'       => 2,
				'message'      => $applied
					? ( 'block' === $mode ? __( 'The firewall blocks requests with obvious attack patterns.', 'grs-security' ) : __( 'The firewall is in log-only mode: suspicious requests are not blocked.', 'grs-security' ) )
					: __( 'The application firewall is off.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Blocks requests with SQL injection, code injection, directory traversal and known automated scanners. Logged-in users with editing permissions are excluded. It does not replace the hosting or Cloudflare firewall, which stop attacks before they reach WordPress.', 'grs-security' ),
			)
		);
	}

	/**
	 * Scansione di integrità attiva.
	 *
	 * @return array
	 */
	private static function integrity_enabled() {
		$applied = Settings::fix_enabled( 'integrity' );
		return Scanner::result(
			array(
				'id'           => 'integrity',
				'category'     => 'monitoring',
				'title'        => __( 'Daily file check', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $applied
					? __( 'Every day WordPress files and wordpress.org plugins are compared with the originals.', 'grs-security' )
					: __( 'No automatic file check: a malicious change could go unnoticed for months.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Compares core and plugins with the official wordpress.org checksums every day, looks for PHP files in uploads and unknown files in the root folder, and alerts you by email about anything new.', 'grs-security' ),
			)
		);
	}

	/**
	 * Esito dell'ultima scansione di integrità.
	 *
	 * @return array
	 */
	private static function integrity_results() {
		$stored = get_option( Integrity::RESULT_OPTION );
		if ( ! is_array( $stored ) || ! isset( $stored['issues'] ) ) {
			return Scanner::result(
				array(
					'id'       => 'integrity_results',
					'category' => 'monitoring',
					'title'    => __( 'Files intact', 'grs-security' ),
					'status'   => 'unknown',
					'message'  => __( 'The file check has not been run yet.', 'grs-security' ),
					'link'     => Plugin::admin_url( 'integrity' ),
				)
			);
		}
		$count = count( $stored['issues'] );
		return Scanner::result(
			array(
				'id'           => 'integrity_results',
				'category'     => 'monitoring',
				'title'        => __( 'Files intact', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => 0 === $count
					/* translators: %s: date */
					? sprintf( __( 'No anomalies in the last check (%s).', 'grs-security' ), wp_date( Plugin::datetime_format(), (int) $stored['time'] ) )
					/* translators: %d: number */
					: sprintf( _n( '%d anomalous file found in the last check.', '%d anomalous files found in the last check.', $count, 'grs-security' ), $count ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Open the File integrity tab to see the list. Modified core files: reinstall WordPress from Dashboard > Updates > Reinstall. Modified plugins: reinstall them from the official zip. PHP files in uploads or unknown files: if you don\'t recognize them, the site may be compromised; have the case assessed before deleting them.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'integrity' ),
			)
		);
	}

	/**
	 * URL di login personalizzato (opzionale).
	 *
	 * @return array
	 */
	private static function login_url() {
		$active = Login_Url::active();
		return Scanner::result(
			array(
				'id'           => 'login_url',
				'category'     => 'monitoring',
				'title'        => __( 'Custom login address', 'grs-security' ),
				'status'       => $active ? 'ok' : 'info',
				'weight'       => 1,
				'optional'     => true,
				'message'      => $active
					/* translators: %s: URL */
					? sprintf( __( 'The login page is %s; wp-login.php and wp-admin answer "page not found" to visitors.', 'grs-security' ), Login_Url::login_url() )
					: __( 'Optional: moving the login page reduces bot traffic, but does not replace strong passwords and two-step verification.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $active,
				'instructions' => __( 'Enable it from the Settings tab by choosing the address. You will receive the new address by email: save it, because wp-login.php will no longer work. In an emergency, disable it with define( \'GRS_SECURITY_DISABLE_LOGIN_URL\', true ); in wp-config.php.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ) . '#grs-login-url',
			)
		);
	}

	/**
	 * Avvisi email.
	 *
	 * @return array
	 */
	private static function alerts() {
		$on = (bool) Settings::get( 'alerts_enabled', true );
		return Scanner::result(
			array(
				'id'           => 'alerts',
				'category'     => 'monitoring',
				'title'        => __( 'Email alerts enabled', 'grs-security' ),
				'status'       => $on ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $on
					/* translators: %s: email */
					? sprintf( __( 'Important events are reported to %s.', 'grs-security' ), Settings::alert_email() )
					: __( 'Email alerts are disabled: events such as the creation of a new administrator would go unnoticed.', 'grs-security' ),
				'fix'          => $on ? 'none' : 'manual',
				'instructions' => __( 'Enable alerts in GRS DEVs > Security, Settings tab, and make sure the site sends email correctly (an SMTP plugin such as GRS SMTP is recommended).', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ),
			)
		);
	}
}
