<?php
/**
 * Controlli sulla configurazione di WordPress e del server.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Htaccess;
use GRSDigital\Security\Loopback;
use GRSDigital\Security\Salts;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Configurazione".
 */
class Config_Checks {

	/**
	 * Plugin di backup riconosciuti (file principale => nome).
	 *
	 * @var array
	 */
	const BACKUP_PLUGINS = array(
		'updraftplus/updraftplus.php'                     => 'UpdraftPlus',
		'backwpup/backwpup.php'                           => 'BackWPup',
		'duplicator/duplicator.php'                       => 'Duplicator',
		'duplicator-pro/duplicator-pro.php'               => 'Duplicator Pro',
		'all-in-one-wp-migration/all-in-one-wp-migration.php' => 'All-in-One WP Migration',
		'wpvivid-backuprestore/wpvivid-backuprestore.php' => 'WPvivid',
		'backup-backup/backup-backup.php'                 => 'Backup Migration',
		'blogvault-real-time-backup/blogvault.php'        => 'BlogVault',
		'jetpack/jetpack.php'                             => 'Jetpack (VaultPress Backup)',
		'jetpack-backup/jetpack-backup.php'               => 'Jetpack VaultPress Backup',
		'backupbuddy/backupbuddy.php'                     => 'Solid Backups',
		'xcloner-backup-and-restore/xcloner.php'          => 'XCloner',
		'wp-time-capsule/wp-time-capsule.php'             => 'WP Time Capsule',
		'boldgrid-backup/boldgrid-backup.php'             => 'Total Upkeep',
	);

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return array(
			self::file_edit(),
			self::debug_display(),
			self::debug_log(),
			self::salts(),
			self::config_perms(),
			self::https(),
			self::app_passwords(),
			self::core_auto_updates(),
			self::backup(),
			self::db_prefix(),
		);
	}

	/**
	 * Editor di file in bacheca.
	 *
	 * @return array
	 */
	private static function file_edit() {
		$constant = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$applied  = Settings::fix_enabled( 'file_edit' );
		return Scanner::result(
			array(
				'id'           => 'file_edit',
				'category'     => 'config',
				'title'        => __( 'Plugin and theme editor disabled', 'grs-security' ),
				'status'       => ( $constant || $applied ) ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => ( $constant || $applied )
					? __( 'Plugin and theme code cannot be edited from the dashboard.', 'grs-security' )
					: __( 'Anyone who logs in as an administrator can edit the PHP code of plugins and themes from the dashboard: it is the quickest way to install a backdoor.', 'grs-security' ),
				'fix'          => $constant ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $constant,
				'instructions' => __( 'Hides and blocks the plugin and theme file editor. Code changes are made via FTP or a deployment.', 'grs-security' ),
			)
		);
	}

	/**
	 * Errori mostrati ai visitatori.
	 *
	 * @return array
	 */
	private static function debug_display() {
		$debug   = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display = ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY;
		$bad     = $debug && $display;
		return Scanner::result(
			array(
				'id'           => 'debug_display',
				'category'     => 'config',
				'title'        => __( 'PHP errors not visible to visitors', 'grs-security' ),
				'status'       => $bad ? 'warning' : 'ok',
				'weight'       => 2,
				'message'      => $bad
					? __( 'WP_DEBUG is on and errors are shown on pages: they reveal server paths and plugin details.', 'grs-security' )
					: __( 'PHP errors are not shown on pages.', 'grs-security' ),
				'fix'          => $bad ? 'manual' : 'none',
				'instructions' => __( 'In wp-config.php set define( \'WP_DEBUG\', false ); or, if you need debugging, define( \'WP_DEBUG_DISPLAY\', false ); and @ini_set( \'display_errors\', 0 );', 'grs-security' ),
			)
		);
	}

	/**
	 * File debug.log pubblico.
	 *
	 * @return array
	 */
	private static function debug_log() {
		$path = WP_CONTENT_DIR . '/debug.log';
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$path = WP_DEBUG_LOG;
		}
		$inside = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) );
		$status = 'ok';
		$msg    = __( 'No log file reachable from the browser.', 'grs-security' );
		if ( file_exists( $path ) && $inside ) {
			$url      = site_url( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ) );
			$response = Loopback::request( $url, 'GET', array( 'headers' => array( 'Range' => 'bytes=0-200' ) ) );
			$code     = Loopback::code( $response );
			if ( null === $response ) {
				$status = 'unknown';
				$msg    = __( 'A debug.log file exists but it was not possible to check whether it is reachable from the browser.', 'grs-security' );
			} elseif ( in_array( $code, array( 200, 206 ), true ) ) {
				$status = 'critical';
				/* translators: %s: URL */
				$msg = sprintf( __( 'The error log can be read by anyone: %s', 'grs-security' ), $url );
			} else {
				$msg = __( 'A debug.log file exists but it is not reachable from the browser.', 'grs-security' );
			}
		}
		$can_htaccess = Htaccess::supported();
		return Scanner::result(
			array(
				'id'           => 'debug_log',
				'category'     => 'config',
				'title'        => __( 'Error log not public', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $msg,
				'fix'          => 'critical' === $status ? ( $can_htaccess ? 'auto' : 'manual' ) : 'none',
				'fix_applied'  => Settings::fix_enabled( 'htaccess_sensitive' ),
				'recommended'  => 'critical' === $status && $can_htaccess,
				'instructions' => $can_htaccess
					? __( 'Blocks browser access to log files, backups and sensitive files via .htaccess. Also consider moving the log outside the public folder with define( \'WP_DEBUG_LOG\', \'/path/outside/the/site/debug.log\' );', 'grs-security' )
					: __( 'Delete the debug.log file and move the log outside the public folder with define( \'WP_DEBUG_LOG\', \'/path/outside/the/site/debug.log\' ); or ask the hosting to block .log files.', 'grs-security' ),
			)
		);
	}

	/**
	 * Chiavi di sicurezza.
	 *
	 * @return array
	 */
	private static function salts() {
		$state = Salts::status();
		$can   = Salts::can_regenerate();
		$ok    = 'ok' === $state['status'];
		return Scanner::result(
			array(
				'id'           => 'salts',
				'category'     => 'config',
				'title'        => __( 'Strong security keys (SALT)', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $ok
					? __( 'The security keys in wp-config.php are present and unique. You can regenerate them if you suspect a breach: everyone will be logged out.', 'grs-security' )
					/* translators: %s: list of problems */
					: sprintf( __( 'Problems with the security keys: %s.', 'grs-security' ), implode( ', ', $state['problems'] ) ),
				'fix'          => is_wp_error( $can ) ? 'manual' : 'auto',
				'recommended'  => ! $ok && ! is_wp_error( $can ),
				'instructions' => is_wp_error( $can )
					? $can->get_error_message() . ' ' . __( 'Generate new keys at https://api.wordpress.org/secret-key/1.1/salt/ and replace them in wp-config.php.', 'grs-security' )
					: __( 'Generates new random keys and writes them to wp-config.php with a syntax check before saving. All users, including you, will be logged out. Compatible GRS plugins (such as GRS SMTP 1.0.1 or later) automatically update their encrypted data; other plugins that encrypt data with the site keys may require you to re-enter passwords or API keys.', 'grs-security' ),
			)
		);
	}

	/**
	 * Permessi di wp-config.php.
	 *
	 * @return array
	 */
	private static function config_perms() {
		$path = Salts::config_path();
		if ( '' === $path ) {
			return Scanner::result(
				array(
					'id'       => 'config_perms',
					'category' => 'config',
					'title'    => __( 'wp-config.php permissions', 'grs-security' ),
					'status'   => 'unknown',
					'message'  => __( 'wp-config.php not found in the standard locations.', 'grs-security' ),
				)
			);
		}
		$perms = fileperms( $path ) & 0777;
		$world = ( $perms & 0002 ) || ( $perms & 0020 );
		return Scanner::result(
			array(
				'id'           => 'config_perms',
				'category'     => 'config',
				'title'        => __( 'wp-config.php permissions', 'grs-security' ),
				'status'       => $world ? 'critical' : 'ok',
				'weight'       => 2,
				/* translators: %s: octal permissions */
				'message'      => sprintf( __( 'Current permissions: %s.', 'grs-security' ), sprintf( '%04o', $perms ) ) . ( $world ? ' ' . __( 'The file is writable by other users on the server.', 'grs-security' ) : '' ),
				'fix'          => $world ? 'manual' : 'none',
				'instructions' => __( 'Set the wp-config.php permissions to 640 or 600 from the hosting file manager or via FTP. If the site does not load after the change, go back to 644 and ask the hosting for the correct value.', 'grs-security' ),
			)
		);
	}

	/**
	 * HTTPS.
	 *
	 * @return array
	 */
	private static function https() {
		$home  = 0 === strpos( home_url(), 'https://' );
		$admin = 0 === strpos( site_url(), 'https://' );
		$ok    = $home && $admin;
		return Scanner::result(
			array(
				'id'           => 'https',
				'category'     => 'config',
				'title'        => __( 'Site on HTTPS', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $ok
					? __( 'The site address and the WordPress address use HTTPS.', 'grs-security' )
					: __( 'The site does not use HTTPS: passwords and login cookies travel unencrypted.', 'grs-security' ),
				'fix'          => $ok ? 'none' : 'manual',
				'instructions' => __( 'Enable an SSL certificate (Let\'s Encrypt is free on almost every hosting), then in Settings > General change both addresses to https:// and set up the redirect from HTTP to HTTPS. After the switch you can enable the HSTS header from here.', 'grs-security' ),
				'link'         => admin_url( 'options-general.php' ),
			)
		);
	}

	/**
	 * Application Passwords.
	 *
	 * @return array
	 */
	private static function app_passwords() {
		$applied = Settings::fix_enabled( 'app_passwords' );
		$in_use  = false;
		if ( ! $applied && class_exists( 'WP_Application_Passwords' ) ) {
			$users  = get_users(
				array(
					'meta_key' => \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- controllo una tantum durante la scansione.
					'number'   => 1,
					'fields'   => 'ID',
				)
			);
			$in_use = ! empty( $users );
		}
		$available = $applied ? false : wp_is_application_passwords_available();
		return Scanner::result(
			array(
				'id'           => 'app_passwords',
				'category'     => 'config',
				'title'        => __( 'Application Passwords only if needed', 'grs-security' ),
				'status'       => ( ! $available || $in_use ) ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $in_use
					? __( 'Application Passwords are used by at least one user (apps or external integrations): leave them enabled.', 'grs-security' )
					: ( $available ? __( 'Application Passwords are enabled but nobody uses them: they are an extra way into the site API.', 'grs-security' ) : __( 'Application Passwords are disabled.', 'grs-security' ) ),
				'fix'          => $in_use ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $in_use && $available,
				'instructions' => __( 'Disables Application Passwords. Re-enable them if you connect mobile apps, Zapier or other services that need them.', 'grs-security' ),
			)
		);
	}

	/**
	 * Aggiornamenti automatici minori del core.
	 *
	 * @return array
	 */
	private static function core_auto_updates() {
		$applied = Settings::fix_enabled( 'core_minor_updates' );
		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php';
		}
		$disabled_all = ( new \WP_Automatic_Updater() )->is_disabled();
		$constant     = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';
		$minor_off    = ( false === $constant );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.
		$filter_on = (bool) apply_filters( 'allow_minor_auto_core_updates', ! $minor_off );
		$ok        = ! $disabled_all && $filter_on;
		return Scanner::result(
			array(
				'id'           => 'core_auto_updates',
				'category'     => 'config',
				'title'        => __( 'Automatic core security updates', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $ok
					? __( 'WordPress installs minor (security) updates on its own.', 'grs-security' )
					: ( $disabled_all ? __( 'All automatic updates are disabled (AUTOMATIC_UPDATER_DISABLED or DISALLOW_FILE_MODS).', 'grs-security' ) : __( 'Automatic minor core updates are disabled.', 'grs-security' ) ),
				'fix'          => $disabled_all ? 'manual' : ( $ok && ! $applied ? 'none' : 'auto' ),
				'fix_applied'  => $applied,
				'recommended'  => ! $ok && ! $disabled_all,
				'instructions' => $disabled_all
					? __( 'Remove AUTOMATIC_UPDATER_DISABLED (or DISALLOW_FILE_MODS, if not needed) from wp-config.php, or make sure you update WordPress manually within a few days of each release.', 'grs-security' )
					: __( 'Re-enables automatic minor core updates (e.g. 7.1.2 → 7.1.3), which contain the security fixes.', 'grs-security' ),
			)
		);
	}

	/**
	 * Plugin di backup.
	 *
	 * @return array
	 */
	private static function backup() {
		$found = array();
		foreach ( self::BACKUP_PLUGINS as $file => $name ) {
			if ( is_plugin_active( $file ) ) {
				$found[] = $name;
			}
		}
		return Scanner::result(
			array(
				'id'           => 'backup',
				'category'     => 'config',
				'title'        => __( 'Site backup', 'grs-security' ),
				'status'       => $found ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $found
					/* translators: %s: plugin */
					? sprintf( __( 'Backup plugin active: %s. Make sure backups are stored off the server (cloud, external storage).', 'grs-security' ), implode( ', ', $found ) )
					: __( 'No known backup plugin. If the hosting already runs daily backups, you can ignore this check.', 'grs-security' ),
				'fix'          => $found ? 'none' : 'manual',
				'instructions' => __( 'Backups are the only protection that always works. Check with the hosting whether it runs daily backups kept for at least 14 days, or install a plugin such as UpdraftPlus saving to the cloud. Test a restore at least once.', 'grs-security' ),
			)
		);
	}

	/**
	 * Prefisso tabelle (solo informativo).
	 *
	 * @return array
	 */
	private static function db_prefix() {
		global $wpdb;
		$default = 'wp_' === $wpdb->prefix;
		return Scanner::result(
			array(
				'id'       => 'db_prefix',
				'category' => 'config',
				'title'    => __( 'Database table prefix', 'grs-security' ),
				'status'   => 'info',
				'optional' => true,
				'message'  => $default
					? __( 'The prefix is the default "wp_". Changing it on an existing site is risky and brings little benefit: no action needed.', 'grs-security' )
					: __( 'The table prefix is not the default one.', 'grs-security' ),
			)
		);
	}
}
