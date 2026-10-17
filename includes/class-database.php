<?php
/**
 * Tabelle custom: registro eventi e tentativi di login per IP.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Schema del database.
 */
class Database {

	const DB_VERSION = 1;
	const OPTION     = 'grs_security_db_version';

	/**
	 * Nome della tabella del registro.
	 *
	 * @return string
	 */
	public static function log_table() {
		global $wpdb;
		return $wpdb->prefix . 'grs_security_log';
	}

	/**
	 * Nome della tabella dei tentativi di login.
	 *
	 * @return string
	 */
	public static function lockout_table() {
		global $wpdb;
		return $wpdb->prefix . 'grs_security_lockouts';
	}

	/**
	 * Crea o aggiorna le tabelle se la versione schema è cambiata.
	 *
	 * @return void
	 */
	public static function maybe_upgrade() {
		if ( (int) get_option( self::OPTION, 0 ) >= self::DB_VERSION ) {
			return;
		}
		self::install();
	}

	/**
	 * Crea le tabelle con dbDelta.
	 *
	 * @return void
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset = $wpdb->get_charset_collate();
		$log     = self::log_table();
		$lock    = self::lockout_table();

		dbDelta(
			"CREATE TABLE {$log} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL,
				event varchar(64) NOT NULL,
				severity varchar(16) NOT NULL DEFAULT 'info',
				user_id bigint(20) unsigned NOT NULL DEFAULT 0,
				username varchar(191) NOT NULL DEFAULT '',
				ip varchar(45) NOT NULL DEFAULT '',
				message text NOT NULL,
				context longtext NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY event (event),
				KEY severity (severity),
				KEY user_id (user_id)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$lock} (
				ip varchar(45) NOT NULL,
				attempts int(10) unsigned NOT NULL DEFAULT 0,
				first_attempt int(10) unsigned NOT NULL DEFAULT 0,
				locked_until int(10) unsigned NOT NULL DEFAULT 0,
				lockouts int(10) unsigned NOT NULL DEFAULT 0,
				last_username varchar(191) NOT NULL DEFAULT '',
				updated_at int(10) unsigned NOT NULL DEFAULT 0,
				PRIMARY KEY  (ip),
				KEY locked_until (locked_until)
			) {$charset};"
		);

		update_option( self::OPTION, self::DB_VERSION, true );
	}
}
