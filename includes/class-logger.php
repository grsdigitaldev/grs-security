<?php
/**
 * Registro attività di sicurezza.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- tabella custom del plugin, nessuna API WP equivalente.

/**
 * Scrive e legge il registro eventi.
 */
class Logger {

	const SEVERITIES = array( 'info', 'warning', 'critical' );

	/**
	 * Righe massime conservate (protezione da riempimento sotto attacco).
	 */
	const MAX_ROWS = 20000;

	/**
	 * Registra un evento.
	 *
	 * @param string $event    Codice evento (es. login_failed_lockout).
	 * @param string $severity info|warning|critical.
	 * @param string $message  Messaggio leggibile.
	 * @param array  $args     user_id, username, context (array).
	 * @return int Id riga o 0.
	 */
	public static function log( $event, $severity, $message, array $args = array() ) {
		global $wpdb;

		if ( (int) get_option( Database::OPTION, 0 ) < 1 ) {
			return 0;
		}
		$severity = in_array( $severity, self::SEVERITIES, true ) ? $severity : 'info';
		$user_id  = isset( $args['user_id'] ) ? (int) $args['user_id'] : 0;
		$username = isset( $args['username'] ) ? (string) $args['username'] : '';
		$context  = isset( $args['context'] ) && is_array( $args['context'] ) ? wp_json_encode( $args['context'] ) : null;
		$ip       = array_key_exists( 'ip', $args ) ? (string) $args['ip'] : Ip::current();

		$ok = $wpdb->insert(
			Database::log_table(),
			array(
				'created_at' => current_time( 'mysql', true ),
				'event'      => substr( sanitize_key( $event ), 0, 64 ),
				'severity'   => $severity,
				'user_id'    => $user_id,
				'username'   => substr( $username, 0, 191 ),
				'ip'         => substr( $ip, 0, 45 ),
				'message'    => $message,
				'context'    => $context,
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s' )
		);

		$id = $ok ? (int) $wpdb->insert_id : 0;

		if ( $id ) {
			/**
			 * Evento di sicurezza registrato.
			 *
			 * @param int    $id       Id riga.
			 * @param string $event    Codice evento.
			 * @param string $severity Gravità.
			 * @param string $message  Messaggio.
			 * @param array  $args     Argomenti.
			 */
			do_action( 'grs_security_event_logged', $id, $event, $severity, $message, $args );
		}
		return $id;
	}

	/**
	 * Elimina le righe più vecchie della conservazione e oltre il massimo.
	 *
	 * @return void
	 */
	public static function purge() {
		global $wpdb;
		$table = Database::log_table();
		$days  = (int) Settings::get( 'log_retention', 90 );
		$limit = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE created_at < %s", $limit ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.

		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		if ( $count > self::MAX_ROWS ) {
			$threshold = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} ORDER BY id DESC LIMIT 1 OFFSET %d", self::MAX_ROWS ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
			if ( $threshold > 0 ) {
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE id <= %d", $threshold ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
			}
		}
	}

	/**
	 * Righe del registro con filtri e paginazione.
	 *
	 * @param array $args severity, event, per_page, page.
	 * @return array { rows: array, total: int }
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$table    = Database::log_table();
		$where    = array( '1=1' );
		$params   = array();
		$per_page = isset( $args['per_page'] ) ? max( 1, (int) $args['per_page'] ) : 50;
		$page     = isset( $args['page'] ) ? max( 1, (int) $args['page'] ) : 1;

		if ( ! empty( $args['severity'] ) && in_array( $args['severity'], self::SEVERITIES, true ) ) {
			$where[]  = 'severity = %s';
			$params[] = $args['severity'];
		}
		if ( ! empty( $args['event'] ) ) {
			$where[]  = 'event = %s';
			$params[] = sanitize_key( $args['event'] );
		}
		if ( ! empty( $args['user_id'] ) ) {
			$where[]  = 'user_id = %d';
			$params[] = (int) $args['user_id'];
		}

		$where_sql = implode( ' AND ', $where );
		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
		$rows_sql  = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d";

		$total = (int) ( $params ? $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ) : $wpdb->get_var( $count_sql ) ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- query composta con segnaposto.
		$rows  = $wpdb->get_results( $wpdb->prepare( $rows_sql, array_merge( $params, array( $per_page, ( $page - 1 ) * $per_page ) ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- query composta con segnaposto.

		return array(
			'rows'  => is_array( $rows ) ? $rows : array(),
			'total' => $total,
		);
	}

	/**
	 * Codici evento presenti nel registro (per il filtro).
	 *
	 * @return string[]
	 */
	public static function events() {
		global $wpdb;
		$table = Database::log_table();
		$rows  = $wpdb->get_col( "SELECT DISTINCT event FROM {$table} ORDER BY event" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		return is_array( $rows ) ? $rows : array();
	}
}
