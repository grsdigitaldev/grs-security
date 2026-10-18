<?php
/**
 * Privacy: testo suggerito, esportazione e cancellazione dei dati personali del registro.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- tabella custom del plugin.

/**
 * Integrazione con gli strumenti privacy di WordPress.
 */
class Privacy {

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'policy_text' ) );
		add_filter( 'wp_privacy_personal_data_exporters', array( __CLASS__, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( __CLASS__, 'register_eraser' ) );
	}

	/**
	 * Testo suggerito per l'informativa.
	 *
	 * @return void
	 */
	public static function policy_text() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$text = '<p>' . esc_html__( 'To protect the site from unauthorized access and cyber attacks we record, for a limited period, the IP address, the username used in login attempts and some actions performed by registered users (for example logins, changes to roles and settings). This data is processed on the basis of the legitimate interest in site security and is deleted automatically after the configured retention period.', 'grs-security' ) . '</p>';
		wp_add_privacy_policy_content( 'GRS Security', wp_kses_post( $text ) );
	}

	/**
	 * Registra l'exporter.
	 *
	 * @param array $exporters Exporter.
	 * @return array
	 */
	public static function register_exporter( $exporters ) {
		$exporters['grs-security'] = array(
			'exporter_friendly_name' => __( 'Security log (GRS Security)', 'grs-security' ),
			'callback'               => array( __CLASS__, 'export' ),
		);
		return $exporters;
	}

	/**
	 * Registra l'eraser.
	 *
	 * @param array $erasers Eraser.
	 * @return array
	 */
	public static function register_eraser( $erasers ) {
		$erasers['grs-security'] = array(
			'eraser_friendly_name' => __( 'Security log (GRS Security)', 'grs-security' ),
			'callback'             => array( __CLASS__, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Esporta le righe del registro dell'utente.
	 *
	 * @param string $email Email.
	 * @param int    $page  Pagina.
	 * @return array
	 */
	public static function export( $email, $page = 1 ) {
		global $wpdb;
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}
		$table  = Database::log_table();
		$limit  = 200;
		$offset = ( max( 1, (int) $page ) - 1 ) * $limit;
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE user_id = %d OR username = %s ORDER BY id ASC LIMIT %d OFFSET %d", $user->ID, $user->user_login, $limit, $offset ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		$data   = array();
		foreach ( (array) $rows as $row ) {
			$data[] = array(
				'group_id'    => 'grs-security-log',
				'group_label' => __( 'Security log', 'grs-security' ),
				'item_id'     => 'grs-security-log-' . $row['id'],
				'data'        => array(
					array(
						'name'  => __( 'Date', 'grs-security' ),
						'value' => $row['created_at'] . ' UTC',
					),
					array(
						'name'  => __( 'Event', 'grs-security' ),
						'value' => $row['message'],
					),
					array(
						'name'  => __( 'IP', 'grs-security' ),
						'value' => $row['ip'],
					),
				),
			);
		}
		return array(
			'data' => $data,
			'done' => count( (array) $rows ) < $limit,
		);
	}

	/**
	 * Anonimizza le righe del registro dell'utente.
	 *
	 * @param string $email Email.
	 * @param int    $page  Pagina.
	 * @return array
	 */
	public static function erase( $email, $page = 1 ) {
		global $wpdb;
		unset( $page );
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);
		}
		$table = Database::log_table();
		// I messaggi possono contenere il nome utente: le righe vengono eliminate, non solo anonimizzate.
		$updated = $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE user_id = %d OR username = %s", $user->ID, $user->user_login ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		return array(
			'items_removed'  => (bool) $updated,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
	}
}
