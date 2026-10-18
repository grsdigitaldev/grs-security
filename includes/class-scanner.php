<?php
/**
 * Scansione della sicurezza: esegue i controlli, calcola il punteggio, salva il risultato.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Registro dei controlli.
 */
class Scanner {

	const OPTION = 'grs_security_scan';

	/**
	 * Categorie dei controlli.
	 *
	 * @return array
	 */
	public static function categories() {
		return array(
			'updates'    => __( 'Updates', 'grs-security' ),
			'users'      => __( 'Users and logins', 'grs-security' ),
			'config'     => __( 'Configuration', 'grs-security' ),
			'exposure'   => __( 'Site exposure', 'grs-security' ),
			'monitoring' => __( 'Active protections and monitoring', 'grs-security' ),
		);
	}

	/**
	 * Completa un risultato con i valori predefiniti.
	 *
	 * @param array $data Dati parziali.
	 * @return array
	 */
	public static function result( array $data ) {
		return array_merge(
			array(
				'id'           => '',
				'category'     => 'config',
				'title'        => '',
				'status'       => 'info',
				'weight'       => 2,
				'message'      => '',
				'fix'          => 'none',
				'fix_applied'  => false,
				'instructions' => '',
				'recommended'  => false,
				'optional'     => false,
				'link'         => '',
			),
			$data
		);
	}

	/**
	 * Esegue tutti i controlli.
	 *
	 * @return array Risultato salvato.
	 */
	public static function run() {
		$results = array_merge(
			Checks\Update_Checks::run(),
			Checks\User_Checks::run(),
			Checks\Config_Checks::run(),
			Checks\Exposure_Checks::run(),
			Checks\Protection_Checks::run()
		);
		/**
		 * Risultati della scansione (permette controlli aggiuntivi).
		 *
		 * @param array $results Risultati.
		 */
		$results = (array) apply_filters( 'grs_security_scan_results', $results );

		$indexed = array();
		foreach ( $results as $row ) {
			$row                   = self::result( $row );
			$indexed[ $row['id'] ] = $row;
		}

		$scan          = array(
			'time'     => time(),
			'locale'   => function_exists( 'determine_locale' ) ? determine_locale() : get_locale(),
			'results'  => $indexed,
			'loopback' => ! Loopback::is_broken(),
		);
		$scan['score'] = self::score( $indexed );
		update_option( self::OPTION, $scan, false );
		return $scan;
	}

	/**
	 * Segna l'ultima scansione come da rifare (impostazioni cambiate).
	 *
	 * @return void
	 */
	public static function mark_stale() {
		$scan = get_option( self::OPTION );
		if ( is_array( $scan ) && empty( $scan['stale'] ) ) {
			$scan['stale'] = true;
			update_option( self::OPTION, $scan, false );
		}
	}

	/**
	 * Ultima scansione salvata.
	 *
	 * @return array|null
	 */
	public static function last() {
		$scan = get_option( self::OPTION );
		return is_array( $scan ) && isset( $scan['results'] ) ? $scan : null;
	}

	/**
	 * Punteggio 0-100 sui controlli valutabili non ignorati.
	 *
	 * @param array $results Risultati.
	 * @return int
	 */
	public static function score( array $results ) {
		$dismissed = (array) Settings::get( 'dismissed_checks', array() );
		$total     = 0;
		$earned    = 0;
		foreach ( $results as $id => $row ) {
			if ( in_array( $id, $dismissed, true ) || ! empty( $row['optional'] ) || ! in_array( $row['status'], array( 'ok', 'warning', 'critical' ), true ) ) {
				continue;
			}
			$weight = max( 1, (int) $row['weight'] );
			$total += $weight;
			if ( 'ok' === $row['status'] ) {
				$earned += $weight;
			}
		}
		return $total > 0 ? (int) round( 100 * $earned / $total ) : 100;
	}
}
