<?php
/**
 * Controlli su aggiornamenti, plugin e temi inutilizzati, versione PHP.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Aggiornamenti".
 */
class Update_Checks {

	/**
	 * Fine del supporto di sicurezza dei rami PHP (fonte: php.net / endoflife.date, verificato 2026-10-17).
	 *
	 * @var array
	 */
	const PHP_EOL = array(
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		if ( ! function_exists( 'get_core_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return array(
			self::core(),
			self::plugins(),
			self::themes(),
			self::inactive_plugins(),
			self::inactive_themes(),
			self::php(),
		);
	}

	/**
	 * Risultato "non verificabile" quando wordpress.org non risponde.
	 *
	 * @param string $id     Id.
	 * @param string $title  Titolo.
	 * @param int    $weight Peso.
	 * @return array
	 */
	private static function unknown( $id, $title, $weight ) {
		return Scanner::result(
			array(
				'id'           => $id,
				'category'     => 'updates',
				'title'        => $title,
				'status'       => 'unknown',
				'weight'       => $weight,
				'message'      => __( 'Impossibile contattare wordpress.org per verificare gli aggiornamenti. Controlla a mano in Bacheca > Aggiornamenti.', 'grs-security' ),
				'fix'          => 'manual',
				'instructions' => __( 'Se il problema persiste, l\'hosting potrebbe bloccare le connessioni in uscita verso wordpress.org: in quel caso nemmeno gli aggiornamenti di sicurezza automatici funzionano. Segnalalo all\'hosting.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Aggiornamento del core.
	 *
	 * @return array
	 */
	private static function core() {
		$transient = get_site_transient( 'update_core' );
		if ( ! is_object( $transient ) || empty( $transient->updates ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_version_check();
			$transient = get_site_transient( 'update_core' );
		}
		if ( ! is_object( $transient ) || empty( $transient->updates ) ) {
			return self::unknown( 'core_update', __( 'WordPress aggiornato', 'grs-security' ), 3 );
		}
		$updates = get_core_updates();
		$latest  = '';
		if ( is_array( $updates ) ) {
			foreach ( $updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					$latest = $update->current;
					break;
				}
			}
		}
		$current = get_bloginfo( 'version' );
		if ( '' === $latest ) {
			return Scanner::result(
				array(
					'id'       => 'core_update',
					'category' => 'updates',
					'title'    => __( 'WordPress aggiornato', 'grs-security' ),
					'status'   => 'ok',
					'weight'   => 3,
					/* translators: %s: versione */
					'message'  => sprintf( __( 'WordPress %s è la versione più recente disponibile.', 'grs-security' ), $current ),
				)
			);
		}
		$major_behind = version_compare( implode( '.', array_slice( explode( '.', $latest ), 0, 2 ) ), implode( '.', array_slice( explode( '.', $current ), 0, 2 ) ), '>' );
		return Scanner::result(
			array(
				'id'           => 'core_update',
				'category'     => 'updates',
				'title'        => __( 'WordPress aggiornato', 'grs-security' ),
				'status'       => $major_behind ? 'warning' : 'critical',
				'weight'       => 3,
				/* translators: 1: versione installata, 2: versione disponibile */
				'message'      => sprintf( __( 'Installata la versione %1$s, disponibile la %2$s.', 'grs-security' ), $current, $latest ),
				'fix'          => 'manual',
				'instructions' => __( 'Fai un backup, poi aggiorna da Bacheca > Aggiornamenti. Gli aggiornamenti minori contengono quasi sempre correzioni di sicurezza: non rimandarli.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Plugin da aggiornare.
	 *
	 * @return array
	 */
	private static function plugins() {
		$transient = get_site_transient( 'update_plugins' );
		if ( ! is_object( $transient ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_update_plugins();
			$transient = get_site_transient( 'update_plugins' );
		}
		if ( ! is_object( $transient ) || ! isset( $transient->no_update ) ) {
			return self::unknown( 'plugin_updates', __( 'Plugin aggiornati', 'grs-security' ), 3 );
		}
		$all   = get_plugins();
		$names = array();
		if ( is_object( $transient ) && ! empty( $transient->response ) ) {
			foreach ( array_keys( (array) $transient->response ) as $file ) {
				$names[] = isset( $all[ $file ]['Name'] ) ? $all[ $file ]['Name'] : $file;
			}
		}
		$count = count( $names );
		return Scanner::result(
			array(
				'id'           => 'plugin_updates',
				'category'     => 'updates',
				'title'        => __( 'Plugin aggiornati', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : ( $count > 3 ? 'critical' : 'warning' ),
				'weight'       => 3,
				'message'      => 0 === $count
					? __( 'Tutti i plugin sono aggiornati.', 'grs-security' )
					/* translators: 1: numero, 2: elenco */
					: sprintf( _n( '%1$d plugin da aggiornare: %2$s.', '%1$d plugin da aggiornare: %2$s.', $count, 'grs-security' ), $count, implode( ', ', $names ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'I plugin non aggiornati sono la prima causa di siti WordPress violati. Aggiornali da Plugin > Plugin installati e valuta gli aggiornamenti automatici per quelli affidabili.', 'grs-security' ),
				'link'         => admin_url( 'plugins.php?plugin_status=upgrade' ),
			)
		);
	}

	/**
	 * Temi da aggiornare.
	 *
	 * @return array
	 */
	private static function themes() {
		$transient = get_site_transient( 'update_themes' );
		if ( ! is_object( $transient ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_update_themes();
			$transient = get_site_transient( 'update_themes' );
		}
		if ( ! is_object( $transient ) || ! isset( $transient->no_update ) ) {
			return self::unknown( 'theme_updates', __( 'Temi aggiornati', 'grs-security' ), 2 );
		}
		$count = ! empty( $transient->response ) ? count( (array) $transient->response ) : 0;
		return Scanner::result(
			array(
				'id'           => 'theme_updates',
				'category'     => 'updates',
				'title'        => __( 'Temi aggiornati', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => 0 === $count
					? __( 'Tutti i temi sono aggiornati.', 'grs-security' )
					/* translators: %d: numero */
					: sprintf( _n( '%d tema da aggiornare.', '%d temi da aggiornare.', $count, 'grs-security' ), $count ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Aggiorna i temi da Bacheca > Aggiornamenti. Se il tema è stato modificato direttamente, sposta le modifiche in un tema child prima di aggiornare.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Plugin installati ma disattivati.
	 *
	 * @return array
	 */
	private static function inactive_plugins() {
		$inactive = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				$inactive[] = $data['Name'];
			}
		}
		$count = count( $inactive );
		return Scanner::result(
			array(
				'id'           => 'inactive_plugins',
				'category'     => 'updates',
				'title'        => __( 'Nessun plugin inutilizzato', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => 0 === $count
					? __( 'Non ci sono plugin disattivati.', 'grs-security' )
					/* translators: 1: numero, 2: elenco */
					: sprintf( _n( '%1$d plugin disattivato: %2$s.', '%1$d plugin disattivati: %2$s.', $count, 'grs-security' ), $count, implode( ', ', array_slice( $inactive, 0, 10 ) ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Un plugin disattivato non gira, ma i suoi file restano raggiungibili e possono contenere vulnerabilità. Se non ti serve, eliminalo.', 'grs-security' ),
				'link'         => admin_url( 'plugins.php?plugin_status=inactive' ),
			)
		);
	}

	/**
	 * Temi inutilizzati (oltre al tema attivo, al genitore e a un tema predefinito di riserva).
	 *
	 * @return array
	 */
	private static function inactive_themes() {
		$active = array( get_stylesheet(), get_template() );
		$extra  = array();
		$spare  = false;
		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( in_array( $slug, $active, true ) ) {
				continue;
			}
			if ( ! $spare && 0 === strpos( $slug, 'twenty' ) ) {
				$spare = true; // Un tema predefinito di riserva è utile per la diagnostica.
				continue;
			}
			$extra[] = $theme->get( 'Name' );
		}
		$count = count( $extra );
		return Scanner::result(
			array(
				'id'           => 'inactive_themes',
				'category'     => 'updates',
				'title'        => __( 'Nessun tema inutilizzato', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => 0 === $count
					? __( 'Sono installati solo il tema attivo e, se presente, un tema predefinito di riserva.', 'grs-security' )
					/* translators: 1: numero, 2: elenco */
					: sprintf( _n( '%1$d tema non usato: %2$s.', '%1$d temi non usati: %2$s.', $count, 'grs-security' ), $count, implode( ', ', $extra ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Elimina i temi che non usi da Aspetto > Temi. Tieni solo il tema attivo, il suo tema genitore e un tema predefinito recente come riserva.', 'grs-security' ),
				'link'         => admin_url( 'themes.php' ),
			)
		);
	}

	/**
	 * Versione PHP.
	 *
	 * @return array
	 */
	private static function php() {
		$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
		$eol    = isset( self::PHP_EOL[ $branch ] ) ? strtotime( self::PHP_EOL[ $branch ] . ' 23:59:59 UTC' ) : 0;
		$now    = time();
		if ( $eol && $eol < $now ) {
			$status = 'critical';
			/* translators: 1: versione, 2: data */
			$message = sprintf( __( 'PHP %1$s non riceve più aggiornamenti di sicurezza dal %2$s.', 'grs-security' ), PHP_VERSION, wp_date( 'd/m/Y', $eol ) );
		} elseif ( $eol && ( $eol - $now ) < 120 * DAY_IN_SECONDS ) {
			$status = 'warning';
			/* translators: 1: versione, 2: data */
			$message = sprintf( __( 'PHP %1$s smetterà di ricevere aggiornamenti di sicurezza il %2$s.', 'grs-security' ), PHP_VERSION, wp_date( 'd/m/Y', $eol ) );
		} else {
			$status = 'ok';
			/* translators: %s: versione */
			$message = sprintf( __( 'PHP %s è supportato.', 'grs-security' ), PHP_VERSION );
		}
		return Scanner::result(
			array(
				'id'           => 'php_version',
				'category'     => 'updates',
				'title'        => __( 'Versione PHP supportata', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $message,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'Cambia la versione PHP dal pannello dell\'hosting scegliendo una versione supportata (8.3 o successiva). Prova prima su uno staging: plugin o temi datati potrebbero non essere compatibili.', 'grs-security' ),
			)
		);
	}
}
