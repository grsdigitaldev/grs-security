<?php
/**
 * Attivazione del plugin.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Operazioni all'attivazione.
 */
class Activator {

	/**
	 * Hook di attivazione.
	 *
	 * @param bool $network_wide Attivazione di rete.
	 * @return void
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			deactivate_plugins( plugin_basename( GRS_SECURITY_FILE ), true, true );
			wp_die(
				esc_html__( 'GRS Security non supporta l\'attivazione di rete in multisite. Attivalo sul singolo sito.', 'grs-security' ),
				esc_html__( 'Attivazione non supportata', 'grs-security' ),
				array( 'back_link' => true )
			);
		}

		Database::install();
		self::ensure_defaults();
		self::schedule_events();
		update_option( 'grs_security_version', GRS_SECURITY_VERSION, true );

		// Ripristina le regole .htaccess delle correzioni già attive (riattivazione).
		Htaccess::sync();

		set_transient( 'grs_security_activation_redirect', 1, 60 );
	}

	/**
	 * Crea l'opzione impostazioni se manca (non sovrascrive).
	 *
	 * @return void
	 */
	public static function ensure_defaults() {
		if ( false === get_option( Settings::OPTION, false ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', true );
			Settings::flush();
		}
	}

	/**
	 * Pianifica gli eventi cron.
	 *
	 * @return void
	 */
	public static function schedule_events() {
		if ( ! wp_next_scheduled( Plugin::CRON_DAILY ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', Plugin::CRON_DAILY );
		}
	}
}
