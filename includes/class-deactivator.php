<?php
/**
 * Disattivazione del plugin.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Operazioni alla disattivazione: il sito torna allo stato precedente.
 */
class Deactivator {

	/**
	 * Hook di disattivazione.
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( Plugin::CRON_DAILY );
		wp_clear_scheduled_hook( Plugin::CRON_INTEGRITY );
		Htaccess::remove_all();
		delete_transient( 'grs_security_activation_redirect' );
	}
}
