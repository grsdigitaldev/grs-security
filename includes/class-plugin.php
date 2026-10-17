<?php
/**
 * Orchestratore del plugin.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Registra i componenti e gli hook.
 */
class Plugin {

	const CRON_DAILY     = 'grs_security_daily';
	const CRON_INTEGRITY = 'grs_security_integrity_run';

	/**
	 * Istanza unica.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Restituisce (e crea) l'istanza.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Costruttore.
	 */
	private function __construct() {
		Database::maybe_upgrade();
		$this->maybe_upgrade();

		Hardening::init();
		Login_Guard::init();
		Two_Factor::init();
		Login_Url::init();
		Event_Monitor::init();
		Notifier::init();
		Privacy::init();
		Updater::init();

		add_action( 'init', array( $this, 'load_textdomain' ) );
		add_action( self::CRON_DAILY, array( $this, 'daily' ) );
		add_action( self::CRON_INTEGRITY, array( 'GRSDigital\\Security\\Integrity', 'run_batch' ) );
		add_action( 'grs_security_settings_updated', array( 'GRSDigital\\Security\\Scanner', 'mark_stale' ) );

		if ( is_admin() ) {
			Admin\Admin::init();
			Admin\Profile::init();
		}
	}

	/**
	 * URL della pagina del plugin in bacheca (menu GRS DEVs), con scheda opzionale.
	 *
	 * @param string $tab  Scheda: '' (analisi), log, integrity, settings.
	 * @param array  $args Parametri aggiuntivi.
	 * @return string
	 */
	public static function admin_url( $tab = '', array $args = array() ) {
		$query = array( 'page' => 'grs-security' );
		if ( '' !== $tab ) {
			$query['tab'] = $tab;
		}
		return add_query_arg( array_merge( $query, $args ), admin_url( 'admin.php' ) );
	}

	/**
	 * Traduzioni (stringhe sorgente in italiano).
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'grs-security', false, dirname( plugin_basename( GRS_SECURITY_FILE ) ) . '/languages' );
	}

	/**
	 * Migrazioni tra versioni.
	 *
	 * @return void
	 */
	private function maybe_upgrade() {
		$stored = get_option( 'grs_security_version', '' );
		if ( GRS_SECURITY_VERSION === $stored ) {
			return;
		}
		// Prima installazione senza attivazione (es. aggiornamento via FTP): assicura cron e opzioni.
		Activator::ensure_defaults();
		Activator::schedule_events();
		// I risultati salvati possono contenere link alle vecchie pagine: nuova analisi alla prima visita.
		Scanner::mark_stale();
		update_option( 'grs_security_version', GRS_SECURITY_VERSION, true );
	}

	/**
	 * Lavori giornalieri: pulizia registro e scansione integrità.
	 *
	 * @return void
	 */
	public function daily() {
		Logger::purge();
		Login_Guard::purge();
		if ( Settings::fix_enabled( 'integrity' ) ) {
			Integrity::start();
		}
		Scanner::run();
	}
}
