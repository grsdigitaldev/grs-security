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
		add_action( 'change_locale', array( __CLASS__, 'reload_textdomain' ) );
		add_action( self::CRON_DAILY, array( $this, 'daily' ) );
		add_action( self::CRON_INTEGRITY, array( 'GRSDigital\\Security\\Integrity', 'run_batch' ) );
		add_action( 'grs_security_settings_updated', array( 'GRSDigital\\Security\\Scanner', 'mark_stale' ) );

		if ( is_admin() ) {
			Admin\Admin::init();
			Admin\Profile::init();
		}
	}

	/**
	 * Passa alla lingua del destinatario di un'email: quella del profilo se l'indirizzo
	 * appartiene a un utente registrato, altrimenti quella del sito.
	 *
	 * Restituisce true se la lingua è stata cambiata: in quel caso chiamare
	 * restore_previous_locale() dopo aver preparato e inviato l'email.
	 *
	 * @param string $email Indirizzo del destinatario.
	 * @return bool
	 */
	public static function switch_to_recipient_locale( $email ) {
		if ( ! function_exists( 'switch_to_locale' ) ) {
			return false;
		}
		$user = is_email( $email ) ? get_user_by( 'email', $email ) : false;
		if ( $user ) {
			if ( function_exists( 'switch_to_user_locale' ) ) {
				return (bool) switch_to_user_locale( $user->ID ); // WP 6.2+.
			}
			return (bool) switch_to_locale( get_user_locale( $user->ID ) );
		}
		return (bool) switch_to_locale( self::site_locale() );
	}

	/**
	 * Lingua del sito (Impostazioni > Generali), anche mentre la lingua corrente è cambiata
	 * (get_locale() restituisce la lingua temporanea durante switch_to_locale()).
	 *
	 * @return string
	 */
	public static function site_locale() {
		$locale = (string) get_option( 'WPLANG' );
		if ( '' === $locale && defined( 'WPLANG' ) ) {
			$locale = (string) WPLANG;
		}
		return '' !== $locale ? $locale : 'en_US';
	}

	/**
	 * Formato data del sito (Impostazioni > Generali), con ripiego.
	 *
	 * @return string
	 */
	public static function date_format() {
		$format = (string) get_option( 'date_format' );
		return '' !== $format ? $format : 'Y-m-d';
	}

	/**
	 * Formato data e ora del sito (Impostazioni > Generali), con ripiego.
	 *
	 * @return string
	 */
	public static function datetime_format() {
		$time = (string) get_option( 'time_format' );
		return self::date_format() . ' ' . ( '' !== $time ? $time : 'H:i' );
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
	 * Traduzioni (testi sorgente in inglese, italiano incluso in languages/).
	 *
	 * @return void
	 */
	public function load_textdomain() {
		load_plugin_textdomain( 'grs-security', false, dirname( plugin_basename( GRS_SECURITY_FILE ) ) . '/languages' );
	}

	/**
	 * Ricarica le traduzioni del plugin quando cambia la lingua (switch_to_locale, es. email nella lingua del destinatario).
	 *
	 * Da WP 6.1 se ne occupa WordPress (registro dei text domain); su WP 6.0 il cambio di lingua
	 * scarica le traduzioni e il caricamento automatico non conosce la cartella languages/ del plugin.
	 *
	 * @param string $locale Nuova lingua.
	 * @return void
	 */
	public static function reload_textdomain( $locale ) {
		if ( class_exists( 'WP_Textdomain_Registry' ) ) {
			return;
		}
		$locale = (string) apply_filters( 'plugin_locale', (string) $locale, 'grs-security' ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- filtro del core.
		unload_textdomain( 'grs-security' );
		if ( ! load_textdomain( 'grs-security', WP_LANG_DIR . '/plugins/grs-security-' . $locale . '.mo' ) ) {
			load_textdomain( 'grs-security', GRS_SECURITY_PATH . 'languages/grs-security-' . $locale . '.mo' );
		}
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
