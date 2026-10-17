<?php
/**
 * Bacheca: menu, pagine e azioni del plugin.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Admin;

use GRSDigital\Security\Fixer;
use GRSDigital\Security\Htaccess;
use GRSDigital\Security\Integrity;
use GRSDigital\Security\Ip;
use GRSDigital\Security\Login_Guard;
use GRSDigital\Security\Login_Url;
use GRSDigital\Security\Plugin;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Interfaccia di amministrazione.
 */
class Admin {

	const CAP    = 'manage_options';
	const SLUG   = 'grs-security';
	const PARENT = 'grs-devs';
	const WIZARD = 'grs_security_wizard_done';

	/**
	 * Hook delle pagine registrate.
	 *
	 * @var string[]
	 */
	private static $hooks = array();

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ), 10 );
		add_filter( 'grs_devs_plugins', array( __CLASS__, 'register_in_grs_devs' ) );
		add_action( 'admin_init', array( __CLASS__, 'activation_redirect' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( GRS_SECURITY_FILE ), array( __CLASS__, 'action_links' ) );

		$actions = array( 'scan', 'fix', 'fix_bulk', 'dismiss', 'settings', 'integrity_run', 'integrity_ignore', 'unlock_ip', 'wizard_skip' );
		foreach ( $actions as $action ) {
			add_action( 'admin_post_grs_security_' . $action, array( __CLASS__, 'handle_' . $action ) );
		}
	}

	/**
	 * Vecchi slug delle pagine (1.0.x) => scheda nella pagina unica.
	 *
	 * @var array
	 */
	const LEGACY_PAGES = array(
		'grs-security-log'       => 'log',
		'grs-security-integrity' => 'integrity',
		'grs-security-settings'  => 'settings',
	);

	/**
	 * Registrazione nella panoramica GRS DEVs.
	 *
	 * @param array $plugins Plugin registrati.
	 * @return array
	 */
	public static function register_in_grs_devs( $plugins ) {
		$plugins = is_array( $plugins ) ? $plugins : array();

		$plugins[ self::SLUG ] = array(
			'name'        => 'GRS Security',
			'version'     => GRS_SECURITY_VERSION,
			'description' => __( 'Analisi della sicurezza, correzioni con un clic, protezione del login, verifica in due passaggi, firewall e controllo dei file.', 'grs-security' ),
			'url'         => Plugin::admin_url(),
		);
		return $plugins;
	}

	/**
	 * Voce di menu (una sola, sotto GRS DEVs) e redirect dai vecchi indirizzi.
	 *
	 * @return void
	 */
	public static function menu() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- solo redirect dai vecchi indirizzi di navigazione.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( isset( self::LEGACY_PAGES[ $page ] ) && current_user_can( self::CAP ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- parametri di navigazione conservati nel redirect.
			$extra = array_map( 'sanitize_text_field', wp_unslash( array_diff_key( $_GET, array( 'page' => 1 ) ) ) );
			wp_safe_redirect( Plugin::admin_url( self::LEGACY_PAGES[ $page ], $extra ) );
			exit;
		}

		$scan  = Scanner::last();
		$badge = '';
		if ( $scan ) {
			$critical = 0;
			$dismiss  = (array) Settings::get( 'dismissed_checks', array() );
			foreach ( $scan['results'] as $id => $row ) {
				if ( 'critical' === $row['status'] && ! in_array( $id, $dismiss, true ) ) {
					++$critical;
				}
			}
			if ( $critical ) {
				$badge = ' <span class="awaiting-mod"><span class="pending-count">' . (int) $critical . '</span></span>';
			}
		}
		self::$hooks[] = add_submenu_page( self::PARENT, 'GRS Security', __( 'Security', 'grs-security' ) . $badge, self::CAP, self::SLUG, array( Pages::class, 'router' ) );
	}

	/**
	 * CSS e JS solo nelle pagine del plugin.
	 *
	 * @param string $hook Hook della pagina.
	 * @return void
	 */
	public static function assets( $hook ) {
		if ( in_array( $hook, self::$hooks, true ) ) {
			// Dopo lo stile condiviso GRS DEVs (grs-ui.css), se caricato.
			$deps = wp_style_is( 'grs-devs-ui', 'enqueued' ) ? array( 'grs-devs-ui' ) : array();
			wp_enqueue_style( 'grs-security-admin', GRS_SECURITY_URL . 'assets/css/admin.css', $deps, GRS_SECURITY_VERSION );
			wp_enqueue_script( 'grs-security-admin', GRS_SECURITY_URL . 'assets/js/admin.js', array(), GRS_SECURITY_VERSION, true );
			wp_localize_script(
				'grs-security-admin',
				'grsSecurity',
				array(
					'confirmSalts'  => __( 'Le chiavi di sicurezza verranno rigenerate e tutti gli utenti, tu compreso, verranno disconnessi. I plugin GRS compatibili (come GRS SMTP) aggiornano automaticamente i propri dati cifrati. Continuare?', 'grs-security' ),
					'confirmRevert' => __( 'Vuoi annullare questa correzione?', 'grs-security' ),
				)
			);
		}
	}

	/**
	 * Link nella riga del plugin.
	 *
	 * @param array $links Link.
	 * @return array
	 */
	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( Plugin::admin_url() ) . '">' . esc_html__( 'Impostazioni', 'grs-security' ) . '</a>' );
		return $links;
	}

	/**
	 * Dopo l'attivazione apre la procedura guidata.
	 *
	 * @return void
	 */
	public static function activation_redirect() {
		if ( ! get_transient( 'grs_security_activation_redirect' ) ) {
			return;
		}
		delete_transient( 'grs_security_activation_redirect' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- solo lettura del contesto di attivazione.
		if ( wp_doing_ajax() || isset( $_GET['activate-multi'] ) || ! current_user_can( self::CAP ) ) {
			return;
		}
		wp_safe_redirect( Plugin::admin_url( '', array( 'grs_scan' => 1 ) ) );
		exit;
	}

	/**
	 * Controllo permessi e nonce comune.
	 *
	 * @param string $action Azione.
	 * @return void
	 */
	private static function guard( $action ) {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'Non hai i permessi per questa azione.', 'grs-security' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'grs_security_' . $action );
	}

	/**
	 * Salva un messaggio da mostrare dopo il redirect.
	 *
	 * @param string $type    success|error|warning|info.
	 * @param string $message Testo.
	 * @return void
	 */
	public static function notice( $type, $message ) {
		$key   = 'grs_security_notice_' . get_current_user_id();
		$queue = get_transient( $key );
		$queue = is_array( $queue ) ? $queue : array();

		$queue[] = array(
			'type'    => $type,
			'message' => $message,
		);
		set_transient( $key, $queue, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Mostra e svuota i messaggi.
	 *
	 * @return void
	 */
	public static function render_notices() {
		$key   = 'grs_security_notice_' . get_current_user_id();
		$queue = get_transient( $key );
		if ( ! is_array( $queue ) ) {
			return;
		}
		delete_transient( $key );
		foreach ( $queue as $item ) {
			$type = in_array( $item['type'], array( 'success', 'error', 'warning', 'info' ), true ) ? $item['type'] : 'info';
			echo '<div class="notice notice-' . esc_attr( $type ) . ' is-dismissible"><p>' . esc_html( $item['message'] ) . '</p></div>';
		}
	}

	/**
	 * Torna alla pagina indicata.
	 *
	 * @param string $tab  Scheda.
	 * @param array  $args Parametri.
	 * @return void
	 */
	private static function back( $tab = '', array $args = array() ) {
		wp_safe_redirect( Plugin::admin_url( $tab, $args ) );
		exit;
	}

	/**
	 * Nuova scansione.
	 *
	 * @return void
	 */
	public static function handle_scan() {
		self::guard( 'scan' );
		Scanner::run();
		self::notice( 'success', __( 'Analisi completata.', 'grs-security' ) );
		self::back();
	}

	/**
	 * Applica o annulla una correzione.
	 *
	 * @return void
	 */
	public static function handle_fix() {
		self::guard( 'fix' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$value = isset( $_POST['fix'] ) ? sanitize_text_field( wp_unslash( $_POST['fix'] ) ) : '';
		$parts = explode( '|', $value, 2 );
		$mode  = sanitize_key( $parts[0] );
		$check = isset( $parts[1] ) ? sanitize_key( $parts[1] ) : '';
		if ( 'revert' === $mode ) {
			$result = Fixer::revert( $check );
		} else {
			$result = Fixer::apply( $check );
		}
		if ( is_wp_error( $result ) ) {
			self::notice( 'error', $result->get_error_message() );
		} elseif ( 'salts' === $check ) {
			wp_safe_redirect( wp_login_url( Plugin::admin_url() ) );
			exit;
		} else {
			self::notice( 'success', 'revert' === $mode ? __( 'Correzione annullata.', 'grs-security' ) : __( 'Correzione applicata.', 'grs-security' ) );
		}
		Scanner::run();
		self::back();
	}

	/**
	 * Applica le correzioni selezionate (procedura guidata).
	 *
	 * @return void
	 */
	public static function handle_fix_bulk() {
		self::guard( 'fix_bulk' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$checks = isset( $_POST['checks'] ) && is_array( $_POST['checks'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['checks'] ) ) : array();
		update_option( self::WIZARD, 1, false );
		if ( empty( $checks ) ) {
			self::notice( 'warning', __( 'Nessuna correzione selezionata.', 'grs-security' ) );
			self::back();
		}
		$out = Fixer::apply_many( $checks );
		if ( $out['applied'] ) {
			/* translators: %d: numero correzioni */
			self::notice( 'success', sprintf( _n( '%d correzione applicata.', '%d correzioni applicate.', count( $out['applied'] ), 'grs-security' ), count( $out['applied'] ) ) );
		}
		foreach ( $out['errors'] as $check => $message ) {
			self::notice( 'error', $check . ': ' . $message );
		}
		if ( $out['salts'] ) {
			wp_safe_redirect( wp_login_url( Plugin::admin_url() ) );
			exit;
		}
		Scanner::run();
		self::back();
	}

	/**
	 * Chiude la procedura guidata senza applicare nulla.
	 *
	 * @return void
	 */
	public static function handle_wizard_skip() {
		self::guard( 'wizard_skip' );
		update_option( self::WIZARD, 1, false );
		self::back();
	}

	/**
	 * Ignora o ripristina un controllo.
	 *
	 * @return void
	 */
	public static function handle_dismiss() {
		self::guard( 'dismiss' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$value = isset( $_POST['dismiss'] ) ? sanitize_text_field( wp_unslash( $_POST['dismiss'] ) ) : '';
		$parts = explode( '|', $value, 2 );
		$undo  = 'undo' === $parts[0];
		$check = isset( $parts[1] ) ? sanitize_key( $parts[1] ) : '';
		if ( '' === $check ) {
			self::back();
		}
		$dismissed = (array) Settings::get( 'dismissed_checks', array() );
		$dismissed = $undo ? array_diff( $dismissed, array( $check ) ) : array_merge( $dismissed, array( $check ) );
		Settings::update( array( 'dismissed_checks' => array_values( $dismissed ) ) );
		self::back();
	}

	/**
	 * Salvataggio impostazioni.
	 *
	 * @return void
	 */
	public static function handle_settings() {
		self::guard( 'settings' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$raw = isset( $_POST['grs'] ) && is_array( $_POST['grs'] ) ? wp_unslash( $_POST['grs'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitizzato da Settings::sanitize().
		// phpcs:enable
		$old       = Settings::all();
		$raw_fixes = isset( $raw['fixes'] ) && is_array( $raw['fixes'] ) ? $raw['fixes'] : array();
		$fixes     = array();
		foreach ( Settings::FIXES as $fix ) {
			$fixes[ $fix ] = ! empty( $raw_fixes[ $fix ] );
		}
		$input = array(
			'fixes'              => $fixes,
			'xmlrpc_mode'        => isset( $raw['xmlrpc_mode'] ) ? $raw['xmlrpc_mode'] : 'off',
			'login_max_attempts' => isset( $raw['login_max_attempts'] ) ? $raw['login_max_attempts'] : '',
			'login_window'       => isset( $raw['login_window'] ) ? $raw['login_window'] : '',
			'login_lockout'      => isset( $raw['login_lockout'] ) ? $raw['login_lockout'] : '',
			'ip_source'          => isset( $raw['ip_source'] ) ? $raw['ip_source'] : 'REMOTE_ADDR',
			'ip_whitelist'       => isset( $raw['ip_whitelist'] ) ? $raw['ip_whitelist'] : '',
			'firewall_mode'      => isset( $raw['firewall_mode'] ) ? $raw['firewall_mode'] : 'block',
			'login_slug'         => isset( $raw['login_slug'] ) ? $raw['login_slug'] : '',
			'twofa_roles'        => isset( $raw['twofa_roles'] ) && is_array( $raw['twofa_roles'] ) ? $raw['twofa_roles'] : array(),
			'alerts_enabled'     => ! empty( $raw['alerts_enabled'] ),
			'alert_email'        => isset( $raw['alert_email'] ) ? $raw['alert_email'] : '',
			'log_retention'      => isset( $raw['log_retention'] ) ? $raw['log_retention'] : '',
			'keep_data'          => ! empty( $raw['keep_data'] ),
		);

		$slug_raw = trim( (string) $input['login_slug'] );
		if ( '' !== $slug_raw && '' === Login_Url::sanitize_slug( $slug_raw ) ) {
			self::notice( 'error', __( 'Indirizzo di login non valido: usa almeno 4 caratteri (lettere, numeri, trattini) ed evita parole come login, admin, dashboard.', 'grs-security' ) );
		} elseif ( ! empty( $input['fixes']['login_url'] ) && '' === $slug_raw ) {
			self::notice( 'error', __( 'Per spostare il login indica il nuovo indirizzo.', 'grs-security' ) );
		}
		if ( '' !== Login_Url::sanitize_slug( $slug_raw ) && get_page_by_path( Login_Url::sanitize_slug( $slug_raw ) ) ) {
			self::notice( 'error', __( 'Esiste già una pagina con questo indirizzo: scegline un altro.', 'grs-security' ) );
			$input['login_slug']         = $old['login_slug'];
			$input['fixes']['login_url'] = $old['fixes']['login_url'];
		}

		Settings::update( $input );
		$new = Settings::all();

		$htaccess_changed = false;
		foreach ( Fixer::HTACCESS_FIXES as $fix ) {
			if ( $old['fixes'][ $fix ] !== $new['fixes'][ $fix ] ) {
				$htaccess_changed = true;
			}
		}
		if ( $htaccess_changed ) {
			$result = Htaccess::sync();
			if ( is_wp_error( $result ) ) {
				$restore = array();
				foreach ( Fixer::HTACCESS_FIXES as $fix ) {
					$restore[ $fix ] = $old['fixes'][ $fix ];
				}
				Settings::update( array( 'fixes' => $restore ) );
				Htaccess::sync();
				self::notice( 'error', $result->get_error_message() );
			}
		}
		if ( ! $old['fixes']['integrity'] && $new['fixes']['integrity'] ) {
			Integrity::start();
		}

		self::notice( 'success', __( 'Impostazioni salvate.', 'grs-security' ) );
		if ( ! empty( $new['fixes']['login_url'] ) && '' !== $new['login_slug'] && ( $new['login_slug'] !== $old['login_slug'] || ! $old['fixes']['login_url'] ) ) {
			self::notice(
				'warning',
				/* translators: %s: URL */
				sprintf( __( 'Da ora la pagina di accesso è %s: salvala nei preferiti. Il nuovo indirizzo è stato inviato anche via email.', 'grs-security' ), Login_Url::login_url() )
			);
		}
		Scanner::run();
		self::back( 'settings' );
	}

	/**
	 * Avvia il controllo integrità.
	 *
	 * @return void
	 */
	public static function handle_integrity_run() {
		self::guard( 'integrity_run' );
		Integrity::start( true );
		$progress = Integrity::progress();
		self::notice(
			'success',
			$progress
				? __( 'Controllo avviato: prosegue in background, ricarica la pagina tra qualche minuto.', 'grs-security' )
				: __( 'Controllo dei file completato.', 'grs-security' )
		);
		self::back( 'integrity' );
	}

	/**
	 * Ignora un file segnalato.
	 *
	 * @return void
	 */
	public static function handle_integrity_ignore() {
		self::guard( 'integrity_ignore' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$issue  = isset( $_POST['issue'] ) ? sanitize_text_field( wp_unslash( $_POST['issue'] ) ) : '';
		$stored = get_option( Integrity::RESULT_OPTION, array() );
		$issues = isset( $stored['issues'] ) ? (array) $stored['issues'] : array();
		if ( ! in_array( $issue, $issues, true ) ) {
			self::back( 'integrity' );
		}
		list( $type, $path ) = array_map( 'trim', explode( ':', $issue, 2 ) );
		$abs                 = self::issue_abs_path( $type, $path );
		if ( '' !== $abs ) {
			Integrity::ignore( $path, $abs );
			self::notice( 'success', __( 'File ignorato: verrà segnalato di nuovo solo se cambia.', 'grs-security' ) );
		}
		self::back( 'integrity' );
	}

	/**
	 * Percorso assoluto di un'anomalia, limitato alle cartelle previste.
	 *
	 * @param string $type Tipo.
	 * @param string $path Percorso relativo.
	 * @return string
	 */
	public static function issue_abs_path( $type, $path ) {
		if ( false !== strpos( $path, '..' ) ) {
			return '';
		}
		if ( 0 === strpos( $type, 'core-' ) || 'root-unknown' === $type ) {
			return ABSPATH . $path;
		}
		if ( 0 === strpos( $type, 'plugin-' ) ) {
			return trailingslashit( WP_PLUGIN_DIR ) . $path;
		}
		if ( 'uploads-php' === $type ) {
			$uploads = wp_upload_dir( null, false );
			return trailingslashit( $uploads['basedir'] ) . $path;
		}
		return '';
	}

	/**
	 * Sblocca un IP.
	 *
	 * @return void
	 */
	public static function handle_unlock_ip() {
		self::guard( 'unlock_ip' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce verificato in guard().
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			Login_Guard::unlock( $ip );
			/* translators: %s: IP */
			self::notice( 'success', sprintf( __( 'IP %s sbloccato.', 'grs-security' ), $ip ) );
		}
		self::back( 'settings' );
	}

	/**
	 * Etichette delle protezioni (per impostazioni e messaggi).
	 *
	 * @return array
	 */
	public static function fix_labels() {
		return array(
			'login_guard'        => __( 'Limite ai tentativi di accesso', 'grs-security' ),
			'twofa'              => __( 'Verifica in due passaggi obbligatoria per i ruoli scelti', 'grs-security' ),
			'login_errors'       => __( 'Errori di login generici', 'grs-security' ),
			'file_edit'          => __( 'Blocca l\'editor di file di plugin e temi', 'grs-security' ),
			'xmlrpc'             => __( 'Disattiva XML-RPC', 'grs-security' ),
			'user_enum'          => __( 'Blocca l\'elenco pubblico dei nomi utente', 'grs-security' ),
			'app_passwords'      => __( 'Disattiva le Application Passwords', 'grs-security' ),
			'headers'            => __( 'Header HTTP di sicurezza', 'grs-security' ),
			'hsts'               => __( 'HSTS (solo siti interamente in HTTPS)', 'grs-security' ),
			'hide_version'       => __( 'Nascondi la versione di WordPress', 'grs-security' ),
			'core_minor_updates' => __( 'Forza gli aggiornamenti automatici minori del core', 'grs-security' ),
			'htaccess_uploads'   => __( 'Blocca PHP nella cartella uploads (.htaccess)', 'grs-security' ),
			'htaccess_sensitive' => __( 'Blocca file sensibili, log e backup (.htaccess)', 'grs-security' ),
			'htaccess_indexes'   => __( 'Disattiva l\'elenco dei file delle cartelle (.htaccess)', 'grs-security' ),
			'firewall'           => __( 'Firewall applicativo', 'grs-security' ),
			'integrity'          => __( 'Controllo giornaliero dell\'integrità dei file', 'grs-security' ),
			'login_url'          => __( 'Sposta la pagina di login', 'grs-security' ),
		);
	}

	/**
	 * IP del visitatore per ogni sorgente (aiuto alla scelta).
	 *
	 * @return array
	 */
	public static function detected_ips() {
		$out = array();
		foreach ( array_keys( Ip::sources() ) as $source ) {
			$out[ $source ] = Ip::from_server( $source );
		}
		return $out;
	}
}
