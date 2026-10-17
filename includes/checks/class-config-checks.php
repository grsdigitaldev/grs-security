<?php
/**
 * Controlli sulla configurazione di WordPress e del server.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Htaccess;
use GRSDigital\Security\Loopback;
use GRSDigital\Security\Salts;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Configurazione".
 */
class Config_Checks {

	/**
	 * Plugin di backup riconosciuti (file principale => nome).
	 *
	 * @var array
	 */
	const BACKUP_PLUGINS = array(
		'updraftplus/updraftplus.php'                     => 'UpdraftPlus',
		'backwpup/backwpup.php'                           => 'BackWPup',
		'duplicator/duplicator.php'                       => 'Duplicator',
		'duplicator-pro/duplicator-pro.php'               => 'Duplicator Pro',
		'all-in-one-wp-migration/all-in-one-wp-migration.php' => 'All-in-One WP Migration',
		'wpvivid-backuprestore/wpvivid-backuprestore.php' => 'WPvivid',
		'backup-backup/backup-backup.php'                 => 'Backup Migration',
		'blogvault-real-time-backup/blogvault.php'        => 'BlogVault',
		'jetpack/jetpack.php'                             => 'Jetpack (VaultPress Backup)',
		'jetpack-backup/jetpack-backup.php'               => 'Jetpack VaultPress Backup',
		'backupbuddy/backupbuddy.php'                     => 'Solid Backups',
		'xcloner-backup-and-restore/xcloner.php'          => 'XCloner',
		'wp-time-capsule/wp-time-capsule.php'             => 'WP Time Capsule',
		'boldgrid-backup/boldgrid-backup.php'             => 'Total Upkeep',
	);

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return array(
			self::file_edit(),
			self::debug_display(),
			self::debug_log(),
			self::salts(),
			self::config_perms(),
			self::https(),
			self::app_passwords(),
			self::core_auto_updates(),
			self::backup(),
			self::db_prefix(),
		);
	}

	/**
	 * Editor di file in bacheca.
	 *
	 * @return array
	 */
	private static function file_edit() {
		$constant = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$applied  = Settings::fix_enabled( 'file_edit' );
		return Scanner::result(
			array(
				'id'           => 'file_edit',
				'category'     => 'config',
				'title'        => __( 'Editor di plugin e temi disattivato', 'grs-security' ),
				'status'       => ( $constant || $applied ) ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => ( $constant || $applied )
					? __( 'Dalla bacheca non è possibile modificare il codice di plugin e temi.', 'grs-security' )
					: __( 'Chi entra come amministratore può modificare il codice PHP di plugin e temi dalla bacheca: è il modo più rapido per installare una backdoor.', 'grs-security' ),
				'fix'          => $constant ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $constant,
				'instructions' => __( 'Nasconde e blocca l\'editor di file di plugin e temi. Le modifiche al codice si fanno via FTP o con un deploy.', 'grs-security' ),
			)
		);
	}

	/**
	 * Errori mostrati ai visitatori.
	 *
	 * @return array
	 */
	private static function debug_display() {
		$debug   = defined( 'WP_DEBUG' ) && WP_DEBUG;
		$display = ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY;
		$bad     = $debug && $display;
		return Scanner::result(
			array(
				'id'           => 'debug_display',
				'category'     => 'config',
				'title'        => __( 'Errori PHP non visibili ai visitatori', 'grs-security' ),
				'status'       => $bad ? 'warning' : 'ok',
				'weight'       => 2,
				'message'      => $bad
					? __( 'WP_DEBUG è attivo e gli errori vengono mostrati nelle pagine: rivelano percorsi del server e dettagli dei plugin.', 'grs-security' )
					: __( 'Gli errori PHP non vengono mostrati nelle pagine.', 'grs-security' ),
				'fix'          => $bad ? 'manual' : 'none',
				'instructions' => __( 'In wp-config.php imposta define( \'WP_DEBUG\', false ); oppure, se ti serve il debug, define( \'WP_DEBUG_DISPLAY\', false ); e @ini_set( \'display_errors\', 0 );', 'grs-security' ),
			)
		);
	}

	/**
	 * File debug.log pubblico.
	 *
	 * @return array
	 */
	private static function debug_log() {
		$path = WP_CONTENT_DIR . '/debug.log';
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && '' !== WP_DEBUG_LOG ) {
			$path = WP_DEBUG_LOG;
		}
		$inside = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) );
		$status = 'ok';
		$msg    = __( 'Nessun file di log raggiungibile dal browser.', 'grs-security' );
		if ( file_exists( $path ) && $inside ) {
			$url      = site_url( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $path ) ) );
			$response = Loopback::request( $url, 'GET', array( 'headers' => array( 'Range' => 'bytes=0-200' ) ) );
			$code     = Loopback::code( $response );
			if ( null === $response ) {
				$status = 'unknown';
				$msg    = __( 'Esiste un file debug.log ma non è stato possibile verificare se è raggiungibile dal browser.', 'grs-security' );
			} elseif ( in_array( $code, array( 200, 206 ), true ) ) {
				$status = 'critical';
				/* translators: %s: URL */
				$msg = sprintf( __( 'Il registro degli errori è leggibile da chiunque: %s', 'grs-security' ), $url );
			} else {
				$msg = __( 'Esiste un file debug.log ma non è raggiungibile dal browser.', 'grs-security' );
			}
		}
		$can_htaccess = Htaccess::supported();
		return Scanner::result(
			array(
				'id'           => 'debug_log',
				'category'     => 'config',
				'title'        => __( 'Registro errori non pubblico', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $msg,
				'fix'          => 'critical' === $status ? ( $can_htaccess ? 'auto' : 'manual' ) : 'none',
				'fix_applied'  => Settings::fix_enabled( 'htaccess_sensitive' ),
				'recommended'  => 'critical' === $status && $can_htaccess,
				'instructions' => $can_htaccess
					? __( 'Blocca l\'accesso via browser ai file di log, di backup e ai file sensibili tramite .htaccess. Valuta anche di spostare il log fuori dalla cartella pubblica con define( \'WP_DEBUG_LOG\', \'/percorso/fuori/dal/sito/debug.log\' );', 'grs-security' )
					: __( 'Elimina il file debug.log e sposta il log fuori dalla cartella pubblica con define( \'WP_DEBUG_LOG\', \'/percorso/fuori/dal/sito/debug.log\' ); oppure chiedi all\'hosting di bloccare i file .log.', 'grs-security' ),
			)
		);
	}

	/**
	 * Chiavi di sicurezza.
	 *
	 * @return array
	 */
	private static function salts() {
		$state = Salts::status();
		$can   = Salts::can_regenerate();
		$ok    = 'ok' === $state['status'];
		return Scanner::result(
			array(
				'id'           => 'salts',
				'category'     => 'config',
				'title'        => __( 'Chiavi di sicurezza (SALT) robuste', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $ok
					? __( 'Le chiavi di sicurezza in wp-config.php sono presenti e uniche. Puoi rigenerarle se sospetti una violazione: tutti verranno disconnessi.', 'grs-security' )
					/* translators: %s: elenco problemi */
					: sprintf( __( 'Problemi nelle chiavi di sicurezza: %s.', 'grs-security' ), implode( ', ', $state['problems'] ) ),
				'fix'          => is_wp_error( $can ) ? 'manual' : 'auto',
				'recommended'  => ! $ok && ! is_wp_error( $can ),
				'instructions' => is_wp_error( $can )
					? $can->get_error_message() . ' ' . __( 'Genera nuove chiavi su https://api.wordpress.org/secret-key/1.1/salt/ e sostituiscile in wp-config.php.', 'grs-security' )
					: __( 'Genera nuove chiavi casuali e le scrive in wp-config.php con un controllo di sintassi prima del salvataggio. Tutti gli utenti, tu compreso, verranno disconnessi. I plugin GRS compatibili (come GRS SMTP 1.0.1 o successivo) aggiornano automaticamente i propri dati cifrati; per altri plugin che cifrano dati con le chiavi del sito potrebbe essere necessario reinserire password o chiavi API.', 'grs-security' ),
			)
		);
	}

	/**
	 * Permessi di wp-config.php.
	 *
	 * @return array
	 */
	private static function config_perms() {
		$path = Salts::config_path();
		if ( '' === $path ) {
			return Scanner::result(
				array(
					'id'       => 'config_perms',
					'category' => 'config',
					'title'    => __( 'Permessi di wp-config.php', 'grs-security' ),
					'status'   => 'unknown',
					'message'  => __( 'wp-config.php non trovato nelle posizioni standard.', 'grs-security' ),
				)
			);
		}
		$perms = fileperms( $path ) & 0777;
		$world = ( $perms & 0002 ) || ( $perms & 0020 );
		return Scanner::result(
			array(
				'id'           => 'config_perms',
				'category'     => 'config',
				'title'        => __( 'Permessi di wp-config.php', 'grs-security' ),
				'status'       => $world ? 'critical' : 'ok',
				'weight'       => 2,
				/* translators: %s: permessi ottali */
				'message'      => sprintf( __( 'Permessi attuali: %s.', 'grs-security' ), sprintf( '%04o', $perms ) ) . ( $world ? ' ' . __( 'Il file è scrivibile da altri utenti del server.', 'grs-security' ) : '' ),
				'fix'          => $world ? 'manual' : 'none',
				'instructions' => __( 'Imposta i permessi di wp-config.php a 640 o 600 dal file manager dell\'hosting o via FTP. Se dopo la modifica il sito non si apre, torna a 644 e chiedi all\'hosting il valore corretto.', 'grs-security' ),
			)
		);
	}

	/**
	 * HTTPS.
	 *
	 * @return array
	 */
	private static function https() {
		$home  = 0 === strpos( home_url(), 'https://' );
		$admin = 0 === strpos( site_url(), 'https://' );
		$ok    = $home && $admin;
		return Scanner::result(
			array(
				'id'           => 'https',
				'category'     => 'config',
				'title'        => __( 'Sito in HTTPS', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $ok
					? __( 'Indirizzo del sito e di WordPress usano HTTPS.', 'grs-security' )
					: __( 'Il sito non usa HTTPS: password e cookie di accesso viaggiano in chiaro.', 'grs-security' ),
				'fix'          => $ok ? 'none' : 'manual',
				'instructions' => __( 'Attiva un certificato SSL (Let\'s Encrypt è gratuito su quasi tutti gli hosting), poi in Impostazioni > Generali cambia i due indirizzi in https:// e imposta il redirect da HTTP a HTTPS. Dopo il passaggio puoi attivare l\'header HSTS da qui.', 'grs-security' ),
				'link'         => admin_url( 'options-general.php' ),
			)
		);
	}

	/**
	 * Application Passwords.
	 *
	 * @return array
	 */
	private static function app_passwords() {
		$applied = Settings::fix_enabled( 'app_passwords' );
		$in_use  = false;
		if ( ! $applied && class_exists( 'WP_Application_Passwords' ) ) {
			$users  = get_users(
				array(
					'meta_key' => \WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- controllo una tantum durante la scansione.
					'number'   => 1,
					'fields'   => 'ID',
				)
			);
			$in_use = ! empty( $users );
		}
		$available = $applied ? false : wp_is_application_passwords_available();
		return Scanner::result(
			array(
				'id'           => 'app_passwords',
				'category'     => 'config',
				'title'        => __( 'Application Passwords solo se servono', 'grs-security' ),
				'status'       => ( ! $available || $in_use ) ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $in_use
					? __( 'Le Application Passwords sono usate da almeno un utente (app o integrazioni esterne): lasciale attive.', 'grs-security' )
					: ( $available ? __( 'Le Application Passwords sono attive ma nessuno le usa: sono un accesso in più all\'API del sito.', 'grs-security' ) : __( 'Le Application Passwords sono disattivate.', 'grs-security' ) ),
				'fix'          => $in_use ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $in_use && $available,
				'instructions' => __( 'Disattiva le Application Passwords. Riattivale se colleghi app mobili, Zapier o altri servizi che le richiedono.', 'grs-security' ),
			)
		);
	}

	/**
	 * Aggiornamenti automatici minori del core.
	 *
	 * @return array
	 */
	private static function core_auto_updates() {
		$applied = Settings::fix_enabled( 'core_minor_updates' );
		if ( ! class_exists( 'WP_Automatic_Updater' ) ) {
			require_once ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php';
		}
		$disabled_all = ( new \WP_Automatic_Updater() )->is_disabled();
		$constant     = defined( 'WP_AUTO_UPDATE_CORE' ) ? WP_AUTO_UPDATE_CORE : 'minor';
		$minor_off    = ( false === $constant );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.
		$filter_on = (bool) apply_filters( 'allow_minor_auto_core_updates', ! $minor_off );
		$ok        = ! $disabled_all && $filter_on;
		return Scanner::result(
			array(
				'id'           => 'core_auto_updates',
				'category'     => 'config',
				'title'        => __( 'Aggiornamenti di sicurezza automatici del core', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $ok
					? __( 'WordPress installa da solo gli aggiornamenti minori (di sicurezza).', 'grs-security' )
					: ( $disabled_all ? __( 'Tutti gli aggiornamenti automatici sono disattivati (AUTOMATIC_UPDATER_DISABLED o DISALLOW_FILE_MODS).', 'grs-security' ) : __( 'Gli aggiornamenti automatici minori del core sono disattivati.', 'grs-security' ) ),
				'fix'          => $disabled_all ? 'manual' : ( $ok && ! $applied ? 'none' : 'auto' ),
				'fix_applied'  => $applied,
				'recommended'  => ! $ok && ! $disabled_all,
				'instructions' => $disabled_all
					? __( 'Rimuovi da wp-config.php AUTOMATIC_UPDATER_DISABLED (o DISALLOW_FILE_MODS, se non serve), oppure assicurati di aggiornare WordPress a mano entro pochi giorni da ogni rilascio.', 'grs-security' )
					: __( 'Riattiva gli aggiornamenti automatici minori del core (es. 7.1.2 → 7.1.3), che contengono le correzioni di sicurezza.', 'grs-security' ),
			)
		);
	}

	/**
	 * Plugin di backup.
	 *
	 * @return array
	 */
	private static function backup() {
		$found = array();
		foreach ( self::BACKUP_PLUGINS as $file => $name ) {
			if ( is_plugin_active( $file ) ) {
				$found[] = $name;
			}
		}
		return Scanner::result(
			array(
				'id'           => 'backup',
				'category'     => 'config',
				'title'        => __( 'Backup del sito', 'grs-security' ),
				'status'       => $found ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $found
					/* translators: %s: plugin */
					? sprintf( __( 'Plugin di backup attivo: %s. Verifica che i backup vengano salvati fuori dal server (cloud, storage esterno).', 'grs-security' ), implode( ', ', $found ) )
					: __( 'Nessun plugin di backup riconosciuto. Se l\'hosting esegue già backup giornalieri, puoi ignorare questo controllo.', 'grs-security' ),
				'fix'          => $found ? 'none' : 'manual',
				'instructions' => __( 'Il backup è l\'unica protezione che funziona sempre. Verifica con l\'hosting se fa backup giornalieri conservati almeno 14 giorni, oppure installa un plugin come UpdraftPlus con salvataggio su cloud. Prova almeno una volta il ripristino.', 'grs-security' ),
			)
		);
	}

	/**
	 * Prefisso tabelle (solo informativo).
	 *
	 * @return array
	 */
	private static function db_prefix() {
		global $wpdb;
		$default = 'wp_' === $wpdb->prefix;
		return Scanner::result(
			array(
				'id'       => 'db_prefix',
				'category' => 'config',
				'title'    => __( 'Prefisso delle tabelle del database', 'grs-security' ),
				'status'   => 'info',
				'optional' => true,
				'message'  => $default
					? __( 'Il prefisso è quello predefinito "wp_". Cambiarlo su un sito esistente è rischioso e porta un beneficio minimo: non serve intervenire.', 'grs-security' )
					: __( 'Il prefisso delle tabelle non è quello predefinito.', 'grs-security' ),
			)
		);
	}
}
