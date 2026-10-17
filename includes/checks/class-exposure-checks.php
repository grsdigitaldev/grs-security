<?php
/**
 * Controlli su ciò che il sito espone ai visitatori (verificati con richieste al sito stesso).
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Htaccess;
use GRSDigital\Security\Loopback;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Esposizione del sito".
 */
class Exposure_Checks {

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		$home = Loopback::request( add_query_arg( 'grs_security_scan', wp_rand(), home_url( '/' ) ) );
		return array(
			self::xmlrpc(),
			self::user_enum(),
			self::headers( $home ),
			self::hsts( $home ),
			self::login_errors(),
			self::wp_version(),
			self::uploads_php(),
			self::sensitive_files(),
			self::dir_listing(),
		);
	}

	/**
	 * Messaggio per le correzioni via .htaccess su server non Apache.
	 *
	 * @return string
	 */
	private static function nginx_note() {
		return __( 'Il server non usa file .htaccess (probabilmente Nginx): chiedi all\'hosting di aggiungere queste regole alla configurazione del sito:', 'grs-security' ) . "\n" . Htaccess::nginx_snippet();
	}

	/**
	 * XML-RPC.
	 *
	 * @return array
	 */
	private static function xmlrpc() {
		$applied = Settings::fix_enabled( 'xmlrpc' );
		$open    = null;
		if ( ! $applied ) {
			$body     = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>';
			$response = Loopback::request(
				site_url( 'xmlrpc.php' ),
				'POST',
				array(
					'body'    => $body,
					'headers' => array( 'Content-Type' => 'text/xml' ),
				)
			);
			if ( null !== $response ) {
				$open = 200 === Loopback::code( $response ) && false !== strpos( wp_remote_retrieve_body( $response ), 'pingback.ping' );
			}
		}
		if ( $applied ) {
			$status = 'ok';
			$msg    = 'pingback' === Settings::get( 'xmlrpc_mode' )
				? __( 'XML-RPC attivo senza pingback e multicall (usati per attacchi e amplificazione del brute force).', 'grs-security' )
				: __( 'XML-RPC disattivato.', 'grs-security' );
		} elseif ( null === $open ) {
			$status = 'warning';
			$msg    = __( 'XML-RPC risulta attivo (verifica dal sito non disponibile). È un bersaglio frequente per attacchi alle password.', 'grs-security' );
		} elseif ( $open ) {
			$status = 'warning';
			$msg    = __( 'XML-RPC è attivo e risponde con pingback e multicall: permette di provare centinaia di password con una sola richiesta.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = __( 'XML-RPC è già bloccato (dall\'hosting o da un altro plugin).', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'xmlrpc',
				'category'     => 'exposure',
				'title'        => __( 'XML-RPC disattivato', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => ( 'ok' === $status && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => 'ok' !== $status,
				'instructions' => __( 'Disattiva XML-RPC. Se usi Jetpack o l\'app WordPress per smartphone, nelle impostazioni puoi scegliere di bloccare solo pingback e multicall.', 'grs-security' ),
			)
		);
	}

	/**
	 * Enumerazione utenti.
	 *
	 * @return array
	 */
	private static function user_enum() {
		$applied = Settings::fix_enabled( 'user_enum' );
		$exposed = null;
		if ( ! $applied ) {
			$response = Loopback::request( rest_url( 'wp/v2/users' ) );
			if ( null !== $response ) {
				$data    = json_decode( wp_remote_retrieve_body( $response ), true );
				$exposed = 200 === Loopback::code( $response ) && is_array( $data ) && isset( $data[0]['slug'] );
			}
		}
		$ok = $applied || false === $exposed;
		return Scanner::result(
			array(
				'id'           => 'user_enum',
				'category'     => 'exposure',
				'title'        => __( 'Nomi utente non elencabili', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $ok
					? __( 'I nomi utente non sono elencati pubblicamente da ?author= e dalla REST API.', 'grs-security' )
					: __( 'Chiunque può ottenere l\'elenco dei nomi utente da /wp-json/wp/v2/users o da ?author=1: metà del lavoro per indovinare un accesso.', 'grs-security' ),
				'fix'          => ( $ok && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $ok,
				'instructions' => __( 'Blocca ?author=N, l\'endpoint REST degli utenti e la sitemap degli autori per i visitatori non connessi, e toglie il nome dell\'autore dagli embed. Le pagine archivio degli autori restano visibili.', 'grs-security' ),
			)
		);
	}

	/**
	 * Header HTTP di sicurezza.
	 *
	 * @param array|null $home Risposta della home.
	 * @return array
	 */
	private static function headers( $home ) {
		$applied = Settings::fix_enabled( 'headers' );
		$missing = array();
		if ( null !== $home ) {
			foreach ( array( 'x-content-type-options', 'x-frame-options', 'referrer-policy' ) as $name ) {
				$value = wp_remote_retrieve_header( $home, $name );
				if ( '' === $value || array() === $value ) {
					$missing[] = $name;
				}
			}
		}
		$ok = $applied || ( null !== $home && empty( $missing ) );
		return Scanner::result(
			array(
				'id'           => 'headers',
				'category'     => 'exposure',
				'title'        => __( 'Header HTTP di sicurezza', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $ok
					? __( 'Il sito invia gli header X-Content-Type-Options, X-Frame-Options e Referrer-Policy.', 'grs-security' )
					: ( null === $home
						? __( 'Impossibile leggere gli header del sito (richiesta al sito non riuscita).', 'grs-security' )
						/* translators: %s: elenco header */
						: sprintf( __( 'Header mancanti: %s. Proteggono da clickjacking e da alcuni attacchi nel browser.', 'grs-security' ), implode( ', ', $missing ) ) ),
				'fix'          => ( $ok && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $ok,
				'instructions' => __( 'Invia gli header X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN e Referrer-Policy: strict-origin-when-cross-origin. Se il sito deve essere mostrato dentro un iframe di un altro dominio, non attivarlo.', 'grs-security' ),
			)
		);
	}

	/**
	 * HSTS (opzionale).
	 *
	 * @param array|null $home Risposta della home.
	 * @return array
	 */
	private static function hsts( $home ) {
		$applied = Settings::fix_enabled( 'hsts' );
		$https   = 0 === strpos( home_url(), 'https://' );
		$present = null !== $home && '' !== wp_remote_retrieve_header( $home, 'strict-transport-security' );
		$ok      = $applied || $present;
		return Scanner::result(
			array(
				'id'           => 'hsts',
				'category'     => 'exposure',
				'title'        => __( 'HSTS (HTTPS obbligatorio nel browser)', 'grs-security' ),
				'status'       => $ok ? 'ok' : ( $https ? 'warning' : 'info' ),
				'weight'       => 1,
				'optional'     => true,
				'message'      => $ok
					? __( 'Il browser è istruito a usare sempre HTTPS per questo sito.', 'grs-security' )
					: __( 'Header HSTS assente. Facoltativo: attivalo solo se l\'intero dominio funziona stabilmente in HTTPS.', 'grs-security' ),
				'fix'          => ( $https && ! ( $present && ! $applied ) ) ? 'auto' : 'none',
				'fix_applied'  => $applied,
				'instructions' => __( 'Invia Strict-Transport-Security con validità di un anno (solo sulle pagine HTTPS). Attenzione: per un anno i browser che hanno visitato il sito rifiuteranno la versione HTTP, anche se il certificato scade.', 'grs-security' ),
			)
		);
	}

	/**
	 * Messaggi di errore del login.
	 *
	 * @return array
	 */
	private static function login_errors() {
		$applied = Settings::fix_enabled( 'login_errors' );
		return Scanner::result(
			array(
				'id'           => 'login_errors',
				'category'     => 'exposure',
				'title'        => __( 'Errori di login generici', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $applied
					? __( 'Il login non rivela se un nome utente o un\'email esistono.', 'grs-security' )
					: __( 'Il messaggio di errore del login conferma se un nome utente esiste ("password errata per l\'utente...").', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Mostra lo stesso messaggio generico per utente inesistente e password errata.', 'grs-security' ),
			)
		);
	}

	/**
	 * Versione di WordPress esposta (opzionale).
	 *
	 * @return array
	 */
	private static function wp_version() {
		$applied = Settings::fix_enabled( 'hide_version' );
		return Scanner::result(
			array(
				'id'           => 'wp_version',
				'category'     => 'exposure',
				'title'        => __( 'Versione di WordPress nascosta', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'info',
				'weight'       => 1,
				'optional'     => true,
				'message'      => $applied
					? __( 'Il meta generator e la versione nei file CSS/JS del core sono nascosti.', 'grs-security' )
					: __( 'La versione di WordPress è visibile nel codice della pagina. Nasconderla è una misura minore: la vera protezione è tenere WordPress aggiornato.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'instructions' => __( 'Rimuove il meta generator e sostituisce ?ver= dei file del core con un codice che cambia a ogni versione (la cache dei browser continua a funzionare).', 'grs-security' ),
			)
		);
	}

	/**
	 * Esecuzione di PHP in uploads (test reale con un file temporaneo).
	 *
	 * @return array
	 */
	private static function uploads_php() {
		$applied   = Settings::fix_enabled( 'htaccess_uploads' );
		$supported = Htaccess::supported();
		$runs      = self::php_runs_in_uploads();

		if ( false === $runs ) {
			$status = 'ok';
			$msg    = __( 'I file PHP caricati in uploads non vengono eseguiti.', 'grs-security' );
		} elseif ( true === $runs ) {
			$status = 'critical';
			$msg    = __( 'Un file PHP messo in uploads viene eseguito: se un plugin vulnerabile permette di caricare file, l\'attaccante prende il controllo del sito.', 'grs-security' );
		} else {
			$status = $applied ? 'ok' : 'warning';
			$msg    = $applied
				? __( 'Regola di blocco attiva (verifica dal sito non disponibile).', 'grs-security' )
				: __( 'Non è stato possibile verificare se i file PHP in uploads vengono eseguiti.', 'grs-security' );
		}
		if ( true === $runs && $applied ) {
			$msg .= ' ' . __( 'La regola .htaccess è attiva ma non ha effetto: il server potrebbe ignorare i file .htaccess.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'uploads_php',
				'category'     => 'exposure',
				'title'        => __( 'PHP bloccato nella cartella uploads', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $msg,
				'fix'          => $supported ? ( ( 'ok' === $status && ! $applied ) ? 'none' : 'auto' ) : ( 'ok' === $status ? 'none' : 'manual' ),
				'fix_applied'  => $applied,
				'recommended'  => $supported && 'ok' !== $status,
				'instructions' => $supported
					? __( 'Aggiunge in wp-content/uploads/.htaccess una regola che impedisce l\'esecuzione di file .php, .phtml, .phar e simili.', 'grs-security' )
					: self::nginx_note(),
			)
		);
	}

	/**
	 * Crea un file PHP temporaneo in uploads e verifica se viene eseguito.
	 *
	 * @return bool|null True eseguito, false non eseguito, null non verificabile.
	 */
	private static function php_runs_in_uploads() {
		$uploads = wp_upload_dir( null, false );
		if ( ! empty( $uploads['error'] ) || ! wp_is_writable( $uploads['basedir'] ) ) {
			return null;
		}
		$token = wp_generate_password( 24, false, false );
		$name  = 'grs-security-test-' . strtolower( wp_generate_password( 12, false, false ) ) . '.php';
		$file  = trailingslashit( $uploads['basedir'] ) . $name;
		$code  = '<?php echo strrev(' . var_export( strrev( $token ), true ) . ');'; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- genera il letterale del file di test.
		if ( false === file_put_contents( $file, $code ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- file di test temporaneo.
			return null;
		}
		$response = Loopback::request( trailingslashit( $uploads['baseurl'] ) . $name );
		wp_delete_file( $file );
		if ( null === $response ) {
			return null;
		}
		$body = wp_remote_retrieve_body( $response );
		if ( 200 === Loopback::code( $response ) && false !== strpos( $body, $token ) ) {
			return true;
		}
		return false;
	}

	/**
	 * File sensibili raggiungibili e copie di backup lasciate nella root.
	 *
	 * @return array
	 */
	private static function sensitive_files() {
		$applied   = Settings::fix_enabled( 'htaccess_sensitive' );
		$supported = Htaccess::supported();
		$found     = array();

		$patterns = array( 'wp-config.php.*', 'wp-config-*.php', 'wp-config.*.php', '*.sql', '*.sql.gz', '*.bak', '*.old', '*.zip', '*.tar', '*.tar.gz', '.env', 'error_log', 'php_errors.log' );
		foreach ( $patterns as $pattern ) {
			$matches = glob( ABSPATH . $pattern );
			foreach ( is_array( $matches ) ? $matches : array() as $path ) {
				$name = basename( $path );
				if ( 'wp-config-sample.php' === $name || 0 === strpos( $name, 'wp-config-grs-backup-' ) ) {
					continue;
				}
				$found[] = $name;
			}
		}
		if ( is_dir( ABSPATH . '.git' ) ) {
			$found[] = '.git/';
		}
		$found    = array_values( array_unique( $found ) );
		$readme   = file_exists( ABSPATH . 'readme.html' );
		$exposed  = false;
		$response = null;
		if ( $readme && ! $applied ) {
			$response = Loopback::request( site_url( 'readme.html' ) );
			$exposed  = 200 === Loopback::code( $response );
		}

		if ( $found ) {
			$status = 'critical';
			/* translators: %s: elenco file */
			$msg = sprintf( __( 'Nella cartella principale ci sono file che possono contenere password o il database: %s.', 'grs-security' ), implode( ', ', $found ) );
		} elseif ( $exposed ) {
			$status = 'warning';
			$msg    = __( 'readme.html e license.txt sono raggiungibili e rivelano che il sito è WordPress e, a volte, la versione.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = $applied
				? __( 'Accesso via browser bloccato per readme.html, license.txt, file di log, backup e cartelle .git.', 'grs-security' )
				: __( 'Nessun file sensibile trovato nella cartella principale.', 'grs-security' );
		}

		$instructions  = $found
			? __( 'Scarica in locale i file elencati se ti servono, poi eliminali dal server via FTP o dal file manager dell\'hosting: le copie di wp-config e i dump del database non devono stare nella cartella pubblica.', 'grs-security' ) . ' '
			: '';
		$instructions .= $supported
			? __( 'La correzione automatica blocca via .htaccess l\'accesso a readme.html, license.txt, file .log, .sql, .bak, .old e alle cartelle .git.', 'grs-security' )
			: self::nginx_note();

		return Scanner::result(
			array(
				'id'           => 'sensitive_files',
				'category'     => 'exposure',
				'title'        => __( 'File sensibili protetti', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $msg,
				'fix'          => $found ? 'manual' : ( $supported ? ( ( 'ok' === $status && ! $applied ) ? 'none' : 'auto' ) : ( 'ok' === $status ? 'none' : 'manual' ) ),
				'fix_applied'  => $applied,
				'recommended'  => $supported && ! $applied,
				'instructions' => $instructions,
			)
		);
	}

	/**
	 * Elenco dei file nelle cartelle (directory listing).
	 *
	 * @return array
	 */
	private static function dir_listing() {
		$applied   = Settings::fix_enabled( 'htaccess_indexes' );
		$supported = Htaccess::supported();
		$uploads   = wp_upload_dir( null, false );
		$probe     = trailingslashit( $uploads['baseurl'] ) . gmdate( 'Y' ) . '/';
		$dir       = trailingslashit( $uploads['basedir'] ) . gmdate( 'Y' );
		if ( ! is_dir( $dir ) || file_exists( $dir . '/index.php' ) || file_exists( $dir . '/index.html' ) ) {
			$probe = trailingslashit( $uploads['baseurl'] );
		}
		$response = Loopback::request( $probe );
		$listed   = null === $response ? null : ( 200 === Loopback::code( $response ) && false !== stripos( wp_remote_retrieve_body( $response ), 'Index of' ) );

		if ( true === $listed ) {
			$status = 'warning';
			$msg    = __( 'Il server mostra l\'elenco dei file delle cartelle senza index (es. uploads): chiunque può sfogliare i file caricati.', 'grs-security' );
		} elseif ( null === $listed && ! $applied ) {
			$status = 'unknown';
			$msg    = __( 'Non è stato possibile verificare l\'elenco dei file delle cartelle.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = __( 'L\'elenco dei file delle cartelle non è visibile.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'dir_listing',
				'category'     => 'exposure',
				'title'        => __( 'Elenco dei file delle cartelle disattivato', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => $supported ? ( ( 'ok' === $status && ! $applied ) ? 'none' : 'auto' ) : ( 'warning' === $status ? 'manual' : 'none' ),
				'fix_applied'  => $applied,
				'recommended'  => $supported && 'warning' === $status,
				'instructions' => $supported
					? __( 'Aggiunge "Options -Indexes" al .htaccess principale. Se l\'hosting non lo consente, il plugin se ne accorge e annulla la modifica.', 'grs-security' )
					: self::nginx_note(),
			)
		);
	}
}
