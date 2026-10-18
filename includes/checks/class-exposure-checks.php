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
		return __( 'The server does not use .htaccess files (probably Nginx): ask the hosting to add these rules to the site configuration:', 'grs-security' ) . "\n" . Htaccess::nginx_snippet();
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
				? __( 'XML-RPC enabled without pingbacks and multicall (used for attacks and to amplify brute force).', 'grs-security' )
				: __( 'XML-RPC disabled.', 'grs-security' );
		} elseif ( null === $open ) {
			$status = 'warning';
			$msg    = __( 'XML-RPC appears to be enabled (check from the site not available). It is a frequent target of password attacks.', 'grs-security' );
		} elseif ( $open ) {
			$status = 'warning';
			$msg    = __( 'XML-RPC is enabled and answers with pingbacks and multicall: it allows hundreds of passwords to be tried with a single request.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = __( 'XML-RPC is already blocked (by the hosting or another plugin).', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'xmlrpc',
				'category'     => 'exposure',
				'title'        => __( 'XML-RPC disabled', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => ( 'ok' === $status && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => 'ok' !== $status,
				'instructions' => __( 'Disables XML-RPC. If you use Jetpack or the WordPress mobile app, in the settings you can choose to block only pingbacks and multicall.', 'grs-security' ),
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
				'title'        => __( 'Usernames not listable', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $ok
					? __( 'Usernames are not publicly listed by ?author= and by the REST API.', 'grs-security' )
					: __( 'Anyone can get the list of usernames from /wp-json/wp/v2/users or from ?author=1: half the work needed to guess a login.', 'grs-security' ),
				'fix'          => ( $ok && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $ok,
				'instructions' => __( 'Blocks ?author=N, the users REST endpoint and the authors sitemap for visitors who are not logged in, and removes the author name from embeds. Author archive pages remain visible.', 'grs-security' ),
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
				'title'        => __( 'Security HTTP headers', 'grs-security' ),
				'status'       => $ok ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $ok
					? __( 'The site sends the X-Content-Type-Options, X-Frame-Options and Referrer-Policy headers.', 'grs-security' )
					: ( null === $home
						? __( 'Unable to read the site headers (request to the site failed).', 'grs-security' )
						/* translators: %s: list of headers */
						: sprintf( __( 'Missing headers: %s. They protect against clickjacking and some browser attacks.', 'grs-security' ), implode( ', ', $missing ) ) ),
				'fix'          => ( $ok && ! $applied ) ? 'none' : 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $ok,
				'instructions' => __( 'Sends the headers X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN and Referrer-Policy: strict-origin-when-cross-origin. Do not enable it if the site must be shown inside an iframe on another domain.', 'grs-security' ),
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
				'title'        => __( 'HSTS (HTTPS enforced in the browser)', 'grs-security' ),
				'status'       => $ok ? 'ok' : ( $https ? 'warning' : 'info' ),
				'weight'       => 1,
				'optional'     => true,
				'message'      => $ok
					? __( 'The browser is told to always use HTTPS for this site.', 'grs-security' )
					: __( 'HSTS header missing. Optional: enable it only if the whole domain works reliably on HTTPS.', 'grs-security' ),
				'fix'          => ( $https && ! ( $present && ! $applied ) ) ? 'auto' : 'none',
				'fix_applied'  => $applied,
				'instructions' => __( 'Sends Strict-Transport-Security valid for one year (on HTTPS pages only). Warning: for one year, browsers that visited the site will refuse the HTTP version, even if the certificate expires.', 'grs-security' ),
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
				'title'        => __( 'Generic login errors', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $applied
					? __( 'Login does not reveal whether a username or email exists.', 'grs-security' )
					: __( 'The login error message confirms whether a username exists ("incorrect password for the user...").', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Shows the same generic message for a non-existent user and a wrong password.', 'grs-security' ),
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
				'title'        => __( 'WordPress version hidden', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'info',
				'weight'       => 1,
				'optional'     => true,
				'message'      => $applied
					? __( 'The generator meta tag and the version in core CSS/JS files are hidden.', 'grs-security' )
					: __( 'The WordPress version is visible in the page code. Hiding it is a minor measure: the real protection is keeping WordPress up to date.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'instructions' => __( 'Removes the generator meta tag and replaces ?ver= of core files with a code that changes with each version (browser caching keeps working).', 'grs-security' ),
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
			$msg    = __( 'PHP files uploaded to uploads are not executed.', 'grs-security' );
		} elseif ( true === $runs ) {
			$status = 'critical';
			$msg    = __( 'A PHP file placed in uploads is executed: if a vulnerable plugin allows file uploads, an attacker takes control of the site.', 'grs-security' );
		} else {
			$status = $applied ? 'ok' : 'warning';
			$msg    = $applied
				? __( 'Blocking rule active (check from the site not available).', 'grs-security' )
				: __( 'It was not possible to check whether PHP files in uploads are executed.', 'grs-security' );
		}
		if ( true === $runs && $applied ) {
			$msg .= ' ' . __( 'The .htaccess rule is in place but has no effect: the server may be ignoring .htaccess files.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'uploads_php',
				'category'     => 'exposure',
				'title'        => __( 'PHP blocked in the uploads folder', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $msg,
				'fix'          => $supported ? ( ( 'ok' === $status && ! $applied ) ? 'none' : 'auto' ) : ( 'ok' === $status ? 'none' : 'manual' ),
				'fix_applied'  => $applied,
				'recommended'  => $supported && 'ok' !== $status,
				'instructions' => $supported
					? __( 'Adds a rule to wp-content/uploads/.htaccess that prevents the execution of .php, .phtml, .phar and similar files.', 'grs-security' )
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
			/* translators: %s: list of files */
			$msg = sprintf( __( 'The root folder contains files that may hold passwords or the database: %s.', 'grs-security' ), implode( ', ', $found ) );
		} elseif ( $exposed ) {
			$status = 'warning';
			$msg    = __( 'readme.html and license.txt are reachable and reveal that the site runs WordPress and, sometimes, its version.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = $applied
				? __( 'Browser access blocked for readme.html, license.txt, log files, backups and .git folders.', 'grs-security' )
				: __( 'No sensitive files found in the root folder.', 'grs-security' );
		}

		$instructions  = $found
			? __( 'Download the listed files locally if you need them, then delete them from the server via FTP or the hosting file manager: copies of wp-config and database dumps must not sit in the public folder.', 'grs-security' ) . ' '
			: '';
		$instructions .= $supported
			? __( 'The automatic fix blocks access via .htaccess to readme.html, license.txt, .log, .sql, .bak, .old files and .git folders.', 'grs-security' )
			: self::nginx_note();

		return Scanner::result(
			array(
				'id'           => 'sensitive_files',
				'category'     => 'exposure',
				'title'        => __( 'Sensitive files protected', 'grs-security' ),
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
			$msg    = __( 'The server shows the file list of folders without an index (e.g. uploads): anyone can browse the uploaded files.', 'grs-security' );
		} elseif ( null === $listed && ! $applied ) {
			$status = 'unknown';
			$msg    = __( 'It was not possible to check folder file listing.', 'grs-security' );
		} else {
			$status = 'ok';
			$msg    = __( 'Folder file listing is not visible.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'dir_listing',
				'category'     => 'exposure',
				'title'        => __( 'Folder file listing disabled', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => $supported ? ( ( 'ok' === $status && ! $applied ) ? 'none' : 'auto' ) : ( 'warning' === $status ? 'manual' : 'none' ),
				'fix_applied'  => $applied,
				'recommended'  => $supported && 'warning' === $status,
				'instructions' => $supported
					? __( 'Adds "Options -Indexes" to the main .htaccess. If the hosting does not allow it, the plugin notices and undoes the change.', 'grs-security' )
					: self::nginx_note(),
			)
		);
	}
}
