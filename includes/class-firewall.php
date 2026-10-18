<?php
/**
 * Firewall applicativo leggero: blocca richieste con schemi di attacco evidenti.
 *
 * Limite noto: gira dentro WordPress, quindi dopo il caricamento dei plugin.
 * Non sostituisce il WAF dell'hosting o di un servizio come Cloudflare.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Regole conservative per ridurre i falsi positivi.
 */
class Firewall {

	const MAX_VALUES = 300;
	const MAX_LENGTH = 65536;

	/**
	 * Regole: id => [ regex, ambiti (get|post|uri|ua), descrizione ].
	 *
	 * @return array
	 */
	public static function rules() {
		$rules = array(
			'sqli_union'     => array( '/\bunion\b(?:\s|\/\*.*?\*\/|\+)+(?:all(?:\s|\+)+)?select\b/i', array( 'get', 'post', 'uri' ), 'SQL injection (UNION SELECT)' ),
			'sqli_functions' => array( '/\binformation_schema\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\bload_file\s*\(|\binto\s+(?:out|dump)file\b/i', array( 'get', 'post', 'uri' ), 'SQL injection (functions)' ),
			'traversal'      => array( '/(?:\.\.[\/\\\\]){2,}|\/etc\/passwd|(?:\.\.[\/\\\\])+wp-config\.php/i', array( 'get', 'post', 'uri' ), 'Directory traversal' ),
			'php_injection'  => array( '/<\?php|\b(?:base64_decode|gzinflate|str_rot13|shell_exec|passthru)\s*\(|\b(?:php|phar|expect|zip|data):\/\/(?:input|filter|text|stdin|[a-z0-9])/i', array( 'get', 'post' ), 'PHP code injection' ),
			'xss'            => array( '/<script\b|javascript\s*:|\bon(?:error|load|mouseover|focus|toggle)\s*=|<(?:iframe|svg|img)\b[^>]*\bon[a-z]+\s*=/i', array( 'get', 'uri' ), 'Cross-site scripting (XSS)' ),
			'scanner_ua'     => array( '/\b(?:sqlmap|nikto|wpscan|acunetix|nessus|masscan|nmap\s+scripting|dirbuster|gobuster|nuclei|zgrab|havij|w3af|fimap|netsparker)\b/i', array( 'ua' ), 'Vulnerability scanner' ),
		);
		/**
		 * Regole del firewall.
		 *
		 * @param array $rules id => [ regex, ambiti, descrizione ].
		 */
		return (array) apply_filters( 'grs_security_firewall_rules', $rules );
	}

	/**
	 * Controllo eseguito su plugins_loaded (priorità minima).
	 *
	 * @return void
	 */
	public static function early_check() {
		if ( ! Settings::fix_enabled( 'firewall' ) ) {
			return;
		}
		if ( defined( 'GRS_SECURITY_DISABLE_FIREWALL' ) && GRS_SECURITY_DISABLE_FIREWALL ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return;
		}
		$ip = Ip::current();
		if ( Ip::is_whitelisted( $ip ) || self::trusted_user() ) {
			return;
		}
		$match = self::inspect();
		if ( null === $match ) {
			return;
		}
		self::handle( $match, $ip );
	}

	/**
	 * Utenti connessi con permessi di redazione sono esclusi (scrivono HTML e codice legittimo).
	 *
	 * @return bool
	 */
	private static function trusted_user() {
		if ( ! function_exists( 'wp_validate_auth_cookie' ) ) {
			return false;
		}
		$user_id = wp_validate_auth_cookie( '', 'logged_in' );
		return $user_id && user_can( $user_id, 'edit_posts' );
	}

	/**
	 * Analizza la richiesta corrente.
	 *
	 * @return array|null [ rule_id, descrizione, ambito ] alla prima corrispondenza.
	 */
	public static function inspect() {
		// phpcs:disable WordPress.Security.NonceVerification,WordPress.Security.ValidatedSanitizedInput -- ispezione in sola lettura dei dati grezzi, nessun salvataggio.
		$targets = array(
			'uri'  => isset( $_SERVER['REQUEST_URI'] ) ? array( rawurldecode( (string) wp_unslash( $_SERVER['REQUEST_URI'] ) ) ) : array(),
			'get'  => self::flatten( wp_unslash( $_GET ) ),
			'post' => self::flatten( wp_unslash( $_POST ) ),
			'ua'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? array( (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : array(),
		);
		// phpcs:enable
		return self::match( $targets );
	}

	/**
	 * Confronta i valori con le regole.
	 *
	 * @param array $targets ambito => valori.
	 * @return array|null
	 */
	public static function match( array $targets ) {
		foreach ( self::rules() as $id => $rule ) {
			list( $regex, $scopes, $label ) = $rule;
			foreach ( (array) $scopes as $scope ) {
				if ( empty( $targets[ $scope ] ) ) {
					continue;
				}
				foreach ( $targets[ $scope ] as $value ) {
					if ( preg_match( $regex, $value ) || preg_match( $regex, rawurldecode( $value ) ) ) {
						return array( $id, $label, $scope );
					}
				}
			}
		}
		return null;
	}

	/**
	 * Appiattisce un array di input (chiavi e valori), con limiti di dimensione.
	 *
	 * @param mixed $data Dati.
	 * @return string[]
	 */
	public static function flatten( $data ) {
		$out   = array();
		$stack = array( $data );
		$count = 0;
		while ( $stack && $count < self::MAX_VALUES ) {
			$item = array_pop( $stack );
			if ( is_array( $item ) ) {
				foreach ( $item as $key => $value ) {
					if ( is_string( $key ) ) {
						$out[] = substr( $key, 0, 256 );
						++$count;
					}
					$stack[] = $value;
				}
			} elseif ( is_scalar( $item ) ) {
				$out[] = substr( (string) $item, 0, self::MAX_LENGTH );
				++$count;
			}
		}
		return $out;
	}

	/**
	 * Registra e, in modalità blocco, interrompe la richiesta.
	 *
	 * @param array  $found Corrispondenza.
	 * @param string $ip    IP.
	 * @return void
	 */
	private static function handle( array $found, $ip ) {
		$block = 'block' === Settings::get( 'firewall_mode', 'block' );

		// Al massimo una riga di registro per IP e regola ogni 10 minuti.
		$key = 'grs_security_fw_' . md5( $ip . '|' . $found[0] );
		if ( ! get_transient( $key ) ) {
			set_transient( $key, 1, 10 * MINUTE_IN_SECONDS );
			$uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			// Testi fissi (vedi text()): qui siamo prima di after_setup_theme e WP 6.7+ segnalerebbe il caricamento anticipato delle traduzioni.
			Logger::log(
				'firewall_' . ( $block ? 'blocked' : 'detected' ),
				'warning',
				sprintf(
					self::text( $block ? 'logged_blocked' : 'logged_detected' ),
					self::text( 'rule_' . $found[0], $found[1] ),
					$found[2]
				),
				array(
					'ip'      => $ip,
					'context' => array(
						'rule' => $found[0],
						'uri'  => substr( $uri, 0, 500 ),
					),
				)
			);
		}

		if ( ! $block ) {
			return;
		}
		status_header( 403 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>403</title></head><body style="font-family:sans-serif;padding:3em;text-align:center"><h1>403</h1><p>'
			. esc_html( self::text( 'blocked_page' ) )
			. '</p></body></html>';
		exit;
	}

	/**
	 * Testi del firewall in inglese o in italiano, scelti in base alla lingua del sito.
	 *
	 * Il firewall gira su plugins_loaded, prima di after_setup_theme: da WP 6.7 le funzioni
	 * di traduzione qui genererebbero un avviso, quindi i testi sono fissi nelle due lingue
	 * principali e si possono cambiare con il filtro grs_security_firewall_text.
	 *
	 * @param string $key      Chiave del testo.
	 * @param string $fallback Testo se la chiave non esiste (es. descrizione di una regola personalizzata).
	 * @return string
	 */
	public static function text( $key, $fallback = '' ) {
		$texts = array(
			'en' => array(
				'blocked_page'        => 'The request was blocked for security reasons. If you think this is an error, contact the site owner.',
				'logged_blocked'      => 'Request blocked: %1$s (in %2$s).',
				'logged_detected'     => 'Suspicious request (logged only): %1$s (in %2$s).',
				'rule_sqli_union'     => 'SQL injection (UNION SELECT)',
				'rule_sqli_functions' => 'SQL injection (functions)',
				'rule_traversal'      => 'Directory traversal',
				'rule_php_injection'  => 'PHP code injection',
				'rule_xss'            => 'Cross-site scripting (XSS)',
				'rule_scanner_ua'     => 'Vulnerability scanner',
			),
			'it' => array(
				'blocked_page'        => 'La richiesta è stata bloccata per motivi di sicurezza. Se pensi sia un errore, contatta il gestore del sito.',
				'logged_blocked'      => 'Richiesta bloccata: %1$s (in %2$s).',
				'logged_detected'     => 'Richiesta sospetta (solo registrata): %1$s (in %2$s).',
				'rule_sqli_union'     => 'SQL injection (UNION SELECT)',
				'rule_sqli_functions' => 'SQL injection (funzioni)',
				'rule_traversal'      => 'Directory traversal',
				'rule_php_injection'  => 'Iniezione di codice PHP',
				'rule_xss'            => 'Cross-site scripting (XSS)',
				'rule_scanner_ua'     => 'Scanner di vulnerabilità',
			),
		);
		$lang  = 'it' === strtolower( substr( (string) get_locale(), 0, 2 ) ) ? 'it' : 'en';
		$text  = isset( $texts[ $lang ][ $key ] ) ? $texts[ $lang ][ $key ] : ( '' !== $fallback ? $fallback : ( isset( $texts['en'][ $key ] ) ? $texts['en'][ $key ] : $key ) );
		/**
		 * Testi del firewall (pagina di blocco, righe del registro, nomi delle regole).
		 *
		 * @param string $text Testo.
		 * @param string $key  Chiave (blocked_page, logged_blocked, logged_detected, rule_<id>).
		 * @param string $lang Lingua scelta (en o it).
		 */
		return (string) apply_filters( 'grs_security_firewall_text', $text, $key, $lang );
	}
}
