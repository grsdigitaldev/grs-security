<?php
/**
 * Richieste dal sito verso sé stesso, per verificare cosa vede un visitatore.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Richieste loopback con gestione dell'indisponibilità.
 */
class Loopback {

	/**
	 * True se una richiesta è già fallita a livello di rete.
	 *
	 * @var bool
	 */
	private static $broken = false;

	/**
	 * Richiesta HTTP non autenticata.
	 *
	 * @param string $url    URL.
	 * @param string $method GET|POST|HEAD.
	 * @param array  $args   Argomenti aggiuntivi.
	 * @return array|null Risposta oppure null se il loopback non funziona.
	 */
	public static function request( $url, $method = 'GET', array $args = array() ) {
		if ( self::$broken ) {
			return null;
		}
		$args = array_merge(
			array(
				'method'      => $method,
				'timeout'     => 6,
				'redirection' => 0,
				'cookies'     => array(),
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.
				'headers'     => array( 'Cache-Control' => 'no-cache' ),
			),
			$args
		);
		/**
		 * Permette di intercettare le richieste loopback (test).
		 *
		 * @param array|null $pre  Risposta precalcolata.
		 * @param string     $url  URL.
		 * @param array      $args Argomenti.
		 */
		$pre = apply_filters( 'grs_security_loopback_pre', null, $url, $args );
		if ( null !== $pre ) {
			return $pre;
		}
		$response = wp_remote_request( $url, $args );
		if ( is_wp_error( $response ) ) {
			self::$broken = true;
			return null;
		}
		return $response;
	}

	/**
	 * Il loopback risulta non disponibile?
	 *
	 * @return bool
	 */
	public static function is_broken() {
		return self::$broken;
	}

	/**
	 * Codice HTTP della risposta.
	 *
	 * @param array|null $response Risposta.
	 * @return int
	 */
	public static function code( $response ) {
		return is_array( $response ) ? (int) wp_remote_retrieve_response_code( $response ) : 0;
	}
}
