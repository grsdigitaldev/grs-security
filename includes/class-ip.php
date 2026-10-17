<?php
/**
 * Rilevamento dell'IP del visitatore e lista IP fidati.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Utility IP.
 */
class Ip {

	/**
	 * Sorgenti IP supportate.
	 *
	 * @return array
	 */
	public static function sources() {
		return array(
			'REMOTE_ADDR'           => __( 'Connessione diretta (REMOTE_ADDR, predefinito)', 'grs-security' ),
			'HTTP_CF_CONNECTING_IP' => __( 'Cloudflare (CF-Connecting-IP)', 'grs-security' ),
			'HTTP_X_FORWARDED_FOR'  => __( 'Proxy o bilanciatore (X-Forwarded-For)', 'grs-security' ),
			'HTTP_X_REAL_IP'        => __( 'Proxy Nginx (X-Real-IP)', 'grs-security' ),
		);
	}

	/**
	 * IP del visitatore secondo la sorgente configurata.
	 *
	 * @return string IP valido oppure stringa vuota.
	 */
	public static function current() {
		$source = (string) Settings::get( 'ip_source', 'REMOTE_ADDR' );
		$ip     = self::from_server( $source );
		if ( '' === $ip && 'REMOTE_ADDR' !== $source ) {
			$ip = self::from_server( 'REMOTE_ADDR' );
		}
		return $ip;
	}

	/**
	 * Legge un IP da $_SERVER.
	 *
	 * @param string $key Chiave.
	 * @return string
	 */
	public static function from_server( $key ) {
		if ( empty( $_SERVER[ $key ] ) || ! is_string( $_SERVER[ $key ] ) ) {
			return '';
		}
		$raw = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
		if ( 'HTTP_X_FORWARDED_FOR' === $key ) {
			$list = explode( ',', $raw );
			$raw  = trim( $list[0] );
		}
		$raw = trim( $raw );
		return filter_var( $raw, FILTER_VALIDATE_IP ) ? $raw : '';
	}

	/**
	 * Valida un IP o un intervallo CIDR.
	 *
	 * @param string $rule Regola.
	 * @return bool
	 */
	public static function is_valid_rule( $rule ) {
		if ( filter_var( $rule, FILTER_VALIDATE_IP ) ) {
			return true;
		}
		if ( false === strpos( $rule, '/' ) ) {
			return false;
		}
		list( $net, $bits ) = explode( '/', $rule, 2 );
		if ( ! ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( filter_var( $net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return $bits >= 0 && $bits <= 32;
		}
		if ( filter_var( $net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $bits >= 0 && $bits <= 128;
		}
		return false;
	}

	/**
	 * Verifica se un IP rientra in una regola (IP singolo o CIDR).
	 *
	 * @param string $ip   IP.
	 * @param string $rule Regola.
	 * @return bool
	 */
	public static function matches( $ip, $rule ) {
		if ( false === strpos( $rule, '/' ) ) {
			return inet_pton( $ip ) === inet_pton( $rule );
		}
		list( $net, $bits ) = explode( '/', $rule, 2 );
		$ip_bin             = inet_pton( $ip );
		$net_bin            = inet_pton( $net );
		if ( false === $ip_bin || false === $net_bin || strlen( $ip_bin ) !== strlen( $net_bin ) ) {
			return false;
		}
		$bits  = (int) $bits;
		$bytes = intdiv( $bits, 8 );
		$rest  = $bits % 8;
		if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $net_bin, 0, $bytes ) ) {
			return false;
		}
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		return ( ord( $ip_bin[ $bytes ] ) & $mask ) === ( ord( $net_bin[ $bytes ] ) & $mask );
	}

	/**
	 * Indica se l'IP è nella lista dei fidati.
	 *
	 * @param string $ip IP.
	 * @return bool
	 */
	public static function is_whitelisted( $ip ) {
		if ( '' === $ip ) {
			return false;
		}
		$rules = preg_split( '/[\r\n]+/', (string) Settings::get( 'ip_whitelist', '' ) );
		foreach ( (array) $rules as $rule ) {
			$rule = trim( $rule );
			if ( '' !== $rule && self::matches( $ip, $rule ) ) {
				return true;
			}
		}
		/**
		 * Permette di considerare fidato un IP via codice.
		 *
		 * @param bool   $trusted Esito.
		 * @param string $ip      IP.
		 */
		return (bool) apply_filters( 'grs_security_ip_whitelisted', false, $ip );
	}
}
