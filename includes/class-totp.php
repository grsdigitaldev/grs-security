<?php
/**
 * TOTP (RFC 6238) e codifica Base32 (RFC 4648), senza dipendenze.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Generazione e verifica dei codici a tempo.
 */
class Totp {

	const PERIOD   = 30;
	const DIGITS   = 6;
	const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Nuovo segreto casuale (160 bit) in Base32.
	 *
	 * @return string
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 20 ) );
	}

	/**
	 * Codifica Base32 senza padding.
	 *
	 * @param string $data Byte.
	 * @return string
	 */
	public static function base32_encode( $data ) {
		$bits = '';
		$len  = strlen( $data );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out    = '';
		$chunks = str_split( $bits, 5 );
		foreach ( $chunks as $chunk ) {
			$out .= self::ALPHABET[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	/**
	 * Decodifica Base32 (ignora spazi e padding).
	 *
	 * @param string $text Testo.
	 * @return string Byte, vuoto se non valido.
	 */
	public static function base32_decode( $text ) {
		$text = strtoupper( preg_replace( '/[\s=]/', '', (string) $text ) );
		if ( '' === $text || strspn( $text, self::ALPHABET ) !== strlen( $text ) ) {
			return '';
		}
		$bits = '';
		$len  = strlen( $text );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( strpos( self::ALPHABET, $text[ $i ] ) ), 5, '0', STR_PAD_LEFT );
		}
		$out   = '';
		$bytes = str_split( $bits, 8 );
		foreach ( $bytes as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/**
	 * Codice per un intervallo temporale.
	 *
	 * @param string $secret Segreto Base32.
	 * @param int    $step   Intervallo (time / 30).
	 * @return string
	 */
	public static function code( $secret, $step ) {
		$key = self::base32_decode( $secret );
		if ( '' === $key ) {
			return '';
		}
		$counter = pack( 'N2', ( $step >> 32 ) & 0xFFFFFFFF, $step & 0xFFFFFFFF );
		$hash    = hash_hmac( 'sha1', $counter, $key, true );
		$offset  = ord( $hash[19] ) & 0x0F;
		$value   = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );
		return str_pad( (string) ( $value % ( 10 ** self::DIGITS ) ), self::DIGITS, '0', STR_PAD_LEFT );
	}

	/**
	 * Intervallo corrente.
	 *
	 * @return int
	 */
	public static function current_step() {
		return (int) floor( time() / self::PERIOD );
	}

	/**
	 * Verifica un codice con tolleranza di ±1 intervallo e protezione dal riuso.
	 *
	 * @param string $secret    Segreto.
	 * @param string $code      Codice inserito.
	 * @param int    $last_step Ultimo intervallo già usato (0 se nessuno).
	 * @return int Intervallo usato se valido, 0 se non valido.
	 */
	public static function verify( $secret, $code, $last_step = 0 ) {
		$code = preg_replace( '/\D/', '', (string) $code );
		if ( strlen( $code ) !== self::DIGITS ) {
			return 0;
		}
		$now = self::current_step();
		for ( $i = -1; $i <= 1; $i++ ) {
			$step = $now + $i;
			if ( $step <= (int) $last_step ) {
				continue;
			}
			if ( hash_equals( self::code( $secret, $step ), $code ) ) {
				return $step;
			}
		}
		return 0;
	}

	/**
	 * URI otpauth:// per le app di autenticazione.
	 *
	 * @param string $secret Segreto.
	 * @param string $label  Account (es. email).
	 * @param string $issuer Emittente (nome del sito).
	 * @return string
	 */
	public static function uri( $secret, $label, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer ) . ':' . rawurlencode( $label )
			. '?secret=' . $secret
			. '&issuer=' . rawurlencode( $issuer )
			. '&digits=' . self::DIGITS
			. '&period=' . self::PERIOD;
	}
}
