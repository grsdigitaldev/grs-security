<?php
/**
 * Verifica e rigenerazione delle chiavi di sicurezza (SALT) in wp-config.php.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Gestione delle chiavi AUTH_KEY, SECURE_AUTH_KEY e simili.
 */
class Salts {

	const KEYS = array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' );

	/**
	 * Percorso di wp-config.php (stessa logica di wp-load.php).
	 *
	 * @return string Vuoto se non trovato.
	 */
	public static function config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		}
		$parent = dirname( ABSPATH ) . '/wp-config.php';
		if ( file_exists( $parent ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return $parent;
		}
		return '';
	}

	/**
	 * Stato delle chiavi.
	 *
	 * @return array { status: ok|weak|missing, problems: string[] }
	 */
	public static function status() {
		$problems = array();
		$values   = array();
		foreach ( self::KEYS as $key ) {
			if ( ! defined( $key ) ) {
				/* translators: %s: nome costante */
				$problems[] = sprintf( __( '%s non definita', 'grs-security' ), $key );
				continue;
			}
			$value = (string) constant( $key );
			if ( strlen( $value ) < 32 || false !== stripos( $value, 'put your unique phrase here' ) || false !== stripos( $value, 'inserisci' ) ) {
				/* translators: %s: nome costante */
				$problems[] = sprintf( __( '%s debole o predefinita', 'grs-security' ), $key );
			}
			$values[] = $value;
		}
		if ( count( $values ) !== count( array_unique( $values ) ) ) {
			$problems[] = __( 'alcune chiavi hanno lo stesso valore', 'grs-security' );
		}
		return array(
			'status'   => $problems ? 'weak' : 'ok',
			'problems' => $problems,
		);
	}

	/**
	 * Regex per una define() di una chiave con valore tra apici.
	 *
	 * @param string $key Costante.
	 * @return string
	 */
	private static function pattern( $key ) {
		return '/define\s*\(\s*([\'"])' . preg_quote( $key, '/' ) . '\1\s*,\s*(?:\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*")\s*\)\s*;/';
	}

	/**
	 * La rigenerazione automatica è possibile?
	 *
	 * @return true|\WP_Error
	 */
	public static function can_regenerate() {
		$path = self::config_path();
		if ( '' === $path ) {
			return new \WP_Error( 'grs_security_no_config', __( 'File wp-config.php non trovato.', 'grs-security' ) );
		}
		if ( ! wp_is_writable( $path ) ) {
			return new \WP_Error( 'grs_security_config_not_writable', __( 'Il file wp-config.php non è scrivibile dal server.', 'grs-security' ) );
		}
		if ( ! wp_is_writable( dirname( $path ) ) ) {
			return new \WP_Error( 'grs_security_config_dir', __( 'La cartella di wp-config.php non è scrivibile (serve per la copia di sicurezza).', 'grs-security' ) );
		}
		$content = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
		foreach ( self::KEYS as $key ) {
			if ( 1 !== preg_match_all( self::pattern( $key ), $content ) ) {
				/* translators: %s: nome costante */
				return new \WP_Error( 'grs_security_key_pattern', sprintf( __( 'La definizione di %s in wp-config.php non è nel formato standard: modifica manuale consigliata.', 'grs-security' ), $key ) );
			}
		}
		return true;
	}

	/**
	 * Genera un valore sicuro senza apici e barre rovesciate.
	 *
	 * @return string
	 */
	public static function generate_value() {
		$chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*()-_[]{}<>~+=,.;:/?|';
		$max   = strlen( $chars ) - 1;
		$out   = '';
		for ( $i = 0; $i < 64; $i++ ) {
			$out .= $chars[ random_int( 0, $max ) ];
		}
		return $out;
	}

	/**
	 * Rigenera le chiavi con copia di sicurezza e controllo della sintassi.
	 *
	 * Tutti gli utenti verranno disconnessi.
	 *
	 * @return true|\WP_Error
	 */
	public static function regenerate() {
		$check = self::can_regenerate();
		if ( is_wp_error( $check ) ) {
			return $check;
		}
		$path     = self::config_path();
		$original = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
		$content  = $original;
		$new_keys = array();
		foreach ( self::KEYS as $key ) {
			$value            = self::generate_value();
			$new_keys[ $key ] = $value;
			$content          = preg_replace_callback(
				self::pattern( $key ),
				function () use ( $key, $value ) {
					return "define( '" . $key . "', '" . $value . "' );";
				},
				$content,
				1
			);
		}

		if ( ! self::valid_php( $content ) ) {
			return new \WP_Error( 'grs_security_config_syntax', __( 'Il nuovo wp-config.php non supera il controllo di sintassi: nessuna modifica eseguita.', 'grs-security' ) );
		}

		$backup = dirname( $path ) . '/wp-config-grs-backup-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 8, false, false ) . '.php';
		if ( ! copy( $path, $backup ) ) {
			return new \WP_Error( 'grs_security_backup_failed', __( 'Impossibile creare la copia di sicurezza di wp-config.php: nessuna modifica eseguita.', 'grs-security' ) );
		}
		$perms = fileperms( $path );

		$written = file_put_contents( $path, $content, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- scrittura del file di configurazione con blocco.
		clearstatcache();
		$check = (string) file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- verifica di quanto scritto.
		if ( false === $written || $check !== $content ) {
			copy( $backup, $path );
			wp_delete_file( $backup );
			return new \WP_Error( 'grs_security_write_failed', __( 'Scrittura di wp-config.php non riuscita: ripristinato il file originale.', 'grs-security' ) );
		}
		if ( false !== $perms ) {
			chmod( $path, $perms & 0777 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- mantiene i permessi originali.
		}
		// Senza invalidazione OPcache potrebbe continuare a usare la vecchia versione del file.
		if ( function_exists( 'opcache_invalidate' ) ) {
			opcache_invalidate( $path, true );
		}
		// La copia contiene credenziali: la eliminiamo, il file nuovo è verificato.
		wp_delete_file( $backup );

		try {
			/**
			 * Chiavi SALT rigenerate e scritte in wp-config.php.
			 *
			 * Lanciata nella stessa richiesta, dopo la scrittura verificata: le costanti
			 * in memoria hanno ancora i valori vecchi, quindi chi cifra dati con chiavi
			 * derivate dai SALT può decifrarli ora e cifrarli di nuovo con i valori nuovi.
			 * Non viene lanciata se la scrittura fallisce o il file originale viene ripristinato.
			 *
			 * @since 1.1.0
			 *
			 * @param array $new_keys Nome costante => nuovo valore (le 8 chiavi di Salts::KEYS).
			 */
			do_action( 'grs_security_salts_regenerated', $new_keys );
		} catch ( \Throwable $e ) {
			Logger::log(
				'salts_listener_error',
				'warning',
				/* translators: %s: messaggio di errore */
				sprintf( __( 'Un plugin collegato alla rigenerazione delle chiavi ha generato un errore: %s', 'grs-security' ), $e->getMessage() ),
				array()
			);
		}

		Logger::log( 'salts_regenerated', 'warning', __( 'Chiavi di sicurezza (SALT) rigenerate: tutti gli utenti sono stati disconnessi.', 'grs-security' ), array() );
		return true;
	}

	/**
	 * Controllo sintattico senza eseguire il codice.
	 *
	 * @param string $code Codice PHP.
	 * @return bool
	 */
	public static function valid_php( $code ) {
		try {
			token_get_all( $code, TOKEN_PARSE );
		} catch ( \ParseError $e ) {
			return false;
		}
		return true;
	}
}
