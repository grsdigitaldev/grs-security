<?php
/**
 * Regole .htaccess (solo Apache e LiteSpeed), scritte in un blocco marcato e reversibile.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Gestione dei blocchi "GRS Security" nei file .htaccess.
 */
class Htaccess {

	const MARKER        = 'GRS Security';
	const BACKUP_OPTION = 'grs_security_htaccess_backup';

	/**
	 * Il server interpreta i file .htaccess?
	 *
	 * @return bool
	 */
	public static function supported() {
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';
		$apache   = ( false !== strpos( $software, 'apache' ) || false !== strpos( $software, 'litespeed' ) );
		/**
		 * Forza il riconoscimento del supporto .htaccess.
		 *
		 * @param bool $apache Esito del rilevamento.
		 */
		return (bool) apply_filters( 'grs_security_htaccess_supported', $apache );
	}

	/**
	 * Percorso del .htaccess principale.
	 *
	 * @return string
	 */
	public static function root_file() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		return trailingslashit( get_home_path() ) . '.htaccess';
	}

	/**
	 * Percorso del .htaccess della cartella uploads.
	 *
	 * @return string
	 */
	public static function uploads_file() {
		$uploads = wp_upload_dir( null, false );
		return trailingslashit( $uploads['basedir'] ) . '.htaccess';
	}

	/**
	 * Regole di negazione compatibili con Apache 2.2 e 2.4.
	 *
	 * @param string $indent Rientro.
	 * @return string[]
	 */
	private static function deny_lines( $indent = "\t" ) {
		return array(
			$indent . '<IfModule mod_authz_core.c>',
			$indent . "\tRequire all denied",
			$indent . '</IfModule>',
			$indent . '<IfModule !mod_authz_core.c>',
			$indent . "\tOrder allow,deny",
			$indent . "\tDeny from all",
			$indent . '</IfModule>',
		);
	}

	/**
	 * Righe per il .htaccess principale in base alle correzioni attive.
	 *
	 * @return string[]
	 */
	public static function root_lines() {
		$lines = array();
		if ( Settings::fix_enabled( 'htaccess_indexes' ) ) {
			$lines[] = 'Options -Indexes';
		}
		if ( Settings::fix_enabled( 'htaccess_sensitive' ) ) {
			$lines[] = '<FilesMatch "^(readme\.html|license\.txt|wp-config\.php|wp-config-sample\.php|error_log|php_errors\.log|\.user\.ini)$">';
			$lines   = array_merge( $lines, self::deny_lines() );
			$lines[] = '</FilesMatch>';
			$lines[] = '<FilesMatch "(?i)\.(bak|old|orig|save|swp|sql|sql\.gz|log)$|~$">';
			$lines   = array_merge( $lines, self::deny_lines() );
			$lines[] = '</FilesMatch>';
			$lines[] = '<IfModule mod_alias.c>';
			$lines[] = "\tRedirectMatch 404 \"/\\.(git|svn|hg|env)(/|$)\"";
			$lines[] = '</IfModule>';
		}
		return $lines;
	}

	/**
	 * Righe per il .htaccess di uploads.
	 *
	 * @return string[]
	 */
	public static function uploads_lines() {
		if ( ! Settings::fix_enabled( 'htaccess_uploads' ) ) {
			return array();
		}
		$lines   = array( '<FilesMatch "(?i)\.(php[0-9]?|phtml|phar|pht|phps)$">' );
		$lines   = array_merge( $lines, self::deny_lines() );
		$lines[] = '</FilesMatch>';
		return $lines;
	}

	/**
	 * Allinea i file .htaccess alle impostazioni correnti.
	 *
	 * @return true|\WP_Error
	 */
	public static function sync() {
		if ( ! self::supported() ) {
			return true;
		}
		$root = self::write_block( self::root_file(), self::root_lines(), true );
		$up   = self::write_block( self::uploads_file(), self::uploads_lines(), false );
		if ( is_wp_error( $root ) ) {
			return $root;
		}
		return $up;
	}

	/**
	 * Rimuove tutti i blocchi del plugin.
	 *
	 * @return void
	 */
	public static function remove_all() {
		foreach ( array( self::root_file(), self::uploads_file() ) as $file ) {
			if ( file_exists( $file ) ) {
				self::write_block( $file, array(), false );
			}
		}
	}

	/**
	 * Contenuto del file senza il blocco del plugin.
	 *
	 * @param string $content Contenuto.
	 * @return string
	 */
	public static function strip_block( $content ) {
		$pattern = '/\n?# BEGIN ' . preg_quote( self::MARKER, '/' ) . '.*?# END ' . preg_quote( self::MARKER, '/' ) . "[^\n]*\n?/s";
		return (string) preg_replace( $pattern, "\n", $content );
	}

	/**
	 * Indica se il blocco del plugin è presente nel file.
	 *
	 * @param string $file Percorso.
	 * @return bool
	 */
	public static function has_block( $file ) {
		if ( ! is_readable( $file ) ) {
			return false;
		}
		$content = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
		return false !== strpos( $content, '# BEGIN ' . self::MARKER );
	}

	/**
	 * Scrive (o rimuove se $lines è vuoto) il blocco in testa al file.
	 *
	 * @param string   $file   Percorso.
	 * @param string[] $lines  Righe.
	 * @param bool     $verify Verifica che il sito risponda dopo la modifica (ripristina se errore 5xx).
	 * @return true|\WP_Error
	 */
	public static function write_block( $file, array $lines, $verify ) {
		$exists = file_exists( $file );
		if ( ! $exists && empty( $lines ) ) {
			return true;
		}
		$dir = dirname( $file );
		if ( ( $exists && ! wp_is_writable( $file ) ) || ( ! $exists && ! wp_is_writable( $dir ) ) ) {
			return new \WP_Error(
				'grs_security_htaccess_not_writable',
				/* translators: %s: percorso del file */
				sprintf( __( 'Il file %s non è scrivibile.', 'grs-security' ), $file )
			);
		}

		$original = $exists ? (string) file_get_contents( $file ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
		$clean    = ltrim( self::strip_block( $original ), "\n" );
		$new      = $clean;
		if ( ! empty( $lines ) ) {
			$block = '# BEGIN ' . self::MARKER . "\n"
				. '# Regole aggiunte da GRS Security: si rimuovono disattivando la correzione o il plugin.' . "\n"
				. implode( "\n", $lines ) . "\n"
				. '# END ' . self::MARKER . "\n";
			$new   = $block . ( '' !== $clean ? "\n" . $clean : '' );
		}

		if ( $new === $original ) {
			return true;
		}

		$backup = get_option( self::BACKUP_OPTION, array() );
		$backup = is_array( $backup ) ? $backup : array();
		if ( ! isset( $backup[ md5( $file ) ] ) ) {
			$backup[ md5( $file ) ] = array(
				'file'    => $file,
				'content' => $original,
				'time'    => time(),
			);
			update_option( self::BACKUP_OPTION, $backup, false );
		}

		if ( '' === trim( $new ) ) {
			// Il file conteneva solo il nostro blocco: lo eliminiamo.
			wp_delete_file( $file );
			return true;
		}
		$written = file_put_contents( $file, $new, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- scrittura atomica del file locale, come insert_with_markers().
		if ( false === $written ) {
			return new \WP_Error( 'grs_security_htaccess_write_failed', __( 'Scrittura del file .htaccess non riuscita.', 'grs-security' ) );
		}

		if ( $verify && ! empty( $lines ) && ! self::site_responds() ) {
			file_put_contents( $file, $original, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- ripristino del contenuto originale.
			return new \WP_Error(
				'grs_security_htaccess_reverted',
				__( 'Dopo la modifica del file .htaccess il sito ha risposto con un errore del server: la modifica è stata annullata automaticamente. Probabilmente l\'hosting non consente alcune direttive; applica le regole a mano o chiedi all\'hosting.', 'grs-security' )
			);
		}
		return true;
	}

	/**
	 * Controlla con una richiesta al sito che non ci siano errori 5xx.
	 *
	 * @return bool False solo se il sito risponde con un errore del server.
	 */
	public static function site_responds() {
		$response = wp_remote_get(
			add_query_arg( 'grs_security_check', wp_rand(), home_url( '/' ) ),
			array(
				'timeout'     => 10,
				'redirection' => 3,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.
			)
		);
		if ( is_wp_error( $response ) ) {
			return true; // Non verificabile: non annulliamo.
		}
		return (int) wp_remote_retrieve_response_code( $response ) < 500;
	}

	/**
	 * Regole equivalenti per Nginx (da far aggiungere all'hosting).
	 *
	 * @return string
	 */
	public static function nginx_snippet() {
		return "location ~* /wp-content/uploads/.*\\.(php[0-9]?|phtml|phar|pht|phps)$ { deny all; }\n"
			. "location ~* /(readme\\.html|license\\.txt|wp-config-sample\\.php|\\.user\\.ini)$ { deny all; }\n"
			. "location ~* \\.(bak|old|orig|save|swp|sql|log)$ { deny all; }\n"
			. "location ~ /\\.(git|svn|hg|env) { deny all; }\n"
			. 'autoindex off;';
	}
}
