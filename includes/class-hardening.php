<?php
/**
 * Correzioni di hardening applicate tramite hook (reversibili disattivando la voce o il plugin).
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Applica le correzioni attive.
 */
class Hardening {

	/**
	 * Registra gli hook delle correzioni attive.
	 *
	 * @return void
	 */
	public static function init() {
		if ( Settings::fix_enabled( 'file_edit' ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'block_file_edit' ), 10, 2 );
		}
		if ( Settings::fix_enabled( 'xmlrpc' ) ) {
			self::xmlrpc();
		}
		if ( Settings::fix_enabled( 'user_enum' ) ) {
			add_action( 'parse_request', array( __CLASS__, 'block_author_query' ), 1 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'filter_rest_users' ) );
			add_filter( 'oembed_response_data', array( __CLASS__, 'filter_oembed' ) );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'filter_sitemap_users' ), 10, 2 );
		}
		if ( Settings::fix_enabled( 'headers' ) || Settings::fix_enabled( 'hsts' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );
			add_action( 'login_init', array( __CLASS__, 'send_security_headers' ) );
			add_action( 'admin_init', array( __CLASS__, 'send_security_headers' ) );
		}
		if ( Settings::fix_enabled( 'login_errors' ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'generic_login_error' ), 98 );
		}
		if ( Settings::fix_enabled( 'app_passwords' ) ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}
		if ( Settings::fix_enabled( 'hide_version' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
			add_filter( 'style_loader_src', array( __CLASS__, 'mask_version' ), 9999 );
			add_filter( 'script_loader_src', array( __CLASS__, 'mask_version' ), 9999 );
		}
		if ( Settings::fix_enabled( 'core_minor_updates' ) ) {
			add_filter( 'allow_minor_auto_core_updates', '__return_true', 99 );
		}
	}

	/**
	 * Toglie le capability di modifica dei file da bacheca.
	 *
	 * @param string[] $caps Capability primitive.
	 * @param string   $cap  Capability richiesta.
	 * @return string[]
	 */
	public static function block_file_edit( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes', 'edit_files' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	/**
	 * Disattiva XML-RPC del tutto o solo pingback e multicall.
	 *
	 * @return void
	 */
	private static function xmlrpc() {
		if ( 'pingback' === Settings::get( 'xmlrpc_mode', 'off' ) ) {
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'remove_pingback_methods' ) );
		} else {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', '__return_empty_array', 999 );
			remove_action( 'wp_head', 'rsd_link' );
			add_action( 'init', array( __CLASS__, 'xmlrpc_forbidden' ), 1 );
		}
		add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		add_filter( 'pings_open', '__return_false', 999 );
	}

	/**
	 * Risponde 403 alle richieste a xmlrpc.php (modalità "off").
	 *
	 * @return void
	 */
	public static function xmlrpc_forbidden() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo 'XML-RPC disabled.';
			exit;
		}
	}

	/**
	 * Rimuove i metodi pingback e system.multicall.
	 *
	 * @param array $methods Metodi.
	 * @return array
	 */
	public static function remove_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'], $methods['system.multicall'] );
		return $methods;
	}

	/**
	 * Rimuove l'header X-Pingback.
	 *
	 * @param array $headers Header.
	 * @return array
	 */
	public static function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Blocca ?author=N per i visitatori non connessi.
	 *
	 * @return void
	 */
	public static function block_author_query() {
		if ( is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- sola lettura di un parametro pubblico.
		$author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';
		if ( '' !== $author && preg_match( '/\d/', $author ) ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Toglie gli endpoint REST degli utenti ai non connessi.
	 *
	 * @param array $endpoints Endpoint.
	 * @return array
	 */
	public static function filter_rest_users( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Rimuove autore dalle risposte oEmbed.
	 *
	 * @param array $data Dati.
	 * @return array
	 */
	public static function filter_oembed( $data ) {
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * Toglie gli utenti dalla sitemap core.
	 *
	 * @param mixed  $provider Provider.
	 * @param string $name     Nome.
	 * @return mixed
	 */
	public static function filter_sitemap_users( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * Header HTTP di sicurezza.
	 *
	 * @return void
	 */
	public static function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		if ( Settings::fix_enabled( 'headers' ) ) {
			$headers = array(
				'X-Content-Type-Options' => 'nosniff',
				'X-Frame-Options'        => 'SAMEORIGIN',
				'Referrer-Policy'        => 'strict-origin-when-cross-origin',
			);
			/**
			 * Header di sicurezza inviati.
			 *
			 * @param array $headers Nome => valore. Valore vuoto = non inviare.
			 */
			$headers = (array) apply_filters( 'grs_security_headers', $headers );
			foreach ( $headers as $name => $value ) {
				if ( '' !== (string) $value ) {
					header( $name . ': ' . $value );
				}
			}
		}
		if ( Settings::fix_enabled( 'hsts' ) && is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}

	/**
	 * Messaggio di errore generico al login (non rivela se l'utente esiste).
	 *
	 * @param \WP_User|\WP_Error|null $user Esito autenticazione.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function generic_login_error( $user ) {
		if ( ! is_wp_error( $user ) ) {
			return $user;
		}
		$codes = $user->get_error_codes();
		if ( array_intersect( $codes, array( 'invalid_username', 'invalid_email', 'incorrect_password' ) ) ) {
			return new \WP_Error(
				'grs_security_invalid_credentials',
				'<strong>' . esc_html__( 'Errore:', 'grs-security' ) . '</strong> ' . esc_html__( 'nome utente, email o password non corretti.', 'grs-security' )
			);
		}
		return $user;
	}

	/**
	 * Sostituisce ?ver=<versione WP> con un hash, mantenendo il cache busting.
	 *
	 * @param string $src URL.
	 * @return string
	 */
	public static function mask_version( $src ) {
		if ( ! is_string( $src ) || '' === $src ) {
			return $src;
		}
		$version = get_bloginfo( 'version' );
		if ( false !== strpos( $src, 'ver=' . $version ) ) {
			$src = add_query_arg( 'ver', substr( wp_hash( $version ), 0, 8 ), $src );
		}
		return $src;
	}
}
