<?php
/**
 * URL di login personalizzato: wp-login.php e wp-admin rispondono 404 ai visitatori non connessi.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Sposta la pagina di login su uno slug scelto.
 */
class Login_Url {

	/**
	 * Slug riservati.
	 *
	 * @var string[]
	 */
	const RESERVED = array( 'wp-admin', 'wp-login', 'wp-login-php', 'login', 'admin', 'dashboard', 'wp-content', 'wp-includes', 'wp-json', 'feed', 'xmlrpc', 'wp-register', 'wp-signup', 'wp-cron', 'sitemap', 'wp-sitemap', 'robots', 'embed', 'page', 'search', 'author', 'category', 'tag' );

	/**
	 * Cosa fare in questa richiesta: '', 'login', 'block'.
	 *
	 * @var string
	 */
	private static $mode = '';

	/**
	 * Sanitizza lo slug (vuoto se non valido).
	 *
	 * @param string $slug Slug.
	 * @return string
	 */
	public static function sanitize_slug( $slug ) {
		$slug = sanitize_title( trim( $slug, " /\t\n\r" ) );
		if ( strlen( $slug ) < 4 || in_array( $slug, self::RESERVED, true ) ) {
			return '';
		}
		return $slug;
	}

	/**
	 * La funzione è attiva in questa richiesta?
	 *
	 * @return bool
	 */
	public static function active() {
		if ( defined( 'GRS_SECURITY_DISABLE_LOGIN_URL' ) && GRS_SECURITY_DISABLE_LOGIN_URL ) {
			return false;
		}
		if ( is_multisite() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return false;
		}
		return Settings::fix_enabled( 'login_url' ) && '' !== (string) Settings::get( 'login_slug', '' );
	}

	/**
	 * Invia via email il nuovo indirizzo quando viene attivato o cambiato.
	 *
	 * @param array $new_settings Nuove impostazioni.
	 * @param array $old_settings Precedenti.
	 * @return void
	 */
	public static function settings_updated( $new_settings, $old_settings ) {
		$on_new = ! empty( $new_settings['fixes']['login_url'] ) && '' !== $new_settings['login_slug'];
		$on_old = ! empty( $old_settings['fixes']['login_url'] ) && '' !== $old_settings['login_slug'];
		if ( ! $on_new || ( $on_old && $new_settings['login_slug'] === $old_settings['login_slug'] ) ) {
			return;
		}
		Settings::flush();
		$url = self::login_url();
		Logger::log(
			'login_url_changed',
			'warning',
			/* translators: %s: URL */
			sprintf( __( 'Nuovo indirizzo di login: %s', 'grs-security' ), $url ),
			array( 'ip' => Ip::current() )
		);
		$recipients = array_unique( array( Settings::alert_email(), (string) get_option( 'admin_email' ) ) );
		$site       = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		foreach ( $recipients as $to ) {
			if ( is_email( $to ) ) {
				wp_mail(
					$to,
					'[' . $site . '] ' . __( 'Nuovo indirizzo di accesso al sito', 'grs-security' ),
					sprintf(
						/* translators: 1: URL, 2: costante */
						__( "La pagina di accesso al sito è stata spostata. Il nuovo indirizzo è:\n\n%1\$s\n\nSalvalo nei preferiti: wp-login.php e wp-admin non mostrano più il login ai visitatori.\nIn caso di emergenza aggiungi in wp-config.php: %2\$s", 'grs-security' ),
						$url,
						"define( 'GRS_SECURITY_DISABLE_LOGIN_URL', true );"
					)
				);
			}
		}
	}

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'grs_security_settings_updated', array( __CLASS__, 'settings_updated' ), 10, 2 );
		if ( ! self::active() ) {
			return;
		}
		self::detect();
		add_filter( 'site_url', array( __CLASS__, 'filter_url' ), 10, 1 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_url' ), 10, 1 );
		add_filter( 'wp_redirect', array( __CLASS__, 'filter_url' ), 10, 1 );
		add_action( 'wp_loaded', array( __CLASS__, 'serve' ), 1 );
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Permalink attivi?
	 *
	 * @return bool
	 */
	private static function pretty_permalinks() {
		return '' !== (string) get_option( 'permalink_structure' );
	}

	/**
	 * Nuovo URL di login.
	 *
	 * @param string|null $scheme Schema.
	 * @return string
	 */
	public static function login_url( $scheme = null ) {
		$slug = (string) Settings::get( 'login_slug', '' );
		if ( self::pretty_permalinks() ) {
			$structure = (string) get_option( 'permalink_structure' );
			$path      = '/' === substr( $structure, -1 ) ? $slug . '/' : $slug;
			return home_url( '/' . $path, $scheme );
		}
		return home_url( '/', $scheme ) . '?' . $slug;
	}

	/**
	 * Riconosce la richiesta corrente.
	 *
	 * @return void
	 */
	private static function detect() {
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$path = rawurldecode( $path );
		$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );
		$slug = (string) Settings::get( 'login_slug', '' );

		$target = untrailingslashit( $home ) . '/' . $slug;
		if ( untrailingslashit( $path ) === $target ) {
			self::$mode = 'login';
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- solo riconoscimento della pagina.
		if ( ! self::pretty_permalinks() && isset( $_GET[ $slug ] ) && untrailingslashit( $path ) === untrailingslashit( $home ) ) {
			self::$mode = 'login';
			return;
		}
		$base = strtolower( basename( $path ) );
		if ( in_array( $base, array( 'wp-login.php', 'wp-register.php' ), true ) || false !== strpos( strtolower( $path ), '/wp-login.php' ) ) {
			self::$mode = 'block';
		}
	}

	/**
	 * Sostituisce wp-login.php negli URL generati da WordPress.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	public static function filter_url( $url ) {
		if ( ! is_string( $url ) || false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		$parts = explode( '?', $url, 2 );
		if ( false === strpos( $parts[0], 'wp-login.php' ) ) {
			return $url;
		}
		$scheme = 0 === strpos( $url, 'https://' ) ? 'https' : null;
		$new    = self::login_url( $scheme );
		if ( isset( $parts[1] ) && '' !== $parts[1] ) {
			$new .= ( false === strpos( $new, '?' ) ? '?' : '&' ) . $parts[1];
		}
		return $new;
	}

	/**
	 * Serve la pagina di login sullo slug o risponde 404.
	 *
	 * @return void
	 */
	public static function serve() {
		global $pagenow;

		if ( 'login' === self::$mode ) {
			self::load_login();
			return;
		}

		if ( 'block' === self::$mode ) {
			self::not_found();
		}

		if ( is_admin() && ! is_user_logged_in() && ! wp_doing_ajax() && ! wp_doing_cron() && 'admin-post.php' !== $pagenow ) {
			self::not_found();
		}
	}

	/**
	 * Carica wp-login.php mantenendo le variabili globali che usa.
	 *
	 * @return void
	 */
	private static function load_login() {
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- wp-login.php si aspetta queste variabili globali.
		global $error, $interim_login, $action, $user_login, $user, $errors, $redirect_to, $requested_redirect_to, $secure_cookie, $reauth, $http_post, $rp_cookie, $rp_path, $value, $customize_login, $login_link_separator, $pagenow, $wp_version;
		$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- simula la pagina di login.
		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Risposta 404.
	 *
	 * @return void
	 */
	private static function not_found() {
		nocache_headers();
		wp_die(
			esc_html__( 'Pagina non trovata.', 'grs-security' ),
			esc_html__( 'Pagina non trovata', 'grs-security' ),
			array( 'response' => 404 )
		);
	}
}
