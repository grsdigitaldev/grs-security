<?php
/**
 * Impostazioni del plugin (un'unica opzione array).
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Lettura e scrittura delle impostazioni.
 */
class Settings {

	const OPTION = 'grs_security_settings';

	/**
	 * Correzioni gestite dal plugin (id => descrizione breve interna).
	 *
	 * @var string[]
	 */
	const FIXES = array(
		'file_edit',
		'xmlrpc',
		'user_enum',
		'headers',
		'hsts',
		'login_errors',
		'app_passwords',
		'hide_version',
		'core_minor_updates',
		'htaccess_uploads',
		'htaccess_sensitive',
		'htaccess_indexes',
		'login_guard',
		'firewall',
		'integrity',
		'twofa',
		'login_url',
	);

	/**
	 * Cache in memoria.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Valori predefiniti.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'fixes'              => array_fill_keys( self::FIXES, false ),
			'xmlrpc_mode'        => 'off',
			'login_max_attempts' => 5,
			'login_window'       => 15,
			'login_lockout'      => 15,
			'ip_source'          => 'REMOTE_ADDR',
			'ip_whitelist'       => '',
			'firewall_mode'      => 'block',
			'login_slug'         => '',
			'twofa_roles'        => array( 'administrator' ),
			'alerts_enabled'     => true,
			'alert_email'        => '',
			'log_retention'      => 90,
			'keep_data'          => false,
			'dismissed_checks'   => array(),
		);
	}

	/**
	 * Tutte le impostazioni, unite ai default.
	 *
	 * @return array
	 */
	public static function all() {
		if ( null === self::$cache ) {
			$stored = get_option( self::OPTION, array() );
			if ( ! is_array( $stored ) ) {
				$stored = array();
			}
			$defaults = self::defaults();
			$merged   = array_merge( $defaults, $stored );
			$fixes    = isset( $stored['fixes'] ) && is_array( $stored['fixes'] ) ? $stored['fixes'] : array();

			$merged['fixes'] = array_merge( $defaults['fixes'], array_intersect_key( $fixes, $defaults['fixes'] ) );
			self::$cache     = $merged;
		}
		return self::$cache;
	}

	/**
	 * Singola impostazione.
	 *
	 * @param string $key     Chiave.
	 * @param mixed  $fallback Valore se assente.
	 * @return mixed
	 */
	public static function get( $key, $fallback = null ) {
		$all = self::all();
		return array_key_exists( $key, $all ) ? $all[ $key ] : $fallback;
	}

	/**
	 * Indica se una correzione è attiva.
	 *
	 * @param string $fix Id della correzione.
	 * @return bool
	 */
	public static function fix_enabled( $fix ) {
		$fixes = self::get( 'fixes', array() );
		return ! empty( $fixes[ $fix ] );
	}

	/**
	 * Aggiorna una o più impostazioni (già sanitizzate).
	 *
	 * @param array $values Valori da unire.
	 * @return void
	 */
	public static function update( array $values ) {
		$all = self::all();
		if ( isset( $values['fixes'] ) && is_array( $values['fixes'] ) ) {
			$values['fixes'] = array_merge( $all['fixes'], array_intersect_key( $values['fixes'], $all['fixes'] ) );
		}
		$new = self::sanitize( array_merge( $all, $values ) );
		update_option( self::OPTION, $new, true );
		self::$cache = null;

		/**
		 * Impostazioni di GRS Security aggiornate.
		 *
		 * @param array $new Nuove impostazioni.
		 * @param array $all Impostazioni precedenti.
		 */
		do_action( 'grs_security_settings_updated', $new, $all );
	}

	/**
	 * Attiva o disattiva una correzione.
	 *
	 * @param string $fix     Id.
	 * @param bool   $enabled Stato.
	 * @return void
	 */
	public static function set_fix( $fix, $enabled ) {
		if ( ! in_array( $fix, self::FIXES, true ) ) {
			return;
		}
		self::update( array( 'fixes' => array( $fix => (bool) $enabled ) ) );
	}

	/**
	 * Svuota la cache in memoria (usato dopo modifiche dirette all'opzione).
	 *
	 * @return void
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Sanitizza l'intero array delle impostazioni.
	 *
	 * @param array $input Valori.
	 * @return array
	 */
	public static function sanitize( $input ) {
		$defaults = self::defaults();
		$input    = is_array( $input ) ? $input : array();
		$out      = array();

		$fixes = isset( $input['fixes'] ) && is_array( $input['fixes'] ) ? $input['fixes'] : array();
		foreach ( $defaults['fixes'] as $fix => $default ) {
			$out['fixes'][ $fix ] = ! empty( $fixes[ $fix ] );
		}

		$out['xmlrpc_mode']        = ( isset( $input['xmlrpc_mode'] ) && 'pingback' === $input['xmlrpc_mode'] ) ? 'pingback' : 'off';
		$out['login_max_attempts'] = self::int_range( $input, 'login_max_attempts', 3, 20, $defaults['login_max_attempts'] );
		$out['login_window']       = self::int_range( $input, 'login_window', 5, 120, $defaults['login_window'] );
		$out['login_lockout']      = self::int_range( $input, 'login_lockout', 5, 1440, $defaults['login_lockout'] );

		$sources          = array_keys( Ip::sources() );
		$out['ip_source'] = ( isset( $input['ip_source'] ) && in_array( $input['ip_source'], $sources, true ) ) ? $input['ip_source'] : 'REMOTE_ADDR';

		$whitelist = array();
		$lines     = isset( $input['ip_whitelist'] ) ? preg_split( '/[\r\n,]+/', (string) $input['ip_whitelist'] ) : array();
		foreach ( (array) $lines as $line ) {
			$line = trim( $line );
			if ( '' !== $line && Ip::is_valid_rule( $line ) ) {
				$whitelist[] = $line;
			}
		}
		$out['ip_whitelist'] = implode( "\n", array_unique( $whitelist ) );

		$out['firewall_mode'] = ( isset( $input['firewall_mode'] ) && 'log' === $input['firewall_mode'] ) ? 'log' : 'block';
		$out['login_slug']    = isset( $input['login_slug'] ) ? Login_Url::sanitize_slug( (string) $input['login_slug'] ) : '';

		$roles     = isset( $input['twofa_roles'] ) && is_array( $input['twofa_roles'] ) ? $input['twofa_roles'] : array();
		$all_roles = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->roles ) : array( 'administrator' );
		$out_roles = array();
		foreach ( $roles as $role ) {
			$role = sanitize_key( $role );
			if ( in_array( $role, $all_roles, true ) ) {
				$out_roles[] = $role;
			}
		}
		$out['twofa_roles'] = array_values( array_unique( $out_roles ) );

		$out['alerts_enabled'] = ! empty( $input['alerts_enabled'] );
		$email                 = isset( $input['alert_email'] ) ? sanitize_email( (string) $input['alert_email'] ) : '';
		$out['alert_email']    = is_email( $email ) ? $email : '';
		$out['log_retention']  = self::int_range( $input, 'log_retention', 7, 365, $defaults['log_retention'] );
		$out['keep_data']      = ! empty( $input['keep_data'] );

		$dismissed = isset( $input['dismissed_checks'] ) && is_array( $input['dismissed_checks'] ) ? $input['dismissed_checks'] : array();

		$out['dismissed_checks'] = array_values( array_unique( array_map( 'sanitize_key', $dismissed ) ) );

		// La protezione del login URL senza slug non ha senso.
		if ( '' === $out['login_slug'] ) {
			$out['fixes']['login_url'] = false;
		}

		return $out;
	}

	/**
	 * Intero limitato a un intervallo.
	 *
	 * @param array  $input    Valori.
	 * @param string $key      Chiave.
	 * @param int    $min      Minimo.
	 * @param int    $max      Massimo.
	 * @param int    $fallback Default.
	 * @return int
	 */
	private static function int_range( $input, $key, $min, $max, $fallback ) {
		if ( ! isset( $input[ $key ] ) || ! is_numeric( $input[ $key ] ) ) {
			return $fallback;
		}
		return max( $min, min( $max, (int) $input[ $key ] ) );
	}

	/**
	 * Email che riceve gli avvisi.
	 *
	 * @return string
	 */
	public static function alert_email() {
		$email = (string) self::get( 'alert_email', '' );
		return '' !== $email ? $email : (string) get_option( 'admin_email' );
	}
}
