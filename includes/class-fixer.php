<?php
/**
 * Applica e annulla le correzioni proposte dalla scansione.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Collega i controlli alle correzioni.
 */
class Fixer {

	/**
	 * Controllo => correzioni (interruttori in Settings::FIXES).
	 *
	 * @var array
	 */
	const MAP = array(
		'file_edit'         => array( 'file_edit' ),
		'xmlrpc'            => array( 'xmlrpc' ),
		'user_enum'         => array( 'user_enum' ),
		'headers'           => array( 'headers' ),
		'hsts'              => array( 'hsts' ),
		'login_errors'      => array( 'login_errors' ),
		'app_passwords'     => array( 'app_passwords' ),
		'wp_version'        => array( 'hide_version' ),
		'core_auto_updates' => array( 'core_minor_updates' ),
		'uploads_php'       => array( 'htaccess_uploads' ),
		'sensitive_files'   => array( 'htaccess_sensitive' ),
		'debug_log'         => array( 'htaccess_sensitive' ),
		'dir_listing'       => array( 'htaccess_indexes' ),
		'login_guard'       => array( 'login_guard' ),
		'firewall'          => array( 'firewall' ),
		'integrity'         => array( 'integrity' ),
		'twofa'             => array( 'twofa' ),
		'login_url'         => array( 'login_url' ),
	);

	const HTACCESS_FIXES = array( 'htaccess_uploads', 'htaccess_sensitive', 'htaccess_indexes' );

	/**
	 * Applica la correzione di un controllo.
	 *
	 * @param string $check Id controllo.
	 * @return true|\WP_Error
	 */
	public static function apply( $check ) {
		if ( 'salts' === $check ) {
			return Salts::regenerate();
		}
		if ( ! isset( self::MAP[ $check ] ) ) {
			return new \WP_Error( 'grs_security_unknown_fix', __( 'Fix not available.', 'grs-security' ) );
		}
		if ( 'login_url' === $check && '' === (string) Settings::get( 'login_slug', '' ) ) {
			return new \WP_Error( 'grs_security_no_slug', __( 'First choose the login address in the settings.', 'grs-security' ) );
		}
		$fixes  = self::MAP[ $check ];
		$values = array_fill_keys( $fixes, true );
		$extra  = array( 'fixes' => $values );
		if ( 'twofa' === $check && empty( Settings::get( 'twofa_roles' ) ) ) {
			$extra['twofa_roles'] = array( 'administrator' );
		}
		Settings::update( $extra );

		if ( array_intersect( $fixes, self::HTACCESS_FIXES ) ) {
			$result = Htaccess::sync();
			if ( is_wp_error( $result ) ) {
				Settings::update( array( 'fixes' => array_fill_keys( $fixes, false ) ) );
				Htaccess::sync();
				return $result;
			}
		}
		if ( 'integrity' === $check ) {
			Integrity::start();
		}
		return true;
	}

	/**
	 * Annulla la correzione di un controllo.
	 *
	 * @param string $check Id controllo.
	 * @return true|\WP_Error
	 */
	public static function revert( $check ) {
		if ( ! isset( self::MAP[ $check ] ) ) {
			return new \WP_Error( 'grs_security_unknown_fix', __( 'Fix not available.', 'grs-security' ) );
		}
		$fixes = self::MAP[ $check ];
		Settings::update( array( 'fixes' => array_fill_keys( $fixes, false ) ) );
		if ( array_intersect( $fixes, self::HTACCESS_FIXES ) ) {
			Htaccess::sync();
		}
		if ( 'integrity' === $check ) {
			wp_clear_scheduled_hook( Plugin::CRON_INTEGRITY );
			delete_option( Integrity::JOB_OPTION );
		}
		return true;
	}

	/**
	 * Applica più correzioni; la rigenerazione SALT va sempre per ultima.
	 *
	 * @param string[] $checks Id controlli.
	 * @return array { applied: string[], errors: array id => messaggio, salts: bool }
	 */
	public static function apply_many( array $checks ) {
		$out    = array(
			'applied' => array(),
			'errors'  => array(),
			'salts'   => false,
		);
		$salts  = in_array( 'salts', $checks, true );
		$checks = array_diff( $checks, array( 'salts' ) );
		foreach ( $checks as $check ) {
			$result = self::apply( $check );
			if ( is_wp_error( $result ) ) {
				$out['errors'][ $check ] = $result->get_error_message();
			} else {
				$out['applied'][] = $check;
			}
		}
		if ( $salts ) {
			$result = self::apply( 'salts' );
			if ( is_wp_error( $result ) ) {
				$out['errors']['salts'] = $result->get_error_message();
			} else {
				$out['salts'] = true;
			}
		}
		return $out;
	}
}
