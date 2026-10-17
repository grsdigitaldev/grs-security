<?php
/**
 * Autoloader del namespace GRSDigital\Security.
 *
 * GRSDigital\Security\Login_Guard   -> includes/class-login-guard.php
 * GRSDigital\Security\Admin\Admin   -> includes/admin/class-admin.php
 *
 * @package GRSDigital\Security
 */

defined( 'ABSPATH' ) || exit;

spl_autoload_register(
	function ( $class_name ) {
		$prefix = 'GRSDigital\\Security\\';
		if ( 0 !== strpos( $class_name, $prefix ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		$parts    = explode( '\\', $relative );
		$class    = array_pop( $parts );
		$dir      = '';
		foreach ( $parts as $part ) {
			$dir .= strtolower( str_replace( '_', '-', $part ) ) . '/';
		}
		$file = GRS_SECURITY_PATH . 'includes/' . $dir . 'class-' . strtolower( str_replace( '_', '-', $class ) ) . '.php';
		if ( is_readable( $file ) ) {
			require_once $file;
		}
	}
);
