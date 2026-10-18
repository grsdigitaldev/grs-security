<?php
/**
 * Controlli su utenti, ruoli e verifica in due passaggi.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;
use GRSDigital\Security\Two_Factor;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Utenti e accessi".
 */
class User_Checks {

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login' ),
				'number' => 200,
			)
		);
		return array(
			self::admin_username(),
			self::admin_count( $admins ),
			self::registration(),
			self::two_factor( $admins ),
		);
	}

	/**
	 * Utente "admin".
	 *
	 * @return array
	 */
	private static function admin_username() {
		$user = get_user_by( 'login', 'admin' );
		$bad  = $user && $user->has_cap( 'edit_posts' );
		return Scanner::result(
			array(
				'id'           => 'admin_username',
				'category'     => 'users',
				'title'        => __( 'No "admin" user', 'grs-security' ),
				'status'       => $bad ? 'warning' : 'ok',
				'weight'       => 2,
				'message'      => $bad
					? __( 'There is a user named "admin": it is the first one bots try in password attacks.', 'grs-security' )
					: __( 'No user with the predictable name "admin".', 'grs-security' ),
				'fix'          => $bad ? 'manual' : 'none',
				'instructions' => __( 'Create a new administrator with a non-obvious name, log in with it and delete the "admin" user, assigning its content to the new user. WordPress usernames cannot be renamed from the dashboard.', 'grs-security' ),
				'link'         => admin_url( 'user-new.php' ),
			)
		);
	}

	/**
	 * Numero di amministratori.
	 *
	 * @param array $admins Amministratori.
	 * @return array
	 */
	private static function admin_count( $admins ) {
		$count = count( $admins );
		$names = wp_list_pluck( $admins, 'user_login' );
		return Scanner::result(
			array(
				'id'           => 'admin_count',
				'category'     => 'users',
				'title'        => __( 'Few administrators', 'grs-security' ),
				'status'       => $count > 3 ? 'warning' : 'ok',
				'weight'       => 1,
				/* translators: 1: number, 2: list */
				'message'      => sprintf( _n( '%1$d administrator: %2$s.', '%1$d administrators: %2$s.', $count, 'grs-security' ), $count, implode( ', ', array_slice( $names, 0, 15 ) ) ),
				'fix'          => $count > 3 ? 'manual' : 'none',
				'instructions' => __( 'Every administrator is a way in. Check that all of them are still needed, delete accounts of former collaborators and assign lower roles (Editor, Author) to those who do not manage the site.', 'grs-security' ),
				'link'         => admin_url( 'users.php?role=administrator' ),
			)
		);
	}

	/**
	 * Registrazione aperta e ruolo predefinito.
	 *
	 * @return array
	 */
	private static function registration() {
		$open = (bool) get_option( 'users_can_register' );
		$role = (string) get_option( 'default_role', 'subscriber' );
		$obj  = get_role( $role );
		$safe = in_array( $role, array( 'subscriber', 'customer' ), true ) || ( $obj && ! $obj->has_cap( 'edit_posts' ) );

		if ( ! $safe ) {
			$status = $open ? 'critical' : 'warning';
			/* translators: %s: role */
			$message = sprintf( __( 'The role assigned to new users is "%s", which allows creating or editing content.', 'grs-security' ), $role );
			if ( $open ) {
				$message .= ' ' . __( 'Registration is open to anyone.', 'grs-security' );
			}
		} else {
			$status  = 'ok';
			$message = $open
				/* translators: %s: role */
				? sprintf( __( 'Registration open with default role "%s" (no editing permissions).', 'grs-security' ), $role )
				: __( 'Public registration disabled.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'registration',
				'category'     => 'users',
				'title'        => __( 'Safe registration and default role', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $message,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'In Settings > General set "New User Default Role" to Subscriber (or Customer for WooCommerce) and turn off "Anyone can register" if not needed. A high role here is a typical sign of a compromised site.', 'grs-security' ),
				'link'         => admin_url( 'options-general.php' ),
			)
		);
	}

	/**
	 * Amministratori con 2FA.
	 *
	 * @param array $admins Amministratori.
	 * @return array
	 */
	private static function two_factor( $admins ) {
		$without = array();
		foreach ( $admins as $admin ) {
			if ( ! Two_Factor::is_enabled( (int) $admin->ID ) ) {
				$without[] = $admin->user_login;
			}
		}
		$required = Settings::fix_enabled( 'twofa' );
		if ( Two_Factor::globally_disabled() ) {
			$status  = 'critical';
			$message = __( 'Two-step verification is disabled by the GRS_SECURITY_DISABLE_2FA constant in wp-config.php.', 'grs-security' );
		} elseif ( empty( $without ) ) {
			$status  = 'ok';
			$message = __( 'All administrators use two-step verification.', 'grs-security' );
		} elseif ( $required ) {
			$status = 'ok';
			/* translators: %s: list */
			$message = sprintf( __( 'Mandatory two-step verification: they still have to set it up at their next login: %s.', 'grs-security' ), implode( ', ', $without ) );
		} else {
			$status = 'critical';
			/* translators: %s: list */
			$message = sprintf( __( 'Administrators without two-step verification: %s. With a password alone, a stolen password is enough to get in.', 'grs-security' ), implode( ', ', $without ) );
		}
		return Scanner::result(
			array(
				'id'           => 'twofa',
				'category'     => 'users',
				'title'        => __( 'Two-step verification for administrators', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $message,
				'fix'          => 'auto',
				'fix_applied'  => $required,
				'recommended'  => true,
				'instructions' => __( 'Makes two-step verification mandatory for the selected roles (default: Administrator). At the next login each administrator will have to connect an app such as Google Authenticator, Microsoft Authenticator or 1Password and save the recovery codes.', 'grs-security' ),
			)
		);
	}
}
