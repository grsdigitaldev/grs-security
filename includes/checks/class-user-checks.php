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
				'title'        => __( 'Nessun utente "admin"', 'grs-security' ),
				'status'       => $bad ? 'warning' : 'ok',
				'weight'       => 2,
				'message'      => $bad
					? __( 'Esiste un utente con nome "admin": è il primo che i bot provano negli attacchi alle password.', 'grs-security' )
					: __( 'Nessun utente con il nome prevedibile "admin".', 'grs-security' ),
				'fix'          => $bad ? 'manual' : 'none',
				'instructions' => __( 'Crea un nuovo amministratore con un nome non ovvio, accedi con quello ed elimina l\'utente "admin" assegnando i suoi contenuti al nuovo utente. Il nome utente in WordPress non si può rinominare dalla bacheca.', 'grs-security' ),
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
				'title'        => __( 'Pochi amministratori', 'grs-security' ),
				'status'       => $count > 3 ? 'warning' : 'ok',
				'weight'       => 1,
				/* translators: 1: numero, 2: elenco */
				'message'      => sprintf( _n( '%1$d amministratore: %2$s.', '%1$d amministratori: %2$s.', $count, 'grs-security' ), $count, implode( ', ', array_slice( $names, 0, 15 ) ) ),
				'fix'          => $count > 3 ? 'manual' : 'none',
				'instructions' => __( 'Ogni amministratore è una porta d\'ingresso. Verifica che tutti siano ancora necessari, elimina gli account di ex collaboratori e assegna ruoli più bassi (Editore, Autore) a chi non gestisce il sito.', 'grs-security' ),
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
			/* translators: %s: ruolo */
			$message = sprintf( __( 'Il ruolo assegnato ai nuovi utenti è "%s", che permette di creare o modificare contenuti.', 'grs-security' ), $role );
			if ( $open ) {
				$message .= ' ' . __( 'La registrazione è aperta a chiunque.', 'grs-security' );
			}
		} else {
			$status  = 'ok';
			$message = $open
				/* translators: %s: ruolo */
				? sprintf( __( 'Registrazione aperta con ruolo predefinito "%s" (senza permessi di modifica).', 'grs-security' ), $role )
				: __( 'Registrazione pubblica disattivata.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'registration',
				'category'     => 'users',
				'title'        => __( 'Registrazione e ruolo predefinito sicuri', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $message,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'In Impostazioni > Generali imposta "Ruolo predefinito del nuovo utente" su Sottoscrittore (o Cliente per WooCommerce) e disattiva "Chiunque può registrarsi" se non serve. Un ruolo elevato qui è un segnale tipico di sito compromesso.', 'grs-security' ),
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
			$message = __( 'La verifica in due passaggi è disattivata dalla costante GRS_SECURITY_DISABLE_2FA in wp-config.php.', 'grs-security' );
		} elseif ( empty( $without ) ) {
			$status  = 'ok';
			$message = __( 'Tutti gli amministratori usano la verifica in due passaggi.', 'grs-security' );
		} elseif ( $required ) {
			$status = 'ok';
			/* translators: %s: elenco */
			$message = sprintf( __( 'Verifica in due passaggi obbligatoria: devono ancora configurarla al prossimo accesso: %s.', 'grs-security' ), implode( ', ', $without ) );
		} else {
			$status = 'critical';
			/* translators: %s: elenco */
			$message = sprintf( __( 'Amministratori senza verifica in due passaggi: %s. Con la sola password, una password rubata basta per entrare.', 'grs-security' ), implode( ', ', $without ) );
		}
		return Scanner::result(
			array(
				'id'           => 'twofa',
				'category'     => 'users',
				'title'        => __( 'Verifica in due passaggi per gli amministratori', 'grs-security' ),
				'status'       => $status,
				'weight'       => 3,
				'message'      => $message,
				'fix'          => 'auto',
				'fix_applied'  => $required,
				'recommended'  => true,
				'instructions' => __( 'Rende obbligatoria la verifica in due passaggi per i ruoli scelti (predefinito: Amministratore). Al prossimo accesso ogni amministratore dovrà collegare un\'app come Google Authenticator, Microsoft Authenticator o 1Password e salvare i codici di recupero.', 'grs-security' ),
			)
		);
	}
}
