<?php
/**
 * Monitoraggio degli eventi critici: nuovi amministratori, cambi di ruolo,
 * opzioni sensibili, plugin e temi.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Registra gli eventi di sicurezza.
 */
class Event_Monitor {

	/**
	 * Opzioni sorvegliate.
	 *
	 * @var string[]
	 */
	const WATCHED_OPTIONS = array( 'siteurl', 'home', 'admin_email', 'default_role', 'users_can_register' );

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'user_register', array( __CLASS__, 'user_registered' ), 99 );
		add_action( 'set_user_role', array( __CLASS__, 'role_set' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'role_added' ), 10, 2 );
		add_action( 'deleted_user', array( __CLASS__, 'user_deleted' ), 10, 1 );
		add_action( 'wp_login', array( __CLASS__, 'logged_in' ), 20, 2 );
		add_action( 'after_password_reset', array( __CLASS__, 'password_reset' ) );
		add_action( 'updated_option', array( __CLASS__, 'option_updated' ), 10, 3 );
		add_action( 'activated_plugin', array( __CLASS__, 'plugin_activated' ) );
		add_action( 'deactivated_plugin', array( __CLASS__, 'plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( __CLASS__, 'plugin_deleted' ), 10, 2 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'upgrader_done' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'theme_switched' ) );
		add_action( 'grs_security_settings_updated', array( __CLASS__, 'settings_changed' ), 10, 2 );
	}

	/**
	 * Utente che esegue l'azione (per il contesto).
	 *
	 * @return array
	 */
	private static function actor() {
		$user = function_exists( 'wp_get_current_user' ) ? wp_get_current_user() : null;
		if ( $user && $user->exists() ) {
			return array(
				'user_id'  => $user->ID,
				'username' => $user->user_login,
			);
		}
		return array(
			'user_id'  => 0,
			'username' => ( defined( 'WP_CLI' ) && WP_CLI ) ? 'WP-CLI' : '',
		);
	}

	/**
	 * Il ruolo concede la gestione del sito?
	 *
	 * @param string $role Ruolo.
	 * @return bool
	 */
	private static function is_admin_role( $role ) {
		$obj = get_role( $role );
		return $obj && ( $obj->has_cap( 'manage_options' ) || $obj->has_cap( 'activate_plugins' ) || $obj->has_cap( 'promote_users' ) || $obj->has_cap( 'edit_users' ) );
	}

	/**
	 * Nuovo utente.
	 *
	 * @param int $user_id Id.
	 * @return void
	 */
	public static function user_registered( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		foreach ( (array) $user->roles as $role ) {
			if ( self::is_admin_role( $role ) ) {
				Logger::log(
					'admin_created',
					'critical',
					/* translators: 1: nome utente, 2: email, 3: ruolo */
					sprintf( __( 'Creato un nuovo utente con permessi di amministrazione: %1$s (%2$s), ruolo %3$s.', 'grs-security' ), $user->user_login, $user->user_email, $role ),
					array_merge( self::actor(), array( 'context' => array( 'new_user_id' => $user_id ) ) )
				);
				return;
			}
		}
		if ( $user->has_cap( 'edit_posts' ) ) {
			Logger::log(
				'user_created',
				'info',
				/* translators: 1: nome utente, 2: ruoli */
				sprintf( __( 'Creato l\'utente %1$s con ruolo %2$s.', 'grs-security' ), $user->user_login, implode( ', ', (array) $user->roles ) ),
				self::actor()
			);
		}
	}

	/**
	 * Cambio di ruolo.
	 *
	 * @param int      $user_id   Id.
	 * @param string   $role      Nuovo ruolo.
	 * @param string[] $old_roles Ruoli precedenti.
	 * @return void
	 */
	public static function role_set( $user_id, $role, $old_roles ) {
		if ( empty( $old_roles ) || in_array( $role, (array) $old_roles, true ) ) {
			return; // Nuovo utente (gestito da user_registered) o nessun cambiamento.
		}
		self::role_granted( $user_id, $role, (array) $old_roles );
	}

	/**
	 * Ruolo aggiunto.
	 *
	 * @param int    $user_id Id.
	 * @param string $role    Ruolo.
	 * @return void
	 */
	public static function role_added( $user_id, $role ) {
		if ( doing_action( 'user_register' ) ) {
			return; // Gestito da user_registered.
		}
		self::role_granted( $user_id, $role, array() );
	}

	/**
	 * Registra un ruolo concesso.
	 *
	 * @param int      $user_id   Id.
	 * @param string   $role      Ruolo.
	 * @param string[] $old_roles Ruoli precedenti.
	 * @return void
	 */
	private static function role_granted( $user_id, $role, array $old_roles ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$admin = self::is_admin_role( $role );
		Logger::log(
			$admin ? 'admin_role_granted' : 'role_changed',
			$admin ? 'critical' : 'info',
			sprintf(
				/* translators: 1: utente, 2: nuovo ruolo, 3: ruoli precedenti */
				__( 'L\'utente %1$s ha ora il ruolo %2$s (prima: %3$s).', 'grs-security' ),
				$user->user_login,
				$role,
				$old_roles ? implode( ', ', $old_roles ) : '-'
			),
			array_merge( self::actor(), array( 'context' => array( 'target_user_id' => $user_id ) ) )
		);
	}

	/**
	 * Utente eliminato.
	 *
	 * @param int $user_id Id.
	 * @return void
	 */
	public static function user_deleted( $user_id ) {
		Logger::log(
			'user_deleted',
			'info',
			/* translators: %d: id utente */
			sprintf( __( 'Eliminato l\'utente con ID %d.', 'grs-security' ), $user_id ),
			self::actor()
		);
	}

	/**
	 * Accesso riuscito di un utente con permessi elevati.
	 *
	 * @param string   $login Login.
	 * @param \WP_User $user  Utente.
	 * @return void
	 */
	public static function logged_in( $login, $user ) {
		if ( ! $user instanceof \WP_User || ! $user->has_cap( 'edit_posts' ) ) {
			return;
		}
		Logger::log(
			'login_success',
			'info',
			/* translators: %s: nome utente */
			sprintf( __( 'Accesso riuscito: %s.', 'grs-security' ), $login ),
			array(
				'user_id'  => $user->ID,
				'username' => $login,
			)
		);
	}

	/**
	 * Password reimpostata.
	 *
	 * @param \WP_User $user Utente.
	 * @return void
	 */
	public static function password_reset( $user ) {
		if ( ! $user instanceof \WP_User ) {
			return;
		}
		Logger::log(
			'password_reset',
			$user->has_cap( 'manage_options' ) ? 'warning' : 'info',
			/* translators: %s: nome utente */
			sprintf( __( 'Password reimpostata tramite il link di recupero: %s.', 'grs-security' ), $user->user_login ),
			array(
				'user_id'  => $user->ID,
				'username' => $user->user_login,
			)
		);
	}

	/**
	 * Modifica di un'opzione sensibile.
	 *
	 * @param string $option Nome.
	 * @param mixed  $old    Vecchio valore.
	 * @param mixed  $value  Nuovo valore.
	 * @return void
	 */
	public static function option_updated( $option, $old, $value ) {
		if ( ! in_array( $option, self::WATCHED_OPTIONS, true ) || (string) $old === (string) $value ) {
			return;
		}
		$severity = 'warning';
		if ( in_array( $option, array( 'siteurl', 'home' ), true ) ) {
			$severity = 'critical';
		} elseif ( 'default_role' === $option && self::is_admin_role( (string) $value ) ) {
			$severity = 'critical';
		} elseif ( 'users_can_register' === $option && $value && self::is_admin_role( (string) get_option( 'default_role' ) ) ) {
			$severity = 'critical';
		}
		Logger::log(
			'option_changed',
			$severity,
			sprintf(
				/* translators: 1: opzione, 2: vecchio valore, 3: nuovo valore */
				__( 'Impostazione "%1$s" modificata: da "%2$s" a "%3$s".', 'grs-security' ),
				$option,
				is_scalar( $old ) ? (string) $old : wp_json_encode( $old ),
				is_scalar( $value ) ? (string) $value : wp_json_encode( $value )
			),
			self::actor()
		);
	}

	/**
	 * Plugin attivato.
	 *
	 * @param string $plugin File.
	 * @return void
	 */
	public static function plugin_activated( $plugin ) {
		/* translators: %s: plugin */
		Logger::log( 'plugin_activated', 'info', sprintf( __( 'Plugin attivato: %s.', 'grs-security' ), $plugin ), self::actor() );
	}

	/**
	 * Plugin disattivato.
	 *
	 * @param string $plugin File.
	 * @return void
	 */
	public static function plugin_deactivated( $plugin ) {
		/* translators: %s: plugin */
		Logger::log( 'plugin_deactivated', 'info', sprintf( __( 'Plugin disattivato: %s.', 'grs-security' ), $plugin ), self::actor() );
	}

	/**
	 * Plugin eliminato.
	 *
	 * @param string $plugin  File.
	 * @param bool   $deleted Esito.
	 * @return void
	 */
	public static function plugin_deleted( $plugin, $deleted ) {
		if ( $deleted ) {
			/* translators: %s: plugin */
			Logger::log( 'plugin_deleted', 'info', sprintf( __( 'Plugin eliminato: %s.', 'grs-security' ), $plugin ), self::actor() );
		}
	}

	/**
	 * Installazione o aggiornamento di plugin, temi, core.
	 *
	 * @param mixed $upgrader Istanza.
	 * @param array $extra    Dati.
	 * @return void
	 */
	public static function upgrader_done( $upgrader, $extra ) {
		unset( $upgrader );
		$type   = isset( $extra['type'] ) ? (string) $extra['type'] : '';
		$action = isset( $extra['action'] ) ? (string) $extra['action'] : '';
		if ( 'install' === $action && in_array( $type, array( 'plugin', 'theme' ), true ) ) {
			Logger::log(
				$type . '_installed',
				'warning',
				'plugin' === $type ? __( 'Installato un nuovo plugin.', 'grs-security' ) : __( 'Installato un nuovo tema.', 'grs-security' ),
				self::actor()
			);
		} elseif ( 'update' === $action ) {
			$items = array();
			foreach ( array( 'plugins', 'themes' ) as $key ) {
				if ( ! empty( $extra[ $key ] ) ) {
					$items = array_merge( $items, (array) $extra[ $key ] );
				}
			}
			Logger::log(
				'updated_' . sanitize_key( $type ),
				'info',
				/* translators: 1: tipo, 2: elenco */
				sprintf( __( 'Aggiornamento completato (%1$s) %2$s', 'grs-security' ), $type, $items ? implode( ', ', $items ) : '' ),
				self::actor()
			);
		}
	}

	/**
	 * Tema cambiato.
	 *
	 * @param string $name Nome tema.
	 * @return void
	 */
	public static function theme_switched( $name ) {
		/* translators: %s: tema */
		Logger::log( 'theme_switched', 'warning', sprintf( __( 'Tema attivo cambiato in: %s.', 'grs-security' ), $name ), self::actor() );
	}

	/**
	 * Protezioni disattivate nelle impostazioni del plugin.
	 *
	 * @param array $new_settings Nuove impostazioni.
	 * @param array $old_settings Precedenti.
	 * @return void
	 */
	public static function settings_changed( $new_settings, $old_settings ) {
		$off = array();
		foreach ( (array) $old_settings['fixes'] as $fix => $was ) {
			if ( $was && empty( $new_settings['fixes'][ $fix ] ) ) {
				$off[] = $fix;
			}
		}
		if ( $off ) {
			Logger::log(
				'protection_disabled',
				'warning',
				/* translators: %s: elenco protezioni */
				sprintf( __( 'Protezioni disattivate in GRS Security: %s.', 'grs-security' ), implode( ', ', $off ) ),
				self::actor()
			);
		}
	}
}
