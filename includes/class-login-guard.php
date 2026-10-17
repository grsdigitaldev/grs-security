<?php
/**
 * Limite ai tentativi di login con blocco temporaneo progressivo per IP.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- tabella custom del plugin, nessuna API WP equivalente.

/**
 * Protezione dal brute force.
 */
class Login_Guard {

	/**
	 * Durata massima di un blocco (secondi).
	 */
	const MAX_LOCK = DAY_IN_SECONDS;

	/**
	 * Registra gli hook se la protezione è attiva.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! Settings::fix_enabled( 'login_guard' ) ) {
			return;
		}
		add_filter( 'authenticate', array( __CLASS__, 'check_locked' ), 99 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 10, 1 );
		add_action( 'wp_login', array( __CLASS__, 'on_success' ), 10, 0 );
		add_action( 'application_password_failed_authentication', array( __CLASS__, 'on_app_password_failed' ) );
	}

	/**
	 * Blocca l'autenticazione se l'IP è bloccato.
	 *
	 * @param \WP_User|\WP_Error|null $user Esito.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function check_locked( $user ) {
		$ip = Ip::current();
		if ( '' === $ip || Ip::is_whitelisted( $ip ) ) {
			return $user;
		}
		$remaining = self::locked_remaining( $ip );
		if ( $remaining > 0 ) {
			$minutes = (int) ceil( $remaining / MINUTE_IN_SECONDS );
			return new \WP_Error(
				'grs_security_locked',
				'<strong>' . esc_html__( 'Accesso temporaneamente bloccato:', 'grs-security' ) . '</strong> ' . esc_html(
					sprintf(
						/* translators: %d: minuti */
						_n( 'troppi tentativi non riusciti. Riprova tra %d minuto.', 'troppi tentativi non riusciti. Riprova tra %d minuti.', $minutes, 'grs-security' ),
						$minutes
					)
				)
			);
		}
		return $user;
	}

	/**
	 * Tentativo fallito dal form di login.
	 *
	 * @param string $username Nome utente inserito.
	 * @return void
	 */
	public static function on_failed( $username ) {
		self::register_failure( (string) $username, 'login' );
	}

	/**
	 * Tentativo fallito con Application Password.
	 *
	 * @param \WP_Error $error Errore.
	 * @return void
	 */
	public static function on_app_password_failed( $error ) {
		unset( $error );
		self::register_failure( '', 'application_password' );
	}

	/**
	 * Login riuscito: azzera il contatore dell'IP.
	 *
	 * @return void
	 */
	public static function on_success() {
		global $wpdb;
		$ip = Ip::current();
		if ( '' !== $ip ) {
			$wpdb->delete( Database::lockout_table(), array( 'ip' => $ip ), array( '%s' ) );
		}
	}

	/**
	 * Registra un tentativo fallito e blocca l'IP oltre la soglia.
	 *
	 * @param string $username Nome utente tentato.
	 * @param string $source   login|application_password|two_factor.
	 * @return void
	 */
	public static function register_failure( $username, $source = 'login' ) {
		global $wpdb;
		if ( ! Settings::fix_enabled( 'login_guard' ) ) {
			return;
		}
		$ip = Ip::current();
		if ( '' === $ip || Ip::is_whitelisted( $ip ) ) {
			return;
		}
		$table = Database::lockout_table();
		$now   = time();
		$row   = self::get_row( $ip );

		if ( $row && (int) $row['locked_until'] > $now ) {
			return;
		}

		$window   = (int) Settings::get( 'login_window', 15 ) * MINUTE_IN_SECONDS;
		$max      = (int) Settings::get( 'login_max_attempts', 5 );
		$attempts = 1;
		$first    = $now;
		$lockouts = 0;
		if ( $row ) {
			$lockouts = ( $now - (int) $row['updated_at'] ) < DAY_IN_SECONDS ? (int) $row['lockouts'] : 0;
			if ( ( $now - (int) $row['first_attempt'] ) <= $window ) {
				$attempts = (int) $row['attempts'] + 1;
				$first    = (int) $row['first_attempt'];
			}
		}

		$locked_until = 0;
		if ( $attempts >= $max ) {
			++$lockouts;
			$base         = (int) Settings::get( 'login_lockout', 15 ) * MINUTE_IN_SECONDS;
			$duration     = (int) min( self::MAX_LOCK, $base * pow( 2, min( 10, $lockouts - 1 ) ) );
			$locked_until = $now + $duration;
			$attempts     = 0;

			Logger::log(
				'login_lockout',
				'warning',
				sprintf(
					/* translators: 1: IP, 2: minuti */
					__( 'IP %1$s bloccato per %2$d minuti dopo troppi tentativi di accesso non riusciti.', 'grs-security' ),
					$ip,
					(int) round( $duration / MINUTE_IN_SECONDS )
				),
				array(
					'username' => $username,
					'ip'       => $ip,
					'context'  => array(
						'source'   => $source,
						'lockouts' => $lockouts,
					),
				)
			);
		}

		$data = array(
			'ip'            => $ip,
			'attempts'      => $attempts,
			'first_attempt' => $first,
			'locked_until'  => $locked_until,
			'lockouts'      => $lockouts,
			'last_username' => substr( $username, 0, 191 ),
			'updated_at'    => $now,
		);
		$fmt  = array( '%s', '%d', '%d', '%d', '%d', '%s', '%d' );
		if ( $row ) {
			$wpdb->update( $table, $data, array( 'ip' => $ip ), $fmt, array( '%s' ) );
		} else {
			$wpdb->insert( $table, $data, $fmt );
		}
	}

	/**
	 * Secondi di blocco rimanenti per un IP.
	 *
	 * @param string $ip IP.
	 * @return int
	 */
	public static function locked_remaining( $ip ) {
		$row = self::get_row( $ip );
		if ( ! $row ) {
			return 0;
		}
		return max( 0, (int) $row['locked_until'] - time() );
	}

	/**
	 * Riga dell'IP.
	 *
	 * @param string $ip IP.
	 * @return array|null
	 */
	private static function get_row( $ip ) {
		global $wpdb;
		$table = Database::lockout_table();
		$row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip = %s", $ip ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		return is_array( $row ) ? $row : null;
	}

	/**
	 * IP attualmente bloccati.
	 *
	 * @return array
	 */
	public static function locked_list() {
		global $wpdb;
		$table = Database::lockout_table();
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE locked_until > %d ORDER BY locked_until DESC LIMIT 200", time() ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Sblocca un IP.
	 *
	 * @param string $ip IP.
	 * @return void
	 */
	public static function unlock( $ip ) {
		global $wpdb;
		$wpdb->delete( Database::lockout_table(), array( 'ip' => $ip ), array( '%s' ) );
	}

	/**
	 * Pulizia delle righe scadute.
	 *
	 * @return void
	 */
	public static function purge() {
		global $wpdb;
		$table = Database::lockout_table();
		$limit = time() - DAY_IN_SECONDS;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE locked_until < %d AND updated_at < %d", $limit, $limit ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- nome tabella interno.
	}
}
