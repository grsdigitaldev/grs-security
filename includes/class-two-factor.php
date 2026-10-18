<?php
/**
 * Autenticazione a due fattori (TOTP + codici di recupero).
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Secondo passaggio del login e gestione dei segreti utente.
 */
class Two_Factor {

	const META_SECRET   = 'grs_security_2fa_secret';
	const META_ENABLED  = 'grs_security_2fa_enabled';
	const META_LAST     = 'grs_security_2fa_last_step';
	const META_RECOVERY = 'grs_security_2fa_recovery';
	const META_PENDING  = 'grs_security_2fa_pending';
	const META_LOGIN    = 'grs_security_2fa_login';
	const ACTION        = 'grs_security_2fa';
	const TOKEN_TTL     = 600;
	const MAX_ATTEMPTS  = 5;

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		if ( self::globally_disabled() ) {
			return;
		}
		add_filter( 'authenticate', array( __CLASS__, 'intercept' ), 9999 );
		add_action( 'login_form_' . self::ACTION, array( __CLASS__, 'handle_form' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce_setup' ), 1 );
		add_filter( 'wp_login_errors', array( __CLASS__, 'login_messages' ) );
	}

	/**
	 * Messaggi sulla pagina di login dopo un secondo passaggio interrotto.
	 *
	 * @param \WP_Error $errors Errori.
	 * @return \WP_Error
	 */
	public static function login_messages( $errors ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- solo messaggio informativo.
		$state = isset( $_GET['grs_2fa'] ) ? sanitize_key( wp_unslash( $_GET['grs_2fa'] ) ) : '';
		if ( 'expired' === $state ) {
			$errors->add( 'grs_2fa_expired', __( 'Two-step verification has expired: log in again.', 'grs-security' ) );
		} elseif ( 'too_many' === $state ) {
			$errors->add( 'grs_2fa_too_many', __( 'Too many invalid codes: log in again.', 'grs-security' ) );
		}
		return $errors;
	}

	/**
	 * 2FA disattivata in emergenza da wp-config.php.
	 *
	 * @return bool
	 */
	public static function globally_disabled() {
		return defined( 'GRS_SECURITY_DISABLE_2FA' ) && GRS_SECURITY_DISABLE_2FA;
	}

	/**
	 * L'utente ha la 2FA attiva?
	 *
	 * @param int $user_id Utente.
	 * @return bool
	 */
	public static function is_enabled( $user_id ) {
		return '1' === (string) get_user_meta( $user_id, self::META_ENABLED, true ) && '' !== (string) get_user_meta( $user_id, self::META_SECRET, true );
	}

	/**
	 * La 2FA è obbligatoria per il ruolo dell'utente?
	 *
	 * @param \WP_User $user Utente.
	 * @return bool
	 */
	public static function is_required( $user ) {
		if ( ! $user instanceof \WP_User || ! Settings::fix_enabled( 'twofa' ) ) {
			return false;
		}
		$roles = (array) Settings::get( 'twofa_roles', array() );
		return (bool) array_intersect( $roles, (array) $user->roles );
	}

	/**
	 * Dopo la verifica della password: se serve la 2FA, sospende il login.
	 *
	 * @param \WP_User|\WP_Error|null $user Esito.
	 * @return \WP_User|\WP_Error|null
	 */
	public static function intercept( $user ) {
		if ( ! $user instanceof \WP_User || ! self::is_enabled( $user->ID ) ) {
			return $user;
		}
		if ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return new \WP_Error( 'grs_security_2fa_required', __( 'This account uses two-step verification: for apps use an Application Password.', 'grs-security' ) );
		}
		if ( wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return new \WP_Error( 'grs_security_2fa_required', __( 'This account uses two-step verification: log in from the site login page.', 'grs-security' ) );
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- il form di login core non ha nonce; leggiamo solo preferenze di redirect.
		$remember = ! empty( $_POST['rememberme'] );
		$redirect = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : '';
		// phpcs:enable

		$token = self::create_token( $user->ID, $remember, $redirect );
		wp_safe_redirect( self::form_url( $user->ID, $token ) );
		exit;
	}

	/**
	 * URL del secondo passaggio.
	 *
	 * @param int    $user_id Utente.
	 * @param string $token   Token.
	 * @return string
	 */
	public static function form_url( $user_id, $token ) {
		return add_query_arg(
			array(
				'action'    => self::ACTION,
				'grs_uid'   => (int) $user_id,
				'grs_token' => $token,
			),
			site_url( 'wp-login.php', 'login_post' )
		);
	}

	/**
	 * Crea il token monouso del login in sospeso.
	 *
	 * @param int    $user_id  Utente.
	 * @param bool   $remember Ricordami.
	 * @param string $redirect Destinazione.
	 * @return string
	 */
	private static function create_token( $user_id, $remember, $redirect ) {
		$token = wp_generate_password( 40, false, false );
		update_user_meta(
			$user_id,
			self::META_LOGIN,
			array(
				'hash'     => wp_hash( $token ),
				'expires'  => time() + self::TOKEN_TTL,
				'attempts' => 0,
				'remember' => (bool) $remember,
				'redirect' => $redirect,
			)
		);
		return $token;
	}

	/**
	 * Dati del login in sospeso se il token è valido.
	 *
	 * @param int    $user_id Utente.
	 * @param string $token   Token.
	 * @return array|null
	 */
	private static function pending_login( $user_id, $token ) {
		$data = get_user_meta( $user_id, self::META_LOGIN, true );
		if ( ! is_array( $data ) || empty( $data['hash'] ) || '' === $token ) {
			return null;
		}
		if ( (int) $data['expires'] < time() || ! hash_equals( (string) $data['hash'], wp_hash( $token ) ) ) {
			return null;
		}
		return $data;
	}

	/**
	 * Pagina del secondo passaggio (wp-login.php?action=grs_security_2fa).
	 *
	 * @return void
	 */
	public static function handle_form() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- il token monouso identifica il login in sospeso; il POST è verificato sotto.
		$user_id = isset( $_REQUEST['grs_uid'] ) ? absint( $_REQUEST['grs_uid'] ) : 0;
		$token   = isset( $_REQUEST['grs_token'] ) ? preg_replace( '/[^A-Za-z0-9]/', '', sanitize_text_field( wp_unslash( $_REQUEST['grs_token'] ) ) ) : '';
		// phpcs:enable
		$user = $user_id ? get_userdata( $user_id ) : false;
		$data = $user ? self::pending_login( $user_id, $token ) : null;

		header( 'Referrer-Policy: no-referrer' );

		if ( ! $user || ! $data ) {
			wp_safe_redirect( add_query_arg( 'grs_2fa', 'expired', wp_login_url() ) );
			exit;
		}

		$errors = new \WP_Error();

		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		if ( 'POST' === $method ) {
			if ( ! isset( $_POST['_grs_2fa_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_grs_2fa_nonce'] ) ), 'grs_security_2fa_' . $user_id ) ) {
				$errors->add( 'nonce', __( 'Session expired, enter the code again.', 'grs-security' ) );
			} elseif ( Settings::fix_enabled( 'login_guard' ) && Login_Guard::locked_remaining( Ip::current() ) > 0 && ! Ip::is_whitelisted( Ip::current() ) ) {
				delete_user_meta( $user_id, self::META_LOGIN );
				wp_safe_redirect( wp_login_url() );
				exit;
			} else {
				$code = isset( $_POST['grs_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['grs_2fa_code'] ) ) : '';
				if ( self::verify_login_code( $user, $code ) ) {
					self::complete_login( $user, $data );
				}
				++$data['attempts'];
				Login_Guard::register_failure( $user->user_login, 'two_factor' );
				Logger::log(
					'2fa_failed',
					'warning',
					__( 'Invalid two-step verification code.', 'grs-security' ),
					array(
						'user_id'  => $user->ID,
						'username' => $user->user_login,
					)
				);
				if ( $data['attempts'] >= self::MAX_ATTEMPTS ) {
					delete_user_meta( $user_id, self::META_LOGIN );
					wp_safe_redirect( add_query_arg( 'grs_2fa', 'too_many', wp_login_url() ) );
					exit;
				}
				update_user_meta( $user_id, self::META_LOGIN, $data );
				$errors->add( 'invalid_code', __( 'Invalid code. Check the phone time and try again.', 'grs-security' ) );
			}
		}

		self::render_form( $user_id, $token, $errors );
		exit;
	}

	/**
	 * Verifica codice TOTP o codice di recupero.
	 *
	 * @param \WP_User $user Utente.
	 * @param string   $code Codice.
	 * @return bool
	 */
	public static function verify_login_code( $user, $code ) {
		$secret = (string) get_user_meta( $user->ID, self::META_SECRET, true );
		$last   = (int) get_user_meta( $user->ID, self::META_LAST, true );
		$step   = Totp::verify( $secret, $code, $last );
		if ( $step > 0 ) {
			update_user_meta( $user->ID, self::META_LAST, $step );
			return true;
		}
		if ( self::use_recovery_code( $user->ID, $code ) ) {
			$left = count( self::recovery_hashes( $user->ID ) );
			Logger::log(
				'2fa_recovery_used',
				'warning',
				/* translators: %d: codes left */
				sprintf( __( 'Login with a recovery code (%d left).', 'grs-security' ), $left ),
				array(
					'user_id'  => $user->ID,
					'username' => $user->user_login,
				)
			);
			return true;
		}
		return false;
	}

	/**
	 * Completa il login dopo il secondo passaggio.
	 *
	 * @param \WP_User $user Utente.
	 * @param array    $data Dati del login in sospeso.
	 * @return void
	 */
	private static function complete_login( $user, $data ) {
		delete_user_meta( $user->ID, self::META_LOGIN );
		wp_set_auth_cookie( $user->ID, ! empty( $data['remember'] ) );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.

		$requested = isset( $data['redirect'] ) ? (string) $data['redirect'] : '';
		$redirect  = '' !== $requested ? $requested : admin_url();
		$redirect  = apply_filters( 'login_redirect', $redirect, $requested, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- hook core.
		if ( ( empty( $redirect ) || admin_url() === $redirect ) && ! $user->has_cap( 'read' ) ) {
			$redirect = home_url( '/' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Form del codice nella grafica della pagina di login.
	 *
	 * @param int       $user_id Utente.
	 * @param string    $token   Token.
	 * @param \WP_Error $errors  Errori.
	 * @return void
	 */
	private static function render_form( $user_id, $token, $errors ) {
		if ( function_exists( 'login_header' ) ) {
			login_header( __( 'Two-step verification', 'grs-security' ), '', $errors );
		}
		?>
		<form name="grs_2fa_form" id="loginform" action="<?php echo esc_url( self::form_url( $user_id, $token ) ); ?>" method="post" autocomplete="off">
			<p><?php esc_html_e( 'Open the authenticator app and enter the 6-digit code. If you don\'t have your phone, use one of the recovery codes.', 'grs-security' ); ?></p>
			<p>
				<label for="grs_2fa_code"><?php esc_html_e( 'Verification code', 'grs-security' ); ?></label>
				<input type="text" name="grs_2fa_code" id="grs_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="text" autofocus required />
			</p>
			<?php wp_nonce_field( 'grs_security_2fa_' . $user_id, '_grs_2fa_nonce' ); ?>
			<p class="submit">
				<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'grs-security' ); ?>" />
			</p>
		</form>
		<p id="nav"><a href="<?php echo esc_url( wp_login_url() ); ?>"><?php esc_html_e( 'Back to login', 'grs-security' ); ?></a></p>
		<?php
		if ( function_exists( 'login_footer' ) ) {
			login_footer( 'grs_2fa_code' );
		}
	}

	/**
	 * Obbliga gli utenti dei ruoli richiesti a configurare la 2FA.
	 *
	 * @return void
	 */
	public static function enforce_setup() {
		if ( wp_doing_ajax() || ! is_user_logged_in() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! self::is_required( $user ) || self::is_enabled( $user->ID ) ) {
			return;
		}
		global $pagenow;
		if ( 'profile.php' === $pagenow ) {
			return;
		}
		wp_safe_redirect( admin_url( 'profile.php?grs_2fa_required=1#grs-security-2fa' ) );
		exit;
	}

	/**
	 * Segreto in attesa di conferma (creato se manca).
	 *
	 * @param int $user_id Utente.
	 * @return string
	 */
	public static function pending_secret( $user_id ) {
		$secret = (string) get_user_meta( $user_id, self::META_PENDING, true );
		if ( '' === $secret ) {
			$secret = Totp::generate_secret();
			update_user_meta( $user_id, self::META_PENDING, $secret );
		}
		return $secret;
	}

	/**
	 * Attiva la 2FA se il codice è valido per il segreto in attesa.
	 *
	 * @param int    $user_id Utente.
	 * @param string $code    Codice.
	 * @return string[]|false Codici di recupero generati, false se codice errato.
	 */
	public static function enable( $user_id, $code ) {
		$secret = (string) get_user_meta( $user_id, self::META_PENDING, true );
		$step   = '' !== $secret ? Totp::verify( $secret, $code, 0 ) : 0;
		if ( ! $step ) {
			return false;
		}
		update_user_meta( $user_id, self::META_SECRET, $secret );
		update_user_meta( $user_id, self::META_LAST, $step );
		update_user_meta( $user_id, self::META_ENABLED, '1' );
		delete_user_meta( $user_id, self::META_PENDING );
		$codes = self::generate_recovery_codes( $user_id );

		$user = get_userdata( $user_id );
		Logger::log(
			'2fa_enabled',
			'info',
			__( 'Two-step verification enabled.', 'grs-security' ),
			array(
				'user_id'  => $user_id,
				'username' => $user ? $user->user_login : '',
			)
		);
		return $codes;
	}

	/**
	 * Disattiva la 2FA e cancella i dati.
	 *
	 * @param int    $user_id Utente.
	 * @param string $by      self|admin.
	 * @return void
	 */
	public static function disable( $user_id, $by = 'self' ) {
		foreach ( array( self::META_SECRET, self::META_ENABLED, self::META_LAST, self::META_RECOVERY, self::META_PENDING, self::META_LOGIN ) as $key ) {
			delete_user_meta( $user_id, $key );
		}
		$user  = get_userdata( $user_id );
		$actor = wp_get_current_user();
		Logger::log(
			'2fa_disabled',
			'warning',
			'admin' === $by
				/* translators: %s: administrator */
				? sprintf( __( 'Two-step verification reset by %s.', 'grs-security' ), $actor->user_login )
				: __( 'Two-step verification disabled by the user.', 'grs-security' ),
			array(
				'user_id'  => $user_id,
				'username' => $user ? $user->user_login : '',
			)
		);
	}

	/**
	 * Genera 10 nuovi codici di recupero (salvati come hash).
	 *
	 * @param int $user_id Utente.
	 * @return string[]
	 */
	public static function generate_recovery_codes( $user_id ) {
		$codes  = array();
		$hashes = array();
		for ( $i = 0; $i < 10; $i++ ) {
			$raw      = strtolower( wp_generate_password( 10, false, false ) );
			$code     = substr( $raw, 0, 5 ) . '-' . substr( $raw, 5 );
			$codes[]  = $code;
			$hashes[] = wp_hash_password( $raw );
		}
		update_user_meta( $user_id, self::META_RECOVERY, $hashes );
		return $codes;
	}

	/**
	 * Hash dei codici di recupero rimasti.
	 *
	 * @param int $user_id Utente.
	 * @return string[]
	 */
	public static function recovery_hashes( $user_id ) {
		$hashes = get_user_meta( $user_id, self::META_RECOVERY, true );
		return is_array( $hashes ) ? array_values( $hashes ) : array();
	}

	/**
	 * Consuma un codice di recupero se valido.
	 *
	 * @param int    $user_id Utente.
	 * @param string $code    Codice.
	 * @return bool
	 */
	private static function use_recovery_code( $user_id, $code ) {
		$raw = strtolower( preg_replace( '/[^a-zA-Z0-9]/', '', (string) $code ) );
		if ( 10 !== strlen( $raw ) ) {
			return false;
		}
		$hashes = self::recovery_hashes( $user_id );
		foreach ( $hashes as $i => $hash ) {
			// Senza user_id: le vecchie versioni di WP altrimenti riscriverebbero la password dell'utente.
			if ( wp_check_password( $raw, $hash ) ) {
				unset( $hashes[ $i ] );
				update_user_meta( $user_id, self::META_RECOVERY, array_values( $hashes ) );
				return true;
			}
		}
		return false;
	}
}
