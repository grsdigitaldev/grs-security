<?php
/**
 * Sezione "Verifica in due passaggi" nel profilo utente.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Admin;

use GRSDigital\Security\Totp;
use GRSDigital\Security\Two_Factor;

defined( 'ABSPATH' ) || exit;

/**
 * Configurazione della 2FA da parte dell'utente.
 */
class Profile {

	/**
	 * Registra gli hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'show_user_profile', array( __CLASS__, 'render_own' ), 5 );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_other' ), 5 );
		add_action( 'user_profile_update_errors', array( __CLASS__, 'process' ), 10, 3 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'required_notice' ) );
	}

	/**
	 * Script del QR code solo nella pagina profilo.
	 *
	 * @param string $hook Pagina.
	 * @return void
	 */
	public static function assets( $hook ) {
		if ( 'profile.php' !== $hook ) {
			return;
		}
		wp_enqueue_script( 'grs-security-qrcode', GRS_SECURITY_URL . 'assets/js/vendor/qrcode.js', array(), '2.0.4', true );
		wp_enqueue_script( 'grs-security-profile', GRS_SECURITY_URL . 'assets/js/profile.js', array( 'grs-security-qrcode' ), GRS_SECURITY_VERSION, true );
		wp_enqueue_style( 'grs-security-admin', GRS_SECURITY_URL . 'assets/css/admin.css', array(), GRS_SECURITY_VERSION );
	}

	/**
	 * Avviso quando la 2FA è obbligatoria e non ancora configurata.
	 *
	 * @return void
	 */
	public static function required_notice() {
		global $pagenow;
		if ( 'profile.php' !== $pagenow ) {
			return;
		}
		Admin::render_notices();
		if ( Two_Factor::globally_disabled() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( Two_Factor::is_required( $user ) && ! Two_Factor::is_enabled( $user->ID ) ) {
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Two-step verification is mandatory.', 'grs-security' ) . '</strong> ' . esc_html__( 'To keep using the dashboard, set up two-step verification in the section below.', 'grs-security' ) . ' <a href="#grs-security-2fa">' . esc_html__( 'Go to setup', 'grs-security' ) . '</a></p></div>';
		}
	}

	/**
	 * Sezione nel proprio profilo.
	 *
	 * @param \WP_User $user Utente.
	 * @return void
	 */
	public static function render_own( $user ) {
		?>
		<h2 id="grs-security-2fa"><?php esc_html_e( 'Two-step verification', 'grs-security' ); ?></h2>
		<?php
		if ( Two_Factor::globally_disabled() ) {
			echo '<p>' . esc_html__( 'Two-step verification is temporarily disabled on the whole site (GRS_SECURITY_DISABLE_2FA constant).', 'grs-security' ) . '</p>';
			if ( Two_Factor::is_enabled( $user->ID ) ) {
				self::reset_field( $user );
			}
			return;
		}
		wp_nonce_field( 'grs_security_profile_2fa_' . $user->ID, '_grs_2fa_profile_nonce' );

		$codes = get_transient( 'grs_security_codes_' . $user->ID );
		if ( is_array( $codes ) ) {
			delete_transient( 'grs_security_codes_' . $user->ID );
			?>
			<div class="grs-sec-codes notice notice-success inline">
				<p><strong><?php esc_html_e( 'Save your recovery codes now.', 'grs-security' ); ?></strong> <?php esc_html_e( 'Each code works only once, instead of the app code, if you lose your phone. They will not be shown again.', 'grs-security' ); ?></p>
				<pre><?php echo esc_html( implode( "\n", $codes ) ); ?></pre>
			</div>
			<?php
		}

		if ( Two_Factor::is_enabled( $user->ID ) ) {
			$left     = count( Two_Factor::recovery_hashes( $user->ID ) );
			$required = Two_Factor::is_required( $user );
			?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Status', 'grs-security' ); ?></th>
					<td>
						<p><span class="grs-sec-badge grs-sec-badge--ok"><?php esc_html_e( 'Active', 'grs-security' ); ?></span>
						<?php
						/* translators: %d: codes left */
						echo esc_html( sprintf( _n( 'You have %d recovery code left.', 'You have %d recovery codes left.', $left, 'grs-security' ), $left ) );
						?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="grs_2fa_action"><?php esc_html_e( 'Management', 'grs-security' ); ?></label></th>
					<td>
						<select name="grs_2fa_action" id="grs_2fa_action">
							<option value=""><?php esc_html_e( 'No change', 'grs-security' ); ?></option>
							<option value="regen"><?php esc_html_e( 'Generate new recovery codes', 'grs-security' ); ?></option>
							<?php if ( ! $required ) : ?>
								<option value="disable"><?php esc_html_e( 'Disable two-step verification', 'grs-security' ); ?></option>
							<?php endif; ?>
						</select>
						<input type="text" name="grs_2fa_confirm" value="" class="regular-text" autocomplete="one-time-code" placeholder="<?php esc_attr_e( 'Current app code', 'grs-security' ); ?>" />
						<p class="description"><?php esc_html_e( 'To confirm, enter the current app code (or a recovery code) and click "Update Profile".', 'grs-security' ); ?>
						<?php if ( $required ) : ?>
							<?php esc_html_e( 'Two-step verification is mandatory for your role and cannot be disabled.', 'grs-security' ); ?>
						<?php endif; ?>
						</p>
					</td>
				</tr>
			</table>
			<?php
			return;
		}

		$secret = Two_Factor::pending_secret( $user->ID );
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$uri    = Totp::uri( $secret, $user->user_email ? $user->user_email : $user->user_login, '' !== $issuer ? $issuer : wp_parse_url( home_url(), PHP_URL_HOST ) );
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( '1. Connect the app', 'grs-security' ); ?></th>
				<td>
					<p><?php esc_html_e( 'Scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden...).', 'grs-security' ); ?></p>
					<div class="grs-sec-qr" data-otpauth="<?php echo esc_attr( $uri ); ?>"></div>
					<p><?php esc_html_e( 'Or enter this key manually:', 'grs-security' ); ?> <code class="grs-sec-secret"><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="grs_2fa_setup_code"><?php esc_html_e( '2. Confirm', 'grs-security' ); ?></label></th>
				<td>
					<input type="text" name="grs_2fa_setup_code" id="grs_2fa_setup_code" value="" class="regular-text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" />
					<p class="description"><?php esc_html_e( 'Enter the 6-digit code shown by the app and click "Update Profile". You will receive recovery codes to keep.', 'grs-security' ); ?></p>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Sezione nel profilo di un altro utente (solo amministratori).
	 *
	 * @param \WP_User $user Utente modificato.
	 * @return void
	 */
	public static function render_other( $user ) {
		if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		?>
		<h2 id="grs-security-2fa"><?php esc_html_e( 'Two-step verification', 'grs-security' ); ?></h2>
		<?php
		wp_nonce_field( 'grs_security_profile_2fa_' . $user->ID, '_grs_2fa_profile_nonce' );
		if ( ! Two_Factor::is_enabled( $user->ID ) ) {
			echo '<p>' . esc_html__( 'Not active for this user.', 'grs-security' ) . ( Two_Factor::is_required( $user ) ? ' ' . esc_html__( 'It is mandatory for their role: they will have to set it up at the next login.', 'grs-security' ) : '' ) . '</p>';
			return;
		}
		self::reset_field( $user );
	}

	/**
	 * Casella di azzeramento.
	 *
	 * @param \WP_User $user Utente.
	 * @return void
	 */
	private static function reset_field( $user ) {
		?>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Reset', 'grs-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="grs_2fa_reset" value="1" /> <?php esc_html_e( 'Disable two-step verification for this account (for example if the user lost their phone)', 'grs-security' ); ?></label>
				</td>
			</tr>
		</table>
		<?php
		if ( get_current_user_id() === (int) $user->ID ) {
			wp_nonce_field( 'grs_security_profile_2fa_' . $user->ID, '_grs_2fa_profile_nonce' );
		}
	}

	/**
	 * Elabora le azioni al salvataggio del profilo.
	 *
	 * @param \WP_Error $errors Errori.
	 * @param bool      $update Aggiornamento.
	 * @param object    $user   Dati utente (con ID).
	 * @return void
	 */
	public static function process( $errors, $update, $user ) {
		if ( ! $update || empty( $user->ID ) ) {
			return;
		}
		$user_id = (int) $user->ID;
		if ( ! isset( $_POST['_grs_2fa_profile_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_grs_2fa_profile_nonce'] ) ), 'grs_security_profile_2fa_' . $user_id ) ) {
			return;
		}
		$own = get_current_user_id() === $user_id;

		if ( ! empty( $_POST['grs_2fa_reset'] ) ) {
			if ( ( current_user_can( 'manage_options' ) && current_user_can( 'edit_user', $user_id ) ) || ( $own && Two_Factor::globally_disabled() ) ) {
				Two_Factor::disable( $user_id, $own ? 'self' : 'admin' );
			}
			return;
		}
		if ( ! $own || Two_Factor::globally_disabled() ) {
			return;
		}

		if ( ! Two_Factor::is_enabled( $user_id ) ) {
			$code = isset( $_POST['grs_2fa_setup_code'] ) ? sanitize_text_field( wp_unslash( $_POST['grs_2fa_setup_code'] ) ) : '';
			if ( '' === $code ) {
				return;
			}
			$codes = Two_Factor::enable( $user_id, $code );
			if ( false === $codes ) {
				$errors->add( 'grs_2fa_setup', __( 'Two-step verification: the code is not correct. Make sure the phone time is set automatically and try again.', 'grs-security' ) );
				return;
			}
			set_transient( 'grs_security_codes_' . $user_id, $codes, 10 * MINUTE_IN_SECONDS );
			return;
		}

		$action = isset( $_POST['grs_2fa_action'] ) ? sanitize_key( wp_unslash( $_POST['grs_2fa_action'] ) ) : '';
		if ( ! in_array( $action, array( 'regen', 'disable' ), true ) ) {
			return;
		}
		$code    = isset( $_POST['grs_2fa_confirm'] ) ? sanitize_text_field( wp_unslash( $_POST['grs_2fa_confirm'] ) ) : '';
		$wp_user = get_userdata( $user_id );
		if ( ! $wp_user || ! Two_Factor::verify_login_code( $wp_user, $code ) ) {
			$errors->add( 'grs_2fa_confirm', __( 'Two-step verification: invalid confirmation code, no change made.', 'grs-security' ) );
			return;
		}
		if ( 'regen' === $action ) {
			set_transient( 'grs_security_codes_' . $user_id, Two_Factor::generate_recovery_codes( $user_id ), 10 * MINUTE_IN_SECONDS );
			return;
		}
		if ( Two_Factor::is_required( $wp_user ) ) {
			$errors->add( 'grs_2fa_required', __( 'Two-step verification is mandatory for your role.', 'grs-security' ) );
			return;
		}
		Two_Factor::disable( $user_id, 'self' );
	}
}
