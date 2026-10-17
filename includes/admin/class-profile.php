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
			echo '<div class="notice notice-warning"><p><strong>' . esc_html__( 'Verifica in due passaggi obbligatoria.', 'grs-security' ) . '</strong> ' . esc_html__( 'Per continuare a usare la bacheca configura la verifica in due passaggi nella sezione qui sotto.', 'grs-security' ) . ' <a href="#grs-security-2fa">' . esc_html__( 'Vai alla configurazione', 'grs-security' ) . '</a></p></div>';
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
		<h2 id="grs-security-2fa"><?php esc_html_e( 'Verifica in due passaggi', 'grs-security' ); ?></h2>
		<?php
		if ( Two_Factor::globally_disabled() ) {
			echo '<p>' . esc_html__( 'La verifica in due passaggi è temporaneamente disattivata su tutto il sito (costante GRS_SECURITY_DISABLE_2FA).', 'grs-security' ) . '</p>';
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
				<p><strong><?php esc_html_e( 'Salva ora i codici di recupero.', 'grs-security' ); ?></strong> <?php esc_html_e( 'Ogni codice funziona una sola volta, al posto del codice dell\'app, se perdi il telefono. Non verranno mostrati di nuovo.', 'grs-security' ); ?></p>
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
					<th scope="row"><?php esc_html_e( 'Stato', 'grs-security' ); ?></th>
					<td>
						<p><span class="grs-sec-badge grs-sec-badge--ok"><?php esc_html_e( 'Attiva', 'grs-security' ); ?></span>
						<?php
						/* translators: %d: codici rimasti */
						echo esc_html( sprintf( _n( 'Ti resta %d codice di recupero.', 'Ti restano %d codici di recupero.', $left, 'grs-security' ), $left ) );
						?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="grs_2fa_action"><?php esc_html_e( 'Gestione', 'grs-security' ); ?></label></th>
					<td>
						<select name="grs_2fa_action" id="grs_2fa_action">
							<option value=""><?php esc_html_e( 'Nessuna modifica', 'grs-security' ); ?></option>
							<option value="regen"><?php esc_html_e( 'Genera nuovi codici di recupero', 'grs-security' ); ?></option>
							<?php if ( ! $required ) : ?>
								<option value="disable"><?php esc_html_e( 'Disattiva la verifica in due passaggi', 'grs-security' ); ?></option>
							<?php endif; ?>
						</select>
						<input type="text" name="grs_2fa_confirm" value="" class="regular-text" autocomplete="one-time-code" placeholder="<?php esc_attr_e( 'Codice attuale dell\'app', 'grs-security' ); ?>" />
						<p class="description"><?php esc_html_e( 'Per confermare inserisci il codice attuale dell\'app (o un codice di recupero) e premi "Aggiorna profilo".', 'grs-security' ); ?>
						<?php if ( $required ) : ?>
							<?php esc_html_e( 'Per il tuo ruolo la verifica in due passaggi è obbligatoria e non può essere disattivata.', 'grs-security' ); ?>
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
				<th scope="row"><?php esc_html_e( '1. Collega l\'app', 'grs-security' ); ?></th>
				<td>
					<p><?php esc_html_e( 'Inquadra il codice QR con un\'app di autenticazione (Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden...).', 'grs-security' ); ?></p>
					<div class="grs-sec-qr" data-otpauth="<?php echo esc_attr( $uri ); ?>"></div>
					<p><?php esc_html_e( 'Oppure inserisci a mano questa chiave:', 'grs-security' ); ?> <code class="grs-sec-secret"><?php echo esc_html( trim( chunk_split( $secret, 4, ' ' ) ) ); ?></code></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="grs_2fa_setup_code"><?php esc_html_e( '2. Conferma', 'grs-security' ); ?></label></th>
				<td>
					<input type="text" name="grs_2fa_setup_code" id="grs_2fa_setup_code" value="" class="regular-text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" />
					<p class="description"><?php esc_html_e( 'Inserisci il codice di 6 cifre mostrato dall\'app e premi "Aggiorna profilo". Riceverai i codici di recupero da conservare.', 'grs-security' ); ?></p>
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
		<h2 id="grs-security-2fa"><?php esc_html_e( 'Verifica in due passaggi', 'grs-security' ); ?></h2>
		<?php
		wp_nonce_field( 'grs_security_profile_2fa_' . $user->ID, '_grs_2fa_profile_nonce' );
		if ( ! Two_Factor::is_enabled( $user->ID ) ) {
			echo '<p>' . esc_html__( 'Non attiva per questo utente.', 'grs-security' ) . ( Two_Factor::is_required( $user ) ? ' ' . esc_html__( 'È obbligatoria per il suo ruolo: dovrà configurarla al prossimo accesso.', 'grs-security' ) : '' ) . '</p>';
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
				<th scope="row"><?php esc_html_e( 'Azzera', 'grs-security' ); ?></th>
				<td>
					<label><input type="checkbox" name="grs_2fa_reset" value="1" /> <?php esc_html_e( 'Disattiva la verifica in due passaggi per questo account (ad esempio se l\'utente ha perso il telefono)', 'grs-security' ); ?></label>
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
				$errors->add( 'grs_2fa_setup', __( 'Verifica in due passaggi: il codice non è corretto. Controlla che l\'ora del telefono sia automatica e riprova.', 'grs-security' ) );
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
			$errors->add( 'grs_2fa_confirm', __( 'Verifica in due passaggi: codice di conferma non valido, nessuna modifica eseguita.', 'grs-security' ) );
			return;
		}
		if ( 'regen' === $action ) {
			set_transient( 'grs_security_codes_' . $user_id, Two_Factor::generate_recovery_codes( $user_id ), 10 * MINUTE_IN_SECONDS );
			return;
		}
		if ( Two_Factor::is_required( $wp_user ) ) {
			$errors->add( 'grs_2fa_required', __( 'La verifica in due passaggi è obbligatoria per il tuo ruolo.', 'grs-security' ) );
			return;
		}
		Two_Factor::disable( $user_id, 'self' );
	}
}
