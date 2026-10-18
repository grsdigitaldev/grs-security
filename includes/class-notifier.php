<?php
/**
 * Avvisi email per gli eventi importanti.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Invio degli avvisi con limitazione della frequenza.
 */
class Notifier {

	/**
	 * Eventi non critici che inviano comunque un'email.
	 *
	 * @var string[]
	 */
	const EMAIL_EVENTS = array( '2fa_disabled', '2fa_recovery_used', 'protection_disabled', 'plugin_installed', 'theme_installed', 'theme_switched' );

	/**
	 * Eventi mai limitati (ogni occorrenza è importante).
	 *
	 * @var string[]
	 */
	const NEVER_THROTTLE = array( 'admin_created', 'admin_role_granted' );

	/**
	 * Registra l'hook.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'grs_security_event_logged', array( __CLASS__, 'on_event' ), 10, 5 );
	}

	/**
	 * Decide se inviare l'email per un evento registrato.
	 *
	 * @param int    $id       Id riga.
	 * @param string $event    Codice.
	 * @param string $severity Gravità.
	 * @param string $message  Messaggio.
	 * @param array  $args     Argomenti.
	 * @return void
	 */
	public static function on_event( $id, $event, $severity, $message, $args ) {
		unset( $id );
		if ( ! Settings::get( 'alerts_enabled', true ) ) {
			return;
		}
		/**
		 * Eventi che generano un'email oltre a quelli critici.
		 *
		 * @param string[] $events Codici evento.
		 */
		$events = (array) apply_filters( 'grs_security_email_events', self::EMAIL_EVENTS );
		if ( 'critical' !== $severity && ! in_array( $event, $events, true ) ) {
			return;
		}
		if ( ! in_array( $event, self::NEVER_THROTTLE, true ) ) {
			$key = 'grs_security_mail_' . md5( $event );
			if ( get_transient( $key ) ) {
				return;
			}
			set_transient( $key, 1, 15 * MINUTE_IN_SECONDS );
		}

		// Testi dell'email nella lingua del destinatario (il messaggio dell'evento resta come è stato registrato).
		$switched = Plugin::switch_to_recipient_locale( Settings::alert_email() );
		$lines    = array( $message, '' );
		if ( ! empty( $args['username'] ) ) {
			/* translators: %s: user */
			$lines[] = sprintf( __( 'User: %s', 'grs-security' ), $args['username'] );
		}
		$ip = isset( $args['ip'] ) ? (string) $args['ip'] : Ip::current();
		if ( '' !== $ip ) {
			/* translators: %s: IP */
			$lines[] = sprintf( __( 'IP: %s', 'grs-security' ), $ip );
		}
		if ( ! empty( $args['context']['files'] ) ) {
			$lines[] = '';
			$lines[] = (string) $args['context']['files'];
		}
		/* translators: %s: date and time */
		$lines[] = sprintf( __( 'Date: %s', 'grs-security' ), wp_date( Plugin::datetime_format() ) );
		$lines[] = '';
		$lines[] = __( 'If you do not recognize this activity, check the site immediately:', 'grs-security' );
		$lines[] = Plugin::admin_url( 'log' );

		self::send(
			'critical' === $severity ? __( 'Important security alert', 'grs-security' ) : __( 'Security alert', 'grs-security' ),
			implode( "\n", $lines )
		);
		if ( $switched ) {
			restore_previous_locale();
		}
	}

	/**
	 * Invia un'email all'indirizzo degli avvisi.
	 *
	 * @param string $subject Oggetto (senza nome sito).
	 * @param string $body    Testo.
	 * @return bool
	 */
	public static function send( $subject, $body ) {
		$to = Settings::alert_email();
		if ( ! is_email( $to ) ) {
			return false;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$body = $body . "\n\n-- \n" . sprintf(
			/* translators: 1: site, 2: URL */
			__( 'GRS Security on %1$s (%2$s)', 'grs-security' ),
			$site,
			home_url( '/' )
		);
		return wp_mail( $to, '[' . $site . '] ' . $subject, $body );
	}
}
