<?php
/**
 * Controlli sulle protezioni attive del plugin e sul monitoraggio.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Integrity;
use GRSDigital\Security\Ip;
use GRSDigital\Security\Login_Url;
use GRSDigital\Security\Plugin;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Protezioni attive e monitoraggio".
 */
class Protection_Checks {

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		return array(
			self::login_guard(),
			self::ip_source(),
			self::firewall(),
			self::integrity_enabled(),
			self::integrity_results(),
			self::login_url(),
			self::alerts(),
		);
	}

	/**
	 * Limite tentativi di login.
	 *
	 * @return array
	 */
	private static function login_guard() {
		$applied = Settings::fix_enabled( 'login_guard' );
		return Scanner::result(
			array(
				'id'           => 'login_guard',
				'category'     => 'monitoring',
				'title'        => __( 'Limite ai tentativi di accesso', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => $applied
					/* translators: 1: tentativi, 2: minuti */
					? sprintf( __( 'Dopo %1$d tentativi falliti l\'IP viene bloccato per %2$d minuti (il blocco raddoppia se l\'attacco continua).', 'grs-security' ), (int) Settings::get( 'login_max_attempts' ), (int) Settings::get( 'login_lockout' ) )
					: __( 'Nessun limite ai tentativi di accesso: un bot può provare password senza sosta.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Blocca temporaneamente gli IP che sbagliano troppe volte la password (anche via XML-RPC e Application Passwords). Puoi indicare gli IP fidati nelle impostazioni.', 'grs-security' ),
			)
		);
	}

	/**
	 * Sorgente dell'IP coerente con proxy/CDN.
	 *
	 * @return array
	 */
	private static function ip_source() {
		$source = (string) Settings::get( 'ip_source', 'REMOTE_ADDR' );
		$cf     = '' !== Ip::from_server( 'HTTP_CF_CONNECTING_IP' );
		$xff    = '' !== Ip::from_server( 'HTTP_X_FORWARDED_FOR' );
		$status = 'ok';
		$msg    = __( 'La sorgente dell\'indirizzo IP dei visitatori è coerente con la configurazione del server.', 'grs-security' );
		if ( 'REMOTE_ADDR' === $source && $cf ) {
			$status = 'warning';
			$msg    = __( 'Il sito sembra dietro Cloudflare ma l\'IP viene letto da REMOTE_ADDR: tutti i visitatori risultano con l\'IP di Cloudflare e un blocco potrebbe colpire tutti.', 'grs-security' );
		} elseif ( 'REMOTE_ADDR' === $source && $xff ) {
			$status = 'warning';
			$msg    = __( 'La richiesta passa da un proxy (header X-Forwarded-For presente): verifica la sorgente IP nelle impostazioni.', 'grs-security' );
		} elseif ( 'REMOTE_ADDR' !== $source && '' === Ip::from_server( $source ) ) {
			$status = 'warning';
			$msg    = __( 'La sorgente IP impostata non è presente in questa richiesta: viene usato REMOTE_ADDR.', 'grs-security' );
		}
		return Scanner::result(
			array(
				'id'           => 'ip_source',
				'category'     => 'monitoring',
				'title'        => __( 'Rilevamento corretto dell\'IP', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $msg,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'In GRS DEVs > Security, scheda Impostazioni, scegli la sorgente IP corretta (Cloudflare, proxy o connessione diretta). Usa un header di proxy solo se il sito è davvero dietro quel proxy: altrimenti l\'IP si può falsificare.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ),
			)
		);
	}

	/**
	 * Firewall applicativo.
	 *
	 * @return array
	 */
	private static function firewall() {
		$applied = Settings::fix_enabled( 'firewall' );
		$mode    = Settings::get( 'firewall_mode', 'block' );
		return Scanner::result(
			array(
				'id'           => 'firewall',
				'category'     => 'monitoring',
				'title'        => __( 'Firewall applicativo', 'grs-security' ),
				'status'       => $applied ? ( 'block' === $mode ? 'ok' : 'warning' ) : 'warning',
				'weight'       => 2,
				'message'      => $applied
					? ( 'block' === $mode ? __( 'Il firewall blocca le richieste con schemi di attacco evidenti.', 'grs-security' ) : __( 'Il firewall è in modalità solo registrazione: le richieste sospette non vengono bloccate.', 'grs-security' ) )
					: __( 'Il firewall applicativo è spento.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Blocca richieste con SQL injection, iniezione di codice, directory traversal e scanner automatici noti. Gli utenti connessi con permessi di redazione sono esclusi. Non sostituisce il firewall dell\'hosting o di Cloudflare, che fermano gli attacchi prima che arrivino a WordPress.', 'grs-security' ),
			)
		);
	}

	/**
	 * Scansione di integrità attiva.
	 *
	 * @return array
	 */
	private static function integrity_enabled() {
		$applied = Settings::fix_enabled( 'integrity' );
		return Scanner::result(
			array(
				'id'           => 'integrity',
				'category'     => 'monitoring',
				'title'        => __( 'Controllo giornaliero dei file', 'grs-security' ),
				'status'       => $applied ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => $applied
					? __( 'Ogni giorno i file di WordPress e dei plugin di wordpress.org vengono confrontati con gli originali.', 'grs-security' )
					: __( 'Nessun controllo automatico dei file: una modifica malevola potrebbe passare inosservata per mesi.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $applied,
				'recommended'  => ! $applied,
				'instructions' => __( 'Confronta ogni giorno core e plugin con i checksum ufficiali di wordpress.org, cerca file PHP in uploads e file estranei nella cartella principale, e ti avvisa via email delle novità.', 'grs-security' ),
			)
		);
	}

	/**
	 * Esito dell'ultima scansione di integrità.
	 *
	 * @return array
	 */
	private static function integrity_results() {
		$stored = get_option( Integrity::RESULT_OPTION );
		if ( ! is_array( $stored ) || ! isset( $stored['issues'] ) ) {
			return Scanner::result(
				array(
					'id'       => 'integrity_results',
					'category' => 'monitoring',
					'title'    => __( 'File integri', 'grs-security' ),
					'status'   => 'unknown',
					'message'  => __( 'Il controllo dei file non è ancora stato eseguito.', 'grs-security' ),
					'link'     => Plugin::admin_url( 'integrity' ),
				)
			);
		}
		$count = count( $stored['issues'] );
		return Scanner::result(
			array(
				'id'           => 'integrity_results',
				'category'     => 'monitoring',
				'title'        => __( 'File integri', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'critical',
				'weight'       => 3,
				'message'      => 0 === $count
					/* translators: %s: data */
					? sprintf( __( 'Nessuna anomalia nell\'ultimo controllo (%s).', 'grs-security' ), wp_date( 'd/m/Y H:i', (int) $stored['time'] ) )
					/* translators: %d: numero */
					: sprintf( _n( '%d file anomalo trovato nell\'ultimo controllo.', '%d file anomali trovati nell\'ultimo controllo.', $count, 'grs-security' ), $count ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Apri la scheda Integrità file per vedere l\'elenco. File del core modificati: reinstalla WordPress da Bacheca > Aggiornamenti > Reinstalla. Plugin modificati: reinstallali dallo zip ufficiale. File PHP in uploads o sconosciuti: se non li riconosci, il sito potrebbe essere compromesso; fai valutare il caso prima di cancellarli.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'integrity' ),
			)
		);
	}

	/**
	 * URL di login personalizzato (opzionale).
	 *
	 * @return array
	 */
	private static function login_url() {
		$active = Login_Url::active();
		return Scanner::result(
			array(
				'id'           => 'login_url',
				'category'     => 'monitoring',
				'title'        => __( 'Indirizzo di login personalizzato', 'grs-security' ),
				'status'       => $active ? 'ok' : 'info',
				'weight'       => 1,
				'optional'     => true,
				'message'      => $active
					/* translators: %s: URL */
					? sprintf( __( 'La pagina di accesso è %s; wp-login.php e wp-admin rispondono "pagina non trovata" ai visitatori.', 'grs-security' ), Login_Url::login_url() )
					: __( 'Facoltativo: spostare la pagina di login riduce il traffico dei bot, ma non sostituisce password robuste e verifica in due passaggi.', 'grs-security' ),
				'fix'          => 'auto',
				'fix_applied'  => $active,
				'instructions' => __( 'Si attiva dalla scheda Impostazioni scegliendo l\'indirizzo. Riceverai il nuovo indirizzo via email: salvalo, perché wp-login.php non funzionerà più. In emergenza si disattiva con define( \'GRS_SECURITY_DISABLE_LOGIN_URL\', true ); in wp-config.php.', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ) . '#grs-login-url',
			)
		);
	}

	/**
	 * Avvisi email.
	 *
	 * @return array
	 */
	private static function alerts() {
		$on = (bool) Settings::get( 'alerts_enabled', true );
		return Scanner::result(
			array(
				'id'           => 'alerts',
				'category'     => 'monitoring',
				'title'        => __( 'Avvisi email attivi', 'grs-security' ),
				'status'       => $on ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => $on
					/* translators: %s: email */
					? sprintf( __( 'Gli eventi importanti vengono segnalati a %s.', 'grs-security' ), Settings::alert_email() )
					: __( 'Gli avvisi email sono disattivati: eventi come la creazione di un nuovo amministratore passerebbero inosservati.', 'grs-security' ),
				'fix'          => $on ? 'none' : 'manual',
				'instructions' => __( 'Attiva gli avvisi in GRS DEVs > Security, scheda Impostazioni, e verifica che il sito invii email correttamente (consigliato un plugin SMTP come GRS SMTP).', 'grs-security' ),
				'link'         => Plugin::admin_url( 'settings' ),
			)
		);
	}
}
