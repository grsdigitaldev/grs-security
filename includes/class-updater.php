<?php
/**
 * Aggiornamenti automatici da release GitHub (Plugin Update Checker 5.7, MIT).
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Collega Plugin Update Checker al repository del plugin.
 */
class Updater {

	/**
	 * Repository pubblico ufficiale (account GitHub grsdigitaldev, vedi dev/distribuzione-github.md).
	 * Sovrascrivibile con la costante GRS_SECURITY_UPDATE_REPO o il filtro grs_security_update_repository;
	 * una stringa vuota spegne gli aggiornamenti.
	 */
	const DEFAULT_REPO = 'https://github.com/grsdigitaldev/grs-security/';

	/**
	 * Istanza di Plugin Update Checker (null se gli aggiornamenti sono spenti).
	 *
	 * @var object|null
	 */
	private static $checker = null;

	/**
	 * Istanza di Plugin Update Checker, per diagnostica e test.
	 *
	 * @return object|null
	 */
	public static function checker() {
		return self::$checker;
	}

	/**
	 * Tiene solo la strategia "ultima release pubblicata".
	 *
	 * @param array $strategies Strategie di rilevamento di PUC.
	 * @return array
	 */
	public static function only_latest_release( $strategies ) {
		return ( is_array( $strategies ) && isset( $strategies['latest_release'] ) ) ? array( 'latest_release' => $strategies['latest_release'] ) : array();
	}

	/**
	 * Registra il controllo aggiornamenti (solo bacheca, cron e WP-CLI).
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! is_admin() && ! wp_doing_cron() && ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$repo = defined( 'GRS_SECURITY_UPDATE_REPO' ) ? (string) GRS_SECURITY_UPDATE_REPO : self::DEFAULT_REPO;
		/**
		 * Repository GitHub da cui scaricare gli aggiornamenti.
		 *
		 * @param string $repo URL del repository.
		 */
		$repo = (string) apply_filters( 'grs_security_update_repository', $repo );
		if ( '' === $repo ) {
			return;
		}
		$loader = GRS_SECURITY_PATH . 'lib/plugin-update-checker/plugin-update-checker.php';
		if ( ! is_readable( $loader ) ) {
			return;
		}
		require_once $loader;
		if ( ! class_exists( '\YahnisElsts\PluginUpdateChecker\v5\PucFactory' ) ) {
			return;
		}
		$checker = \YahnisElsts\PluginUpdateChecker\v5\PucFactory::buildUpdateChecker( $repo, GRS_SECURITY_FILE, 'grs-security' );
		$api     = method_exists( $checker, 'getVcsApi' ) ? $checker->getVcsApi() : null;
		$require = $api ? get_class( $api ) . '::REQUIRE_RELEASE_ASSETS' : '';
		if ( ! $api || ! method_exists( $api, 'enableReleaseAssets' ) || ! defined( $require ) ) {
			// Libreria inattesa: meglio nessun aggiornamento che il sorgente del repository.
			add_filter( $checker->getUniqueName( 'vcs_update_detection_strategies' ), '__return_empty_array' );
			return;
		}
		// Solo lo zip allegato con il nome atteso; senza allegato nessun aggiornamento (mai il sorgente del repository).
		$api->enableReleaseAssets( '/^grs-security-[0-9]+\.[0-9]+\.[0-9]+\.zip$/i', constant( $require ) );
		// Solo release pubblicate: altrimenti PUC ripiega su tag e branch main.
		add_filter(
			$checker->getUniqueName( 'vcs_update_detection_strategies' ),
			array( __CLASS__, 'only_latest_release' )
		);
		if ( defined( 'GRS_SECURITY_GITHUB_TOKEN' ) && GRS_SECURITY_GITHUB_TOKEN && method_exists( $checker, 'setAuthentication' ) ) {
			$checker->setAuthentication( (string) GRS_SECURITY_GITHUB_TOKEN );
		}
		self::$checker = $checker;
	}
}
