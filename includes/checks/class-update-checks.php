<?php
/**
 * Controlli su aggiornamenti, plugin e temi inutilizzati, versione PHP.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Checks;

use GRSDigital\Security\Scanner;

defined( 'ABSPATH' ) || exit;

/**
 * Categoria "Aggiornamenti".
 */
class Update_Checks {

	/**
	 * Fine del supporto di sicurezza dei rami PHP (fonte: php.net / endoflife.date, verificato 2026-10-17).
	 *
	 * @var array
	 */
	const PHP_EOL = array(
		'7.4' => '2022-11-28',
		'8.0' => '2023-11-26',
		'8.1' => '2025-12-31',
		'8.2' => '2026-12-31',
		'8.3' => '2027-12-31',
		'8.4' => '2028-12-31',
		'8.5' => '2029-12-31',
	);

	/**
	 * Esegue i controlli.
	 *
	 * @return array
	 */
	public static function run() {
		if ( ! function_exists( 'get_core_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		return array(
			self::core(),
			self::plugins(),
			self::themes(),
			self::inactive_plugins(),
			self::inactive_themes(),
			self::php(),
		);
	}

	/**
	 * Risultato "non verificabile" quando wordpress.org non risponde.
	 *
	 * @param string $id     Id.
	 * @param string $title  Titolo.
	 * @param int    $weight Peso.
	 * @return array
	 */
	private static function unknown( $id, $title, $weight ) {
		return Scanner::result(
			array(
				'id'           => $id,
				'category'     => 'updates',
				'title'        => $title,
				'status'       => 'unknown',
				'weight'       => $weight,
				'message'      => __( 'Unable to contact wordpress.org to check for updates. Check manually in Dashboard > Updates.', 'grs-security' ),
				'fix'          => 'manual',
				'instructions' => __( 'If the problem persists, the hosting may be blocking outgoing connections to wordpress.org: in that case automatic security updates do not work either. Report it to the hosting.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Aggiornamento del core.
	 *
	 * @return array
	 */
	private static function core() {
		$transient = get_site_transient( 'update_core' );
		if ( ! is_object( $transient ) || empty( $transient->updates ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_version_check();
			$transient = get_site_transient( 'update_core' );
		}
		if ( ! is_object( $transient ) || empty( $transient->updates ) ) {
			return self::unknown( 'core_update', __( 'WordPress up to date', 'grs-security' ), 3 );
		}
		$updates = get_core_updates();
		$latest  = '';
		if ( is_array( $updates ) ) {
			foreach ( $updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					$latest = $update->current;
					break;
				}
			}
		}
		$current = get_bloginfo( 'version' );
		if ( '' === $latest ) {
			return Scanner::result(
				array(
					'id'       => 'core_update',
					'category' => 'updates',
					'title'    => __( 'WordPress up to date', 'grs-security' ),
					'status'   => 'ok',
					'weight'   => 3,
					/* translators: %s: version */
					'message'  => sprintf( __( 'WordPress %s is the latest available version.', 'grs-security' ), $current ),
				)
			);
		}
		$major_behind = version_compare( implode( '.', array_slice( explode( '.', $latest ), 0, 2 ) ), implode( '.', array_slice( explode( '.', $current ), 0, 2 ) ), '>' );
		return Scanner::result(
			array(
				'id'           => 'core_update',
				'category'     => 'updates',
				'title'        => __( 'WordPress up to date', 'grs-security' ),
				'status'       => $major_behind ? 'warning' : 'critical',
				'weight'       => 3,
				/* translators: 1: installed version, 2: available version */
				'message'      => sprintf( __( 'Version %1$s installed, %2$s available.', 'grs-security' ), $current, $latest ),
				'fix'          => 'manual',
				'instructions' => __( 'Back up, then update from Dashboard > Updates. Minor updates almost always contain security fixes: do not postpone them.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Plugin da aggiornare.
	 *
	 * @return array
	 */
	private static function plugins() {
		$transient = get_site_transient( 'update_plugins' );
		if ( ! is_object( $transient ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_update_plugins();
			$transient = get_site_transient( 'update_plugins' );
		}
		if ( ! is_object( $transient ) || ! isset( $transient->no_update ) ) {
			return self::unknown( 'plugin_updates', __( 'Plugins up to date', 'grs-security' ), 3 );
		}
		$all   = get_plugins();
		$names = array();
		if ( is_object( $transient ) && ! empty( $transient->response ) ) {
			foreach ( array_keys( (array) $transient->response ) as $file ) {
				$names[] = isset( $all[ $file ]['Name'] ) ? $all[ $file ]['Name'] : $file;
			}
		}
		$count = count( $names );
		return Scanner::result(
			array(
				'id'           => 'plugin_updates',
				'category'     => 'updates',
				'title'        => __( 'Plugins up to date', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : ( $count > 3 ? 'critical' : 'warning' ),
				'weight'       => 3,
				'message'      => 0 === $count
					? __( 'All plugins are up to date.', 'grs-security' )
					/* translators: 1: number, 2: list */
					: sprintf( _n( '%1$d plugin to update: %2$s.', '%1$d plugins to update: %2$s.', $count, 'grs-security' ), $count, implode( ', ', $names ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Outdated plugins are the leading cause of hacked WordPress sites. Update them from Plugins > Installed Plugins and consider automatic updates for the reliable ones.', 'grs-security' ),
				'link'         => admin_url( 'plugins.php?plugin_status=upgrade' ),
			)
		);
	}

	/**
	 * Temi da aggiornare.
	 *
	 * @return array
	 */
	private static function themes() {
		$transient = get_site_transient( 'update_themes' );
		if ( ! is_object( $transient ) || ! isset( $transient->last_checked ) || ( time() - (int) $transient->last_checked ) > 12 * HOUR_IN_SECONDS ) {
			wp_update_themes();
			$transient = get_site_transient( 'update_themes' );
		}
		if ( ! is_object( $transient ) || ! isset( $transient->no_update ) ) {
			return self::unknown( 'theme_updates', __( 'Themes up to date', 'grs-security' ), 2 );
		}
		$count = ! empty( $transient->response ) ? count( (array) $transient->response ) : 0;
		return Scanner::result(
			array(
				'id'           => 'theme_updates',
				'category'     => 'updates',
				'title'        => __( 'Themes up to date', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 2,
				'message'      => 0 === $count
					? __( 'All themes are up to date.', 'grs-security' )
					/* translators: %d: number */
					: sprintf( _n( '%d theme to update.', '%d themes to update.', $count, 'grs-security' ), $count ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Update themes from Dashboard > Updates. If the theme was edited directly, move the changes to a child theme before updating.', 'grs-security' ),
				'link'         => admin_url( 'update-core.php' ),
			)
		);
	}

	/**
	 * Plugin installati ma disattivati.
	 *
	 * @return array
	 */
	private static function inactive_plugins() {
		$inactive = array();
		foreach ( get_plugins() as $file => $data ) {
			if ( ! is_plugin_active( $file ) ) {
				$inactive[] = $data['Name'];
			}
		}
		$count = count( $inactive );
		return Scanner::result(
			array(
				'id'           => 'inactive_plugins',
				'category'     => 'updates',
				'title'        => __( 'No unused plugins', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => 0 === $count
					? __( 'There are no inactive plugins.', 'grs-security' )
					/* translators: 1: number, 2: list */
					: sprintf( _n( '%1$d inactive plugin: %2$s.', '%1$d inactive plugins: %2$s.', $count, 'grs-security' ), $count, implode( ', ', array_slice( $inactive, 0, 10 ) ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'An inactive plugin does not run, but its files remain reachable and may contain vulnerabilities. If you don\'t need it, delete it.', 'grs-security' ),
				'link'         => admin_url( 'plugins.php?plugin_status=inactive' ),
			)
		);
	}

	/**
	 * Temi inutilizzati (oltre al tema attivo, al genitore e a un tema predefinito di riserva).
	 *
	 * @return array
	 */
	private static function inactive_themes() {
		$active = array( get_stylesheet(), get_template() );
		$extra  = array();
		$spare  = false;
		foreach ( wp_get_themes() as $slug => $theme ) {
			if ( in_array( $slug, $active, true ) ) {
				continue;
			}
			if ( ! $spare && 0 === strpos( $slug, 'twenty' ) ) {
				$spare = true; // Un tema predefinito di riserva è utile per la diagnostica.
				continue;
			}
			$extra[] = $theme->get( 'Name' );
		}
		$count = count( $extra );
		return Scanner::result(
			array(
				'id'           => 'inactive_themes',
				'category'     => 'updates',
				'title'        => __( 'No unused themes', 'grs-security' ),
				'status'       => 0 === $count ? 'ok' : 'warning',
				'weight'       => 1,
				'message'      => 0 === $count
					? __( 'Only the active theme and, if present, a default fallback theme are installed.', 'grs-security' )
					/* translators: 1: number, 2: list */
					: sprintf( _n( '%1$d unused theme: %2$s.', '%1$d unused themes: %2$s.', $count, 'grs-security' ), $count, implode( ', ', $extra ) ),
				'fix'          => 0 === $count ? 'none' : 'manual',
				'instructions' => __( 'Delete the themes you don\'t use from Appearance > Themes. Keep only the active theme, its parent theme and a recent default theme as a fallback.', 'grs-security' ),
				'link'         => admin_url( 'themes.php' ),
			)
		);
	}

	/**
	 * Versione PHP.
	 *
	 * @return array
	 */
	private static function php() {
		$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
		$eol    = isset( self::PHP_EOL[ $branch ] ) ? strtotime( self::PHP_EOL[ $branch ] . ' 23:59:59 UTC' ) : 0;
		$now    = time();
		if ( $eol && $eol < $now ) {
			$status = 'critical';
			/* translators: 1: version, 2: date */
			$message = sprintf( __( 'PHP %1$s no longer receives security updates since %2$s.', 'grs-security' ), PHP_VERSION, wp_date( \GRSDigital\Security\Plugin::date_format(), $eol ) );
		} elseif ( $eol && ( $eol - $now ) < 120 * DAY_IN_SECONDS ) {
			$status = 'warning';
			/* translators: 1: version, 2: date */
			$message = sprintf( __( 'PHP %1$s will stop receiving security updates on %2$s.', 'grs-security' ), PHP_VERSION, wp_date( \GRSDigital\Security\Plugin::date_format(), $eol ) );
		} else {
			$status = 'ok';
			/* translators: %s: version */
			$message = sprintf( __( 'PHP %s is supported.', 'grs-security' ), PHP_VERSION );
		}
		return Scanner::result(
			array(
				'id'           => 'php_version',
				'category'     => 'updates',
				'title'        => __( 'Supported PHP version', 'grs-security' ),
				'status'       => $status,
				'weight'       => 2,
				'message'      => $message,
				'fix'          => 'ok' === $status ? 'none' : 'manual',
				'instructions' => __( 'Change the PHP version from the hosting control panel, choosing a supported version (8.3 or later). Test on a staging site first: outdated plugins or themes may not be compatible.', 'grs-security' ),
			)
		);
	}
}
