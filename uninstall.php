<?php
/**
 * Disinstallazione: rimuove opzioni, tabelle, dati utente e regole .htaccess
 * (salvo l'opzione "conserva dati").
 *
 * @package GRSDigital\Security
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- pulizia delle tabelle del plugin.

/**
 * Rimuove le regole .htaccess del plugin da un file.
 *
 * @param string $file Percorso.
 * @return void
 */
function grs_security_uninstall_strip_htaccess( $file ) {
	if ( ! is_file( $file ) || ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- disinstallazione, WP_Filesystem non necessario.
		return;
	}
	$content = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
	$clean   = preg_replace( '/\n?# BEGIN GRS Security.*?# END GRS Security[^\n]*\n?/s', "\n", $content );
	$clean   = ltrim( (string) $clean, "\n" );
	if ( $clean === $content ) {
		return;
	}
	if ( '' === trim( $clean ) ) {
		wp_delete_file( $file );
		return;
	}
	file_put_contents( $file, $clean, LOCK_EX ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- ripristino del file senza il blocco del plugin.
}

if ( ! function_exists( 'get_home_path' ) ) {
	require_once ABSPATH . 'wp-admin/includes/file.php';
}

// Le regole .htaccess si tolgono sempre: senza il plugin non sarebbero più gestibili dalla bacheca.
grs_security_uninstall_strip_htaccess( trailingslashit( get_home_path() ) . '.htaccess' );
$grs_security_uploads = wp_upload_dir( null, false );
grs_security_uninstall_strip_htaccess( trailingslashit( $grs_security_uploads['basedir'] ) . '.htaccess' );

$grs_security_settings = get_option( 'grs_security_settings', array() );
if ( is_array( $grs_security_settings ) && ! empty( $grs_security_settings['keep_data'] ) ) {
	return;
}

global $wpdb;

$grs_security_options = array(
	'grs_security_settings',
	'grs_security_version',
	'grs_security_db_version',
	'grs_security_scan',
	'grs_security_integrity',
	'grs_security_integrity_job',
	'grs_security_integrity_ignore',
	'grs_security_htaccess_backup',
	'grs_security_wizard_done',
);
foreach ( $grs_security_options as $grs_security_option ) {
	delete_option( $grs_security_option );
}

$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}grs_security_log" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- rimozione tabella del plugin.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}grs_security_lockouts" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- rimozione tabella del plugin.

// Transient del plugin (avvisi, limitazioni email e firewall, codici temporanei).
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_grs\\_security\\_%' OR option_name LIKE '\\_transient\\_timeout\\_grs\\_security\\_%'" );

// Dati della verifica in due passaggi.
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'grs\\_security\\_2fa\\_%'" );

wp_clear_scheduled_hook( 'grs_security_daily' );
wp_clear_scheduled_hook( 'grs_security_integrity_run' );
