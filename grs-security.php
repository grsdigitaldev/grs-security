<?php
/**
 * Plugin Name:       GRS Security
 * Plugin URI:        https://grsdigital.it
 * Description:       Analizza la sicurezza del sito, applica con un clic le correzioni consigliate e protegge login, utenti e file.
 * Version:           1.1.1
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            GRS Digital
 * Author URI:        https://grsdigital.it
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       grs-security
 * Domain Path:       /languages
 * Update URI:        https://github.com/grsdigitaldev/grs-security
 *
 * @package GRSDigital\Security
 */

defined( 'ABSPATH' ) || exit;

define( 'GRS_SECURITY_VERSION', '1.1.1' );
define( 'GRS_SECURITY_FILE', __FILE__ );
define( 'GRS_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'GRS_SECURITY_URL', plugin_dir_url( __FILE__ ) );

// Guard versione PHP: questo file deve restare sintatticamente valido anche su PHP vecchi.
if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'GRS Security richiede PHP 7.4 o superiore.', 'grs-security' ) . '</p></div>';
		}
	);
	return;
}

require_once GRS_SECURITY_PATH . 'includes/autoload.php';

// Menu condiviso "GRS DEVs" dei plugin GRS Digital (si carica la copia più recente tra i plugin attivi).
require_once GRS_SECURITY_PATH . 'includes/grs-devs/loader.php';

register_activation_hook( __FILE__, array( 'GRSDigital\\Security\\Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'GRSDigital\\Security\\Deactivator', 'deactivate' ) );

// Il firewall applicativo parte il prima possibile, prima degli altri componenti.
add_action( 'plugins_loaded', array( 'GRSDigital\\Security\\Firewall', 'early_check' ), -9999 );
add_action( 'plugins_loaded', array( 'GRSDigital\\Security\\Plugin', 'instance' ) );
