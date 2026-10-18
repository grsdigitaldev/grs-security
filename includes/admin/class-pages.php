<?php
/**
 * Rendering delle pagine di amministrazione.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security\Admin;

use GRSDigital\Security\Htaccess;
use GRSDigital\Security\Integrity;
use GRSDigital\Security\Ip;
use GRSDigital\Security\Logger;
use GRSDigital\Security\Login_Guard;
use GRSDigital\Security\Login_Url;
use GRSDigital\Security\Plugin;
use GRSDigital\Security\Scanner;
use GRSDigital\Security\Settings;

defined( 'ABSPATH' ) || exit;

/**
 * Pagine: analisi, registro, integrità, impostazioni.
 */
class Pages {

	/**
	 * Etichette degli stati.
	 *
	 * @return array
	 */
	private static function status_labels() {
		return array(
			'ok'       => __( 'OK', 'grs-security' ),
			'warning'  => __( 'Needs improvement', 'grs-security' ),
			'critical' => __( 'Critical', 'grs-security' ),
			'info'     => __( 'Info', 'grs-security' ),
			'unknown'  => __( 'Cannot be verified', 'grs-security' ),
		);
	}

	/**
	 * Campo nascosto con azione e nonce.
	 *
	 * @param string $action Azione.
	 * @return void
	 */
	private static function form_fields( $action ) {
		echo '<input type="hidden" name="action" value="' . esc_attr( 'grs_security_' . $action ) . '" />';
		wp_nonce_field( 'grs_security_' . $action );
	}

	/**
	 * Schede della pagina (chiave => etichetta).
	 *
	 * @return array
	 */
	public static function tabs() {
		return array(
			''          => __( 'Analysis', 'grs-security' ),
			'log'       => __( 'Activity log', 'grs-security' ),
			'integrity' => __( 'File integrity', 'grs-security' ),
			'settings'  => __( 'Settings', 'grs-security' ),
		);
	}

	/**
	 * Scheda richiesta.
	 *
	 * @return string
	 */
	public static function current_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigazione tra schede.
		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : '';
		return array_key_exists( $tab, self::tabs() ) ? $tab : '';
	}

	/**
	 * Pagina unica del plugin: smista sulla scheda richiesta.
	 *
	 * @return void
	 */
	public static function router() {
		switch ( self::current_tab() ) {
			case 'log':
				self::log();
				break;
			case 'integrity':
				self::integrity();
				break;
			case 'settings':
				self::settings();
				break;
			default:
				self::dashboard();
		}
	}

	/**
	 * Intestazione comune con le schede.
	 *
	 * @param string $title Titolo della sezione.
	 * @return void
	 */
	private static function header( $title ) {
		$current = self::current_tab();
		echo '<div class="wrap grs-sec grs-ui">';
		$meta = '<span class="grs-ui-version">v' . esc_html( GRS_SECURITY_VERSION ) . '</span>';
		if ( class_exists( 'GRS_Devs_Menu', false ) && method_exists( 'GRS_Devs_Menu', 'render_header' ) ) {
			\GRS_Devs_Menu::render_header( 'GRS Security', __( 'Site analysis, fixes and protections.', 'grs-security' ), $meta );
		} else {
			// Componente GRS DEVs < 1.1.0 caricato da un altro plugin: intestazione semplice.
			echo '<h1>GRS Security</h1><hr class="wp-header-end">';
		}
		echo '<nav class="nav-tab-wrapper wp-clearfix" aria-label="' . esc_attr__( 'GRS Security sections', 'grs-security' ) . '">';
		foreach ( self::tabs() as $tab => $label ) {
			$class = 'nav-tab' . ( $tab === $current ? ' nav-tab-active' : '' );
			echo '<a href="' . esc_url( Plugin::admin_url( $tab ) ) . '" class="' . esc_attr( $class ) . '"' . ( $tab === $current ? ' aria-current="page"' : '' ) . '>' . esc_html( $label ) . '</a>';
		}
		echo '</nav>';
		echo '<h2 class="screen-reader-text">' . esc_html( $title ) . '</h2>';
		Admin::render_notices();
	}

	/**
	 * Piede comune (chiude anche il contenitore aperto da header()).
	 *
	 * @return void
	 */
	private static function footer() {
		if ( class_exists( 'GRS_Devs_Menu', false ) && method_exists( 'GRS_Devs_Menu', 'render_footer' ) ) {
			\GRS_Devs_Menu::render_footer();
		}
		echo '</div>';
	}

	/**
	 * Pagina "Analisi".
	 *
	 * @return void
	 */
	public static function dashboard() {
		if ( ! current_user_can( Admin::CAP ) ) {
			return;
		}
		$scan = Scanner::last();
		// Risultati salvati con testi in un'altra lingua (altro amministratore o cron): analisi rifatta nella lingua di chi guarda.
		$locale_changed = is_array( $scan ) && isset( $scan['locale'] ) && get_user_locale() !== $scan['locale'];
		if ( ! $scan || ! empty( $scan['stale'] ) || $locale_changed ) {
			$scan = Scanner::run();
		}
		$dismissed = (array) Settings::get( 'dismissed_checks', array() );
		$labels    = self::status_labels();
		$wizard    = ! get_option( Admin::WIZARD );
		$score     = (int) $scan['score'];
		$level     = $score >= 85 ? 'good' : ( $score >= 60 ? 'fair' : 'poor' );
		$counts    = array(
			'critical' => 0,
			'warning'  => 0,
			'ok'       => 0,
		);
		foreach ( $scan['results'] as $id => $row ) {
			if ( isset( $counts[ $row['status'] ] ) && ! in_array( $id, $dismissed, true ) ) {
				++$counts[ $row['status'] ];
			}
		}
		$verdicts = array(
			'good' => __( 'The site is well protected.', 'grs-security' ),
			'fair' => __( 'A good base, with a few points to improve.', 'grs-security' ),
			'poor' => __( 'There are important actions to take.', 'grs-security' ),
		);

		self::header( __( 'GRS Security: analysis and fixes', 'grs-security' ) );
		?>
		<div class="grs-sec-summary">
			<div class="grs-sec-score grs-sec-score--<?php echo esc_attr( $level ); ?>" style="--grs-score: <?php echo esc_attr( (string) max( 0, min( 100, $score ) ) ); ?>" role="img" aria-label="<?php echo esc_attr( sprintf( /* translators: %d: score */ __( 'Security score: %d out of 100', 'grs-security' ), $score ) ); ?>">
				<span class="grs-sec-score__value"><?php echo esc_html( (string) $score ); ?></span>
				<span class="grs-sec-score__label"><?php esc_html_e( 'out of 100', 'grs-security' ); ?></span>
			</div>
			<div class="grs-sec-summary__text">
				<p class="grs-sec-summary__title"><?php echo esc_html( $verdicts[ $level ] ); ?></p>
				<ul class="grs-sec-counters">
					<?php if ( $counts['critical'] ) : ?>
						<li><span class="grs-sec-badge grs-sec-badge--critical">
						<?php
						/* translators: %d: number */
						echo esc_html( sprintf( _n( '%d critical', '%d critical', $counts['critical'], 'grs-security' ), $counts['critical'] ) );
						?>
						</span></li>
					<?php endif; ?>
					<?php if ( $counts['warning'] ) : ?>
						<li><span class="grs-sec-badge grs-sec-badge--warning">
						<?php
						/* translators: %d: number */
						echo esc_html( sprintf( _n( '%d to improve', '%d to improve', $counts['warning'], 'grs-security' ), $counts['warning'] ) );
						?>
						</span></li>
					<?php endif; ?>
					<li><span class="grs-sec-badge grs-sec-badge--ok">
					<?php
					/* translators: %d: number */
					echo esc_html( sprintf( _n( '%d OK', '%d OK', $counts['ok'], 'grs-security' ), $counts['ok'] ) );
					?>
					</span></li>
				</ul>
				<p class="grs-sec-muted">
					<?php
					/* translators: %s: date and time */
					echo esc_html( sprintf( __( 'Last analysis: %s.', 'grs-security' ), wp_date( Plugin::datetime_format(), (int) $scan['time'] ) ) );
					?>
				</p>
				<?php if ( empty( $scan['loopback'] ) ) : ?>
					<p class="grs-sec-muted"><?php esc_html_e( 'Some checks require a request from the site to itself, which the hosting did not allow: those checks are marked "cannot be verified".', 'grs-security' ); ?></p>
				<?php endif; ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php self::form_fields( 'scan' ); ?>
					<button type="submit" class="button"><?php esc_html_e( 'Analyze again', 'grs-security' ); ?></button>
				</form>
			</div>
		</div>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="grs-sec-bulk">
			<?php self::form_fields( 'fix_bulk' ); ?>
			<?php if ( $wizard ) : ?>
				<div class="grs-sec-wizard">
					<h2><?php esc_html_e( 'Welcome to GRS Security', 'grs-security' ); ?></h2>
					<p><?php esc_html_e( 'We analyzed the site. The fixes we can apply automatically are already selected below: review them and click "Apply selected fixes". Each one can be undone at any time, and deactivating the plugin restores the site as it was.', 'grs-security' ); ?></p>
					<p><?php esc_html_e( 'Items marked "Instructions" require manual action: open them to see what to do.', 'grs-security' ); ?></p>
				</div>
			<?php endif; ?>

			<div class="grs-sec-bulkbar">
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Apply selected fixes', 'grs-security' ); ?></button>
				<?php if ( $wizard ) : ?>
					<button type="submit" class="button-link" form="grs-sec-skip"><?php esc_html_e( 'Skip, I\'ll decide later', 'grs-security' ); ?></button>
				<?php endif; ?>
			</div>

			<?php
			foreach ( Scanner::categories() as $cat => $cat_label ) {
				$rows = array_filter(
					$scan['results'],
					function ( $row ) use ( $cat ) {
						return $row['category'] === $cat;
					}
				);
				if ( ! $rows ) {
					continue;
				}
				$issues = 0;
				foreach ( $rows as $id => $row ) {
					if ( in_array( $row['status'], array( 'warning', 'critical' ), true ) && ! in_array( $id, $dismissed, true ) ) {
						++$issues;
					}
				}
				echo '<section class="grs-ui-card grs-sec-cat"><div class="grs-sec-cat__head"><h2 class="grs-ui-card__title">' . esc_html( $cat_label ) . '</h2>';
				if ( $issues ) {
					/* translators: %d: number */
					echo '<span class="grs-sec-cat-count grs-sec-badge grs-sec-badge--warning">' . esc_html( sprintf( _n( '%d to fix', '%d to fix', $issues, 'grs-security' ), $issues ) ) . '</span>';
				} else {
					echo '<span class="grs-sec-cat-count grs-sec-badge grs-sec-badge--ok">' . esc_html__( 'All good', 'grs-security' ) . '</span>';
				}
				echo '</div><table class="widefat grs-sec-checks"><tbody>';
				foreach ( $rows as $id => $row ) {
					self::check_row( $id, $row, in_array( $id, $dismissed, true ), $labels );
				}
				echo '</tbody></table></section>';
			}
			?>
			<div class="grs-sec-bulkbar">
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Apply selected fixes', 'grs-security' ); ?></button>
			</div>
		</form>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="grs-sec-skip"><?php self::form_fields( 'wizard_skip' ); ?></form>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="grs-sec-single"><?php self::form_fields( 'fix' ); ?></form>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" id="grs-sec-dismiss"><?php self::form_fields( 'dismiss' ); ?></form>
		<?php
		self::footer();
	}

	/**
	 * Riga di un controllo.
	 *
	 * @param string $id        Id.
	 * @param array  $row       Risultato.
	 * @param bool   $dismissed Ignorato.
	 * @param array  $labels    Etichette stato.
	 * @return void
	 */
	private static function check_row( $id, $row, $dismissed, $labels ) {
		$status   = $dismissed ? 'info' : $row['status'];
		$failing  = in_array( $row['status'], array( 'warning', 'critical' ), true );
		$can_auto = 'auto' === $row['fix'] && ! $row['fix_applied'] && ( $failing || 'salts' === $id || ! empty( $row['optional'] ) );
		$checked  = $can_auto && ! empty( $row['recommended'] ) && ! $dismissed && 'salts' !== $id && 'login_url' !== $id;
		?>
		<tr class="grs-sec-check grs-sec-check--<?php echo esc_attr( $status ); ?><?php echo $dismissed ? ' grs-sec-check--dismissed' : ''; ?>">
			<td class="grs-sec-check__select">
				<?php if ( $can_auto && 'login_url' !== $id ) : ?>
					<input type="checkbox" name="checks[]" value="<?php echo esc_attr( $id ); ?>" id="grs-check-<?php echo esc_attr( $id ); ?>" <?php checked( $checked ); ?> <?php echo 'salts' === $id ? 'data-grs-confirm="salts"' : ''; ?> />
				<?php endif; ?>
			</td>
			<td class="grs-sec-check__status"><span class="grs-sec-badge grs-sec-badge--<?php echo esc_attr( $status ); ?>"><?php echo esc_html( $dismissed ? __( 'Ignored', 'grs-security' ) : $labels[ $row['status'] ] ); ?></span></td>
			<td class="grs-sec-check__body">
				<label for="grs-check-<?php echo esc_attr( $id ); ?>"><strong><?php echo esc_html( $row['title'] ); ?></strong></label>
				<?php if ( ! empty( $row['optional'] ) ) : ?>
					<span class="grs-sec-tag"><?php esc_html_e( 'optional', 'grs-security' ); ?></span>
				<?php endif; ?>
				<?php if ( $row['fix_applied'] ) : ?>
					<span class="grs-sec-tag grs-sec-tag--on"><?php esc_html_e( 'enabled by GRS Security', 'grs-security' ); ?></span>
				<?php endif; ?>
				<p><?php echo esc_html( $row['message'] ); ?></p>
				<?php if ( '' !== $row['instructions'] && ( $failing || $row['fix_applied'] || 'auto' === $row['fix'] ) ) : ?>
					<details>
						<summary><?php echo 'manual' === $row['fix'] ? esc_html__( 'Instructions', 'grs-security' ) : esc_html__( 'What the fix does', 'grs-security' ); ?></summary>
						<p class="grs-sec-pre"><?php echo esc_html( $row['instructions'] ); ?></p>
					</details>
				<?php endif; ?>
			</td>
			<td class="grs-sec-check__actions">
				<?php if ( $can_auto && 'login_url' !== $id ) : ?>
					<button type="submit" form="grs-sec-single" class="button button-small" name="fix" value="<?php echo esc_attr( 'apply|' . $id ); ?>" <?php echo 'salts' === $id ? 'data-grs-confirm="salts"' : ''; ?>><?php echo 'salts' === $id ? esc_html__( 'Regenerate', 'grs-security' ) : esc_html__( 'Fix', 'grs-security' ); ?></button>
				<?php elseif ( 'login_url' === $id && ! $row['fix_applied'] ) : ?>
					<a class="button button-small" href="<?php echo esc_url( $row['link'] ); ?>"><?php esc_html_e( 'Configure', 'grs-security' ); ?></a>
				<?php endif; ?>
				<?php if ( $row['fix_applied'] ) : ?>
					<button type="submit" form="grs-sec-single" class="button-link grs-sec-revert" name="fix" value="<?php echo esc_attr( 'revert|' . $id ); ?>" data-grs-confirm="revert"><?php esc_html_e( 'Undo', 'grs-security' ); ?></button>
				<?php endif; ?>
				<?php if ( 'manual' === $row['fix'] && '' !== $row['link'] ) : ?>
					<a class="button button-small" href="<?php echo esc_url( $row['link'] ); ?>"><?php esc_html_e( 'Open', 'grs-security' ); ?></a>
				<?php endif; ?>
				<?php if ( $failing || $dismissed ) : ?>
					<button type="submit" form="grs-sec-dismiss" class="button-link grs-sec-dismiss" name="dismiss" value="<?php echo esc_attr( ( $dismissed ? 'undo|' : 'add|' ) . $id ); ?>"><?php echo $dismissed ? esc_html__( 'Restore', 'grs-security' ) : esc_html__( 'Ignore', 'grs-security' ); ?></button>
				<?php endif; ?>
			</td>
		</tr>
		<?php
	}

	/**
	 * Pagina "Registro attività".
	 *
	 * @return void
	 */
	public static function log() {
		if ( ! current_user_can( Admin::CAP ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- filtri di sola lettura.
		$severity = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '';
		$event    = isset( $_GET['event'] ) ? sanitize_key( wp_unslash( $_GET['event'] ) ) : '';
		$paged    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:enable
		$per_page = 50;
		$data     = Logger::query(
			array(
				'severity' => $severity,
				'event'    => $event,
				'per_page' => $per_page,
				'page'     => $paged,
			)
		);
		$sev_lbl  = array(
			'info'     => __( 'Info', 'grs-security' ),
			'warning'  => __( 'Warning', 'grs-security' ),
			'critical' => __( 'Critical', 'grs-security' ),
		);

		self::header( __( 'Activity log', 'grs-security' ) );
		?>
		<form method="get" class="grs-sec-filters">
			<input type="hidden" name="page" value="grs-security" />
			<input type="hidden" name="tab" value="log" />
			<select name="severity">
				<option value=""><?php esc_html_e( 'All severities', 'grs-security' ); ?></option>
				<?php foreach ( $sev_lbl as $key => $label ) : ?>
					<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $severity, $key ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<select name="event">
				<option value=""><?php esc_html_e( 'All events', 'grs-security' ); ?></option>
				<?php foreach ( Logger::events() as $code ) : ?>
					<option value="<?php echo esc_attr( $code ); ?>" <?php selected( $event, $code ); ?>><?php echo esc_html( $code ); ?></option>
				<?php endforeach; ?>
			</select>
			<button class="button"><?php esc_html_e( 'Filter', 'grs-security' ); ?></button>
		</form>
		<table class="widefat striped grs-sec-log">
			<thead><tr>
				<th><?php esc_html_e( 'Date', 'grs-security' ); ?></th>
				<th><?php esc_html_e( 'Severity', 'grs-security' ); ?></th>
				<th><?php esc_html_e( 'Event', 'grs-security' ); ?></th>
				<th><?php esc_html_e( 'User', 'grs-security' ); ?></th>
				<th><?php esc_html_e( 'IP', 'grs-security' ); ?></th>
			</tr></thead>
			<tbody>
			<?php if ( empty( $data['rows'] ) ) : ?>
				<tr><td colspan="5"><?php esc_html_e( 'No events logged.', 'grs-security' ); ?></td></tr>
			<?php endif; ?>
			<?php foreach ( $data['rows'] as $row ) : ?>
				<?php $sev = isset( $sev_lbl[ $row['severity'] ] ) ? $row['severity'] : 'info'; ?>
				<tr>
					<td><?php echo esc_html( wp_date( Plugin::datetime_format(), strtotime( $row['created_at'] . ' UTC' ) ) ); ?></td>
					<td><span class="grs-sec-badge grs-sec-badge--<?php echo esc_attr( 'info' === $sev ? 'info' : $sev ); ?>"><?php echo esc_html( $sev_lbl[ $sev ] ); ?></span></td>
					<td><?php echo esc_html( $row['message'] ); ?><br /><code><?php echo esc_html( $row['event'] ); ?></code></td>
					<td><?php echo esc_html( $row['username'] ); ?></td>
					<td><?php echo esc_html( $row['ip'] ); ?></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<?php
		$pages = (int) ceil( $data['total'] / $per_page );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%' ),
						'format'  => '',
						'current' => $paged,
						'total'   => $pages,
					)
				)
			);
			echo '</div></div>';
		}
		/* translators: %d: days */
		echo '<p class="grs-sec-muted">' . esc_html( sprintf( __( 'Events are kept for %d days.', 'grs-security' ), (int) Settings::get( 'log_retention', 90 ) ) ) . '</p>';
		self::footer();
	}

	/**
	 * Pagina "Integrità file".
	 *
	 * @return void
	 */
	public static function integrity() {
		if ( ! current_user_can( Admin::CAP ) ) {
			return;
		}
		$stored   = get_option( Integrity::RESULT_OPTION );
		$progress = Integrity::progress();
		$labels   = array(
			'core-modified'   => __( 'Core file modified', 'grs-security' ),
			'core-missing'    => __( 'Core file missing', 'grs-security' ),
			'core-unknown'    => __( 'Unknown PHP file in wp-admin or wp-includes', 'grs-security' ),
			'plugin-modified' => __( 'Plugin file modified compared to wordpress.org', 'grs-security' ),
			'plugin-added'    => __( 'PHP file added to a plugin', 'grs-security' ),
			'uploads-php'     => __( 'PHP file in the uploads folder', 'grs-security' ),
			'root-unknown'    => __( 'Unknown PHP file in the root folder', 'grs-security' ),
		);

		self::header( __( 'File integrity', 'grs-security' ) );
		?>
		<p><?php esc_html_e( 'The check compares WordPress files and wordpress.org plugins with the official versions, looks for PHP files in uploads and unknown files in the root folder. Commercial or custom plugins have no public checksums and are marked "cannot be verified".', 'grs-security' ); ?></p>
		<?php if ( ! Settings::fix_enabled( 'integrity' ) ) : ?>
			<div class="notice notice-warning inline"><p><?php esc_html_e( 'The automatic daily check is off: enable it from the Analysis or Settings tab.', 'grs-security' ); ?></p></div>
		<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php self::form_fields( 'integrity_run' ); ?>
			<button type="submit" class="button button-primary" <?php disabled( null !== $progress ); ?>><?php esc_html_e( 'Check files now', 'grs-security' ); ?></button>
			<?php if ( $progress ) : ?>
				<span class="grs-sec-muted">
				<?php
				/* translators: 1: completed items, 2: total */
				echo esc_html( sprintf( __( 'Check in progress: %1$d of %2$d items.', 'grs-security' ), $progress['done'], $progress['total'] ) );
				?>
				</span>
			<?php endif; ?>
		</form>
		<?php
		if ( ! is_array( $stored ) || ! isset( $stored['results'] ) ) {
			echo '<p>' . esc_html__( 'No check run yet.', 'grs-security' ) . '</p>';
			self::footer();
			return;
		}
		/* translators: %s: date */
		echo '<h2>' . esc_html( sprintf( __( 'Last check: %s', 'grs-security' ), wp_date( Plugin::datetime_format(), (int) $stored['time'] ) ) ) . '</h2>';

		$core = $stored['results']['core'];
		if ( isset( $core['status'] ) && 'error' === $core['status'] ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $core['error'] ) . '</p></div>';
		}

		if ( empty( $stored['issues'] ) ) {
			echo '<p class="grs-sec-ok">' . esc_html__( 'No anomalies found.', 'grs-security' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Type', 'grs-security' ) . '</th><th>' . esc_html__( 'File', 'grs-security' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $stored['issues'] as $issue ) {
				list( $type, $path ) = array_map( 'trim', explode( ':', $issue, 2 ) );
				echo '<tr><td>' . esc_html( isset( $labels[ $type ] ) ? $labels[ $type ] : $type ) . '</td><td><code>' . esc_html( $path ) . '</code></td><td>';
				if ( 'core-missing' !== $type ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
					self::form_fields( 'integrity_ignore' );
					echo '<input type="hidden" name="issue" value="' . esc_attr( $issue ) . '" />';
					echo '<button type="submit" class="button-link">' . esc_html__( 'Ignore (known file)', 'grs-security' ) . '</button></form>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
			echo '<p>' . esc_html__( 'What to do: modified or missing core files are fixed with Dashboard > Updates > Reinstall. For plugins, reinstall the same version from the official zip. An unknown PHP file, especially in uploads, is often a sign of a compromise: back up before deleting it and, if you don\'t know what it is, have the case assessed.', 'grs-security' ) . '</p>';
		}

		$not_checked = array();
		foreach ( (array) $stored['results']['plugins'] as $plugin ) {
			if ( in_array( $plugin['status'], array( 'not_available', 'error' ), true ) ) {
				$not_checked[] = $plugin['name'];
			}
		}
		if ( $not_checked ) {
			echo '<p class="grs-sec-muted">' . esc_html__( 'Plugins that cannot be verified (not on wordpress.org or checksums not available):', 'grs-security' ) . ' ' . esc_html( implode( ', ', $not_checked ) ) . '</p>';
		}
		self::footer();
	}

	/**
	 * Pagina "Impostazioni".
	 *
	 * @return void
	 */
	public static function settings() {
		if ( ! current_user_can( Admin::CAP ) ) {
			return;
		}
		$s        = Settings::all();
		$labels   = Admin::fix_labels();
		$detected = Admin::detected_ips();
		$roles    = wp_roles()->get_names();

		self::header( __( 'GRS Security settings', 'grs-security' ) );
		?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="grs-sec-settings">
			<?php self::form_fields( 'settings' ); ?>

			<div class="grs-ui-card">
			<h2><?php esc_html_e( 'Protections', 'grs-security' ); ?></h2>
			<p class="grs-sec-muted"><?php esc_html_e( 'The same fixes offered in the Analysis tab. Unchecking a box removes the protection.', 'grs-security' ); ?></p>
			<?php if ( ! Htaccess::supported() ) : ?>
				<p class="grs-sec-muted"><?php esc_html_e( 'The server does not seem to use .htaccess files: the .htaccess items would have no effect.', 'grs-security' ); ?></p>
			<?php endif; ?>
			<fieldset class="grs-sec-fixes">
				<?php foreach ( $labels as $fix => $label ) : ?>
					<?php
					if ( 'login_url' === $fix ) {
						continue;
					}
					?>
					<label><input type="checkbox" name="grs[fixes][<?php echo esc_attr( $fix ); ?>]" value="1" <?php checked( ! empty( $s['fixes'][ $fix ] ) ); ?> /> <?php echo esc_html( $label ); ?></label><br />
				<?php endforeach; ?>
			</fieldset>

			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'XML-RPC mode', 'grs-security' ); ?></th>
					<td>
						<label><input type="radio" name="grs[xmlrpc_mode]" value="off" <?php checked( 'off', $s['xmlrpc_mode'] ); ?> /> <?php esc_html_e( 'Disable completely (recommended)', 'grs-security' ); ?></label><br />
						<label><input type="radio" name="grs[xmlrpc_mode]" value="pingback" <?php checked( 'pingback', $s['xmlrpc_mode'] ); ?> /> <?php esc_html_e( 'Block only pingbacks and multicall (for Jetpack or the WordPress app)', 'grs-security' ); ?></label>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Firewall mode', 'grs-security' ); ?></th>
					<td>
						<label><input type="radio" name="grs[firewall_mode]" value="block" <?php checked( 'block', $s['firewall_mode'] ); ?> /> <?php esc_html_e( 'Block suspicious requests', 'grs-security' ); ?></label><br />
						<label><input type="radio" name="grs[firewall_mode]" value="log" <?php checked( 'log', $s['firewall_mode'] ); ?> /> <?php esc_html_e( 'Log only (useful in the first days to rule out false positives)', 'grs-security' ); ?></label>
					</td>
				</tr>
			</table>
			</div>

			<div class="grs-ui-card">
			<h2><?php esc_html_e( 'Login', 'grs-security' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="grs-max"><?php esc_html_e( 'Attempts before blocking', 'grs-security' ); ?></label></th>
					<td><input type="number" min="3" max="20" id="grs-max" name="grs[login_max_attempts]" value="<?php echo esc_attr( (string) $s['login_max_attempts'] ); ?>" class="small-text" />
						<?php esc_html_e( 'within', 'grs-security' ); ?>
						<input type="number" min="5" max="120" name="grs[login_window]" value="<?php echo esc_attr( (string) $s['login_window'] ); ?>" class="small-text" /> <?php esc_html_e( 'minutes', 'grs-security' ); ?></td>
				</tr>
				<tr>
					<th scope="row"><label for="grs-lock"><?php esc_html_e( 'First block duration', 'grs-security' ); ?></label></th>
					<td><input type="number" min="5" max="1440" id="grs-lock" name="grs[login_lockout]" value="<?php echo esc_attr( (string) $s['login_lockout'] ); ?>" class="small-text" /> <?php esc_html_e( 'minutes (doubles with each new block within 24 hours, up to 24 hours)', 'grs-security' ); ?></td>
				</tr>
				<tr>
					<th scope="row"><label for="grs-ipsrc"><?php esc_html_e( 'IP source', 'grs-security' ); ?></label></th>
					<td>
						<select id="grs-ipsrc" name="grs[ip_source]">
							<?php foreach ( Ip::sources() as $key => $label ) : ?>
								<option value="<?php echo esc_attr( $key ); ?>" <?php selected( $s['ip_source'], $key ); ?>>
									<?php echo esc_html( $label . ( '' !== $detected[ $key ] ? ' (' . $detected[ $key ] . ')' : '' ) ); ?>
								</option>
							<?php endforeach; ?>
						</select>
						<p class="description"><?php esc_html_e( 'In brackets, the IP read in this request. Choose the source that shows your real IP. Use a proxy header only if the site really is behind that proxy.', 'grs-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="grs-wl"><?php esc_html_e( 'Trusted IPs', 'grs-security' ); ?></label></th>
					<td>
						<textarea id="grs-wl" name="grs[ip_whitelist]" rows="4" class="large-text code"><?php echo esc_textarea( $s['ip_whitelist'] ); ?></textarea>
						<p class="description">
							<?php
							/* translators: %s: IP */
							echo esc_html( sprintf( __( 'One IP or CIDR range per line: they are never blocked or filtered by the firewall. Your current IP is %s.', 'grs-security' ), Ip::current() ) );
							?>
						</p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Two-step verification', 'grs-security' ); ?></th>
					<td>
						<p><?php esc_html_e( 'Each user can enable it from their profile. Make it mandatory for these roles (with the "Mandatory two-step verification" protection enabled):', 'grs-security' ); ?></p>
						<?php foreach ( $roles as $role => $name ) : ?>
							<label><input type="checkbox" name="grs[twofa_roles][]" value="<?php echo esc_attr( $role ); ?>" <?php checked( in_array( $role, (array) $s['twofa_roles'], true ) ); ?> /> <?php echo esc_html( translate_user_role( $name ) ); ?></label><br />
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Emergency (lost phone and recovery codes used up): add define( \'GRS_SECURITY_DISABLE_2FA\', true ); to wp-config.php, log in and reset the verification from the profile, then remove the line.', 'grs-security' ); ?></p>
					</td>
				</tr>
				<tr id="grs-login-url">
					<th scope="row"><?php esc_html_e( 'Login page', 'grs-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="grs[fixes][login_url]" value="1" <?php checked( ! empty( $s['fixes']['login_url'] ) ); ?> /> <?php esc_html_e( 'Move the login page to this address:', 'grs-security' ); ?></label><br />
						<code><?php echo esc_html( trailingslashit( home_url() ) . ( '' === (string) get_option( 'permalink_structure' ) ? '?' : '' ) ); ?></code>
						<input type="text" name="grs[login_slug]" value="<?php echo esc_attr( $s['login_slug'] ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'e.g. private-access', 'grs-security' ); ?>" />
						<p class="description"><?php esc_html_e( 'Optional. Once enabled, wp-login.php and wp-admin answer "page not found" to visitors who are not logged in, and you receive the new address by email. Emergency: define( \'GRS_SECURITY_DISABLE_LOGIN_URL\', true ); in wp-config.php. Not available on multisite.', 'grs-security' ); ?></p>
						<?php if ( Login_Url::active() ) : ?>
							<p><strong><?php esc_html_e( 'Current address:', 'grs-security' ); ?></strong> <a href="<?php echo esc_url( Login_Url::login_url() ); ?>"><?php echo esc_html( Login_Url::login_url() ); ?></a></p>
						<?php endif; ?>
					</td>
				</tr>
			</table>
			</div>

			<div class="grs-ui-card">
			<h2><?php esc_html_e( 'Alerts and log', 'grs-security' ); ?></h2>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><?php esc_html_e( 'Email alerts', 'grs-security' ); ?></th>
					<td>
						<label><input type="checkbox" name="grs[alerts_enabled]" value="1" <?php checked( $s['alerts_enabled'] ); ?> /> <?php esc_html_e( 'Send an email for important events (new administrator, modified files, protections disabled...)', 'grs-security' ); ?></label><br />
						<input type="email" name="grs[alert_email]" value="<?php echo esc_attr( $s['alert_email'] ); ?>" class="regular-text" placeholder="<?php echo esc_attr( (string) get_option( 'admin_email' ) ); ?>" />
						<p class="description"><?php esc_html_e( 'Empty = site administration email.', 'grs-security' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="grs-ret"><?php esc_html_e( 'Log retention', 'grs-security' ); ?></label></th>
					<td><input type="number" min="7" max="365" id="grs-ret" name="grs[log_retention]" value="<?php echo esc_attr( (string) $s['log_retention'] ); ?>" class="small-text" /> <?php esc_html_e( 'days', 'grs-security' ); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Uninstall', 'grs-security' ); ?></th>
					<td><label><input type="checkbox" name="grs[keep_data]" value="1" <?php checked( $s['keep_data'] ); ?> /> <?php esc_html_e( 'Keep settings and log when the plugin is deleted', 'grs-security' ); ?></label></td>
				</tr>
			</table>
			</div>
			<?php submit_button( __( 'Save settings', 'grs-security' ) ); ?>
		</form>

		<div class="grs-ui-card">
		<h2><?php esc_html_e( 'Currently blocked IPs', 'grs-security' ); ?></h2>
		<?php
		$locked = Login_Guard::locked_list();
		if ( ! $locked ) {
			echo '<p>' . esc_html__( 'No blocked IPs.', 'grs-security' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><thead><tr><th>IP</th><th>' . esc_html__( 'Last username tried', 'grs-security' ) . '</th><th>' . esc_html__( 'Blocked until', 'grs-security' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $locked as $row ) {
				echo '<tr><td>' . esc_html( $row['ip'] ) . '</td><td>' . esc_html( $row['last_username'] ) . '</td><td>' . esc_html( wp_date( Plugin::datetime_format(), (int) $row['locked_until'] ) ) . '</td><td>';
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
				self::form_fields( 'unlock_ip' );
				echo '<input type="hidden" name="ip" value="' . esc_attr( $row['ip'] ) . '" /><button type="submit" class="button-link">' . esc_html__( 'Unblock', 'grs-security' ) . '</button></form></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
		self::footer();
	}
}
