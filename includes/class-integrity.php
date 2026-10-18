<?php
/**
 * Controllo di integrità dei file: core e plugin da wordpress.org con checksum ufficiali,
 * file PHP in uploads e file estranei nella root.
 *
 * @package GRSDigital\Security
 */

namespace GRSDigital\Security;

defined( 'ABSPATH' ) || exit;

/**
 * Scansione a lotti via WP-Cron.
 */
class Integrity {

	const JOB_OPTION    = 'grs_security_integrity_job';
	const RESULT_OPTION = 'grs_security_integrity';
	const IGNORE_OPTION = 'grs_security_integrity_ignore';
	const TIME_BUDGET   = 20;
	const MAX_FILES     = 60000;

	/**
	 * Estensioni considerate eseguibili.
	 */
	const PHP_EXT = '/\.(php[0-9]?|phtml|phar|pht|phps)$/i';

	/**
	 * Avvia una nuova scansione completa.
	 *
	 * @param bool $run_now Esegue subito il primo lotto.
	 * @return void
	 */
	public static function start( $run_now = false ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$queue = array( 'core', 'root', 'uploads' );
		foreach ( array_keys( get_plugins() ) as $file ) {
			$queue[] = 'plugin:' . $file;
		}
		update_option(
			self::JOB_OPTION,
			array(
				'queue'   => $queue,
				'total'   => count( $queue ),
				'started' => time(),
				'results' => array(
					'core'    => array(),
					'plugins' => array(),
					'uploads' => array(),
					'root'    => array(),
				),
			),
			false
		);
		wp_clear_scheduled_hook( Plugin::CRON_INTEGRITY );
		if ( $run_now ) {
			self::run_batch();
		} else {
			wp_schedule_single_event( time() + 5, Plugin::CRON_INTEGRITY );
		}
	}

	/**
	 * Scansione in corso?
	 *
	 * @return array|null Avanzamento [ done, total ].
	 */
	public static function progress() {
		$job = get_option( self::JOB_OPTION );
		if ( ! is_array( $job ) || empty( $job['queue'] ) ) {
			return null;
		}
		return array(
			'done'  => (int) $job['total'] - count( $job['queue'] ),
			'total' => (int) $job['total'],
		);
	}

	/**
	 * Elabora elementi della coda entro il tempo disponibile.
	 *
	 * @return void
	 */
	public static function run_batch() {
		$job = get_option( self::JOB_OPTION );
		if ( ! is_array( $job ) || ! isset( $job['queue'] ) ) {
			return;
		}
		$start = microtime( true );
		while ( ! empty( $job['queue'] ) && ( microtime( true ) - $start ) < self::TIME_BUDGET ) {
			$item = array_shift( $job['queue'] );
			if ( 'core' === $item ) {
				$job['results']['core'] = self::check_core();
			} elseif ( 'root' === $item ) {
				$job['results']['root'] = self::check_root();
			} elseif ( 'uploads' === $item ) {
				$job['results']['uploads'] = self::check_uploads();
			} elseif ( 0 === strpos( $item, 'plugin:' ) ) {
				$file                               = substr( $item, 7 );
				$job['results']['plugins'][ $file ] = self::check_plugin( $file );
			}
		}

		if ( ! empty( $job['queue'] ) ) {
			update_option( self::JOB_OPTION, $job, false );
			if ( ! wp_next_scheduled( Plugin::CRON_INTEGRITY ) ) {
				wp_schedule_single_event( time() + 30, Plugin::CRON_INTEGRITY );
			}
			return;
		}

		delete_option( self::JOB_OPTION );
		self::finalize( $job['results'] );
	}

	/**
	 * Salva il risultato e avvisa delle nuove anomalie.
	 *
	 * @param array $results Risultati.
	 * @return void
	 */
	private static function finalize( array $results ) {
		$previous = get_option( self::RESULT_OPTION, array() );
		$old      = isset( $previous['issues'] ) && is_array( $previous['issues'] ) ? $previous['issues'] : array();
		$issues   = self::issues( $results );

		update_option(
			self::RESULT_OPTION,
			array(
				'time'    => time(),
				'results' => $results,
				'issues'  => $issues,
			),
			false
		);

		$new = array_values( array_diff( $issues, $old ) );
		if ( $new ) {
			$list = implode( "\n", array_slice( $new, 0, 50 ) );
			Logger::log(
				'integrity_issues',
				'critical',
				/* translators: %d: number of anomalies */
				sprintf( _n( 'Integrity check: %d new file anomaly.', 'Integrity check: %d new file anomalies.', count( $new ), 'grs-security' ), count( $new ) ),
				array(
					'ip'      => '',
					'context' => array( 'files' => $list ),
				)
			);
		}
	}

	/**
	 * Elenco piatto delle anomalie (per confronto tra scansioni).
	 *
	 * @param array $results Risultati.
	 * @return string[]
	 */
	public static function issues( array $results ) {
		$ignore = self::ignore_list();
		$out    = array();
		$add    = function ( $label, $path, $abs ) use ( &$out, $ignore ) {
			if ( isset( $ignore[ $path ] ) && file_exists( $abs ) && md5_file( $abs ) === $ignore[ $path ] ) {
				return;
			}
			$out[] = $label . ': ' . $path;
		};

		$core = isset( $results['core'] ) ? $results['core'] : array();
		foreach ( array( 'modified', 'unknown' ) as $type ) {
			if ( ! empty( $core[ $type ] ) ) {
				foreach ( $core[ $type ] as $path ) {
					$add( 'core-' . $type, $path, ABSPATH . $path );
				}
			}
		}
		if ( ! empty( $core['missing'] ) ) {
			foreach ( $core['missing'] as $path ) {
				$out[] = 'core-missing: ' . $path;
			}
		}
		foreach ( ( isset( $results['plugins'] ) ? $results['plugins'] : array() ) as $file => $plugin ) {
			$dir = trailingslashit( WP_PLUGIN_DIR ) . dirname( $file ) . '/';
			foreach ( array( 'modified', 'added' ) as $type ) {
				if ( ! empty( $plugin[ $type ] ) ) {
					foreach ( $plugin[ $type ] as $path ) {
						$add( 'plugin-' . $type, dirname( $file ) . '/' . $path, $dir . $path );
					}
				}
			}
		}
		$uploads = wp_upload_dir( null, false );
		foreach ( ( isset( $results['uploads'] ) ? $results['uploads'] : array() ) as $path ) {
			$add( 'uploads-php', $path, trailingslashit( $uploads['basedir'] ) . $path );
		}
		foreach ( ( isset( $results['root'] ) ? $results['root'] : array() ) as $path ) {
			$add( 'root-unknown', $path, ABSPATH . $path );
		}
		return array_values( array_unique( $out ) );
	}

	/**
	 * File ignorati dall'utente (percorso => md5).
	 *
	 * @return array
	 */
	public static function ignore_list() {
		$list = get_option( self::IGNORE_OPTION, array() );
		return is_array( $list ) ? $list : array();
	}

	/**
	 * Aggiunge un file agli ignorati (solo finché non cambia).
	 *
	 * @param string $path Percorso relativo come mostrato nell'anomalia.
	 * @param string $abs  Percorso assoluto.
	 * @return void
	 */
	public static function ignore( $path, $abs ) {
		if ( ! file_exists( $abs ) ) {
			return;
		}
		$list          = self::ignore_list();
		$list[ $path ] = md5_file( $abs );
		update_option( self::IGNORE_OPTION, $list, false );

		$stored = get_option( self::RESULT_OPTION, array() );
		if ( is_array( $stored ) && isset( $stored['results'] ) ) {
			$stored['issues'] = self::issues( $stored['results'] );
			update_option( self::RESULT_OPTION, $stored, false );
		}
	}

	/**
	 * Richiesta JSON con timeout.
	 *
	 * @param string $url URL.
	 * @return array|int Dati decodificati oppure codice HTTP / 0 in caso di errore.
	 */
	private static function fetch_json( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout' => 15,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);
		if ( is_wp_error( $response ) ) {
			return 0;
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return $code;
		}
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return is_array( $data ) ? $data : 0;
	}

	/**
	 * Checksum ufficiali del core per la versione e lingua installate.
	 *
	 * @return array|null
	 */
	private static function core_checksums() {
		static $cache = false;
		if ( false !== $cache ) {
			return $cache;
		}
		$cache   = null;
		$version = get_bloginfo( 'version' );
		$locales = array_unique( array( get_locale(), 'en_US' ) );
		foreach ( $locales as $locale ) {
			$data = self::fetch_json(
				add_query_arg(
					array(
						'version' => $version,
						'locale'  => $locale,
					),
					'https://api.wordpress.org/core/checksums/1.0/'
				)
			);
			if ( is_array( $data ) && ! empty( $data['checksums'] ) && is_array( $data['checksums'] ) ) {
				$sums = $data['checksums'];
				if ( isset( $sums[ $version ] ) && is_array( $sums[ $version ] ) ) {
					$sums = $sums[ $version ];
				}
				$cache = $sums;
				return $sums;
			}
		}
		return null;
	}

	/**
	 * Confronta i file del core.
	 *
	 * @return array
	 */
	public static function check_core() {
		$sums = self::core_checksums();
		if ( null === $sums ) {
			return array(
				'status' => 'error',
				'error'  => __( 'Unable to download the official checksums from wordpress.org.', 'grs-security' ),
			);
		}
		$modified = array();
		$missing  = array();
		foreach ( $sums as $file => $md5 ) {
			if ( 0 === strpos( $file, 'wp-content/' ) ) {
				continue;
			}
			$root_doc = ( false === strpos( $file, '/' ) && ! preg_match( self::PHP_EXT, $file ) );
			$path     = ABSPATH . $file;
			if ( ! file_exists( $path ) ) {
				if ( ! $root_doc && 'wp-config-sample.php' !== $file ) {
					$missing[] = $file;
				}
				continue;
			}
			if ( ! $root_doc && md5_file( $path ) !== $md5 ) {
				$modified[] = $file;
			}
		}

		$unknown = array();
		foreach ( array( 'wp-admin', 'wp-includes' ) as $dir ) {
			foreach ( self::list_files( ABSPATH . $dir ) as $rel ) {
				$file = $dir . '/' . $rel;
				if ( ! isset( $sums[ $file ] ) && preg_match( self::PHP_EXT, $file ) ) {
					$unknown[] = $file;
				}
			}
		}

		return array(
			'status'   => ( $modified || $missing || $unknown ) ? 'issues' : 'ok',
			'version'  => get_bloginfo( 'version' ),
			'modified' => $modified,
			'missing'  => $missing,
			'unknown'  => $unknown,
		);
	}

	/**
	 * File PHP nella root che non appartengono al core.
	 *
	 * @return string[]
	 */
	public static function check_root() {
		$sums  = self::core_checksums();
		$known = array( 'wp-config.php' );
		$out   = array();
		$files = glob( ABSPATH . '*' );
		foreach ( is_array( $files ) ? $files : array() as $path ) {
			$name = basename( $path );
			if ( ! is_file( $path ) || ! preg_match( self::PHP_EXT, $name ) || in_array( $name, $known, true ) ) {
				continue;
			}
			if ( null === $sums || ! isset( $sums[ $name ] ) ) {
				// Senza checksum consideriamo noti i file standard del core.
				if ( null === $sums && 0 === strpos( $name, 'wp-' ) ) {
					continue;
				}
				if ( null === $sums && 'index.php' === $name ) {
					continue;
				}
				$out[] = $name;
			}
		}
		return $out;
	}

	/**
	 * File eseguibili dentro uploads (non dovrebbero esserci).
	 *
	 * @return string[]
	 */
	public static function check_uploads() {
		$uploads = wp_upload_dir( null, false );
		$base    = $uploads['basedir'];
		$out     = array();
		foreach ( self::list_files( $base ) as $rel ) {
			if ( ! preg_match( self::PHP_EXT, $rel ) ) {
				continue;
			}
			$abs = trailingslashit( $base ) . $rel;
			if ( 'index.php' === basename( $rel ) && self::is_silence_file( $abs ) ) {
				continue;
			}
			$out[] = $rel;
		}
		return $out;
	}

	/**
	 * File "Silence is golden" innocuo.
	 *
	 * @param string $abs Percorso.
	 * @return bool
	 */
	private static function is_silence_file( $abs ) {
		if ( filesize( $abs ) > 200 ) {
			return false;
		}
		$content = (string) file_get_contents( $abs ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- file locale.
		$code    = trim( preg_replace( '#/\*.*?\*/|//[^\n]*|\#[^\n]*#s', '', str_replace( array( '<?php', '?>' ), '', $content ) ) );
		return '' === $code;
	}

	/**
	 * Confronta un plugin con i checksum di wordpress.org.
	 *
	 * @param string $file File principale (cartella/file.php).
	 * @return array
	 */
	public static function check_plugin( $file ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		$data    = isset( $plugins[ $file ] ) ? $plugins[ $file ] : array();
		$name    = isset( $data['Name'] ) ? $data['Name'] : $file;
		$slug    = dirname( $file );
		$version = isset( $data['Version'] ) ? $data['Version'] : '';
		$result  = array(
			'name'     => $name,
			'version'  => $version,
			'status'   => 'not_available',
			'modified' => array(),
			'missing'  => array(),
			'added'    => array(),
		);

		$update_uri = isset( $data['UpdateURI'] ) ? (string) $data['UpdateURI'] : '';
		$wporg      = ( '' === $update_uri || false !== strpos( $update_uri, 'wordpress.org' ) || false !== strpos( $update_uri, 'w.org' ) );
		if ( '.' === $slug || '' === $version || ! $wporg ) {
			return $result;
		}

		$json = self::fetch_json( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json' );
		if ( ! is_array( $json ) ) {
			$result['status'] = 404 === $json ? 'not_available' : 'error';
			return $result;
		}
		if ( empty( $json['files'] ) || ! is_array( $json['files'] ) ) {
			return $result;
		}

		$dir = trailingslashit( WP_PLUGIN_DIR ) . $slug . '/';
		foreach ( $json['files'] as $rel => $sums ) {
			$abs = $dir . $rel;
			if ( ! file_exists( $abs ) ) {
				if ( preg_match( self::PHP_EXT, $rel ) ) {
					$result['missing'][] = $rel;
				}
				continue;
			}
			if ( ! preg_match( self::PHP_EXT, $rel ) && ! preg_match( '/\.js$/i', $rel ) ) {
				continue;
			}
			$expected = isset( $sums['md5'] ) ? (array) $sums['md5'] : array();
			if ( $expected && ! in_array( md5_file( $abs ), $expected, true ) ) {
				$result['modified'][] = $rel;
			}
		}
		foreach ( self::list_files( $dir ) as $rel ) {
			if ( preg_match( self::PHP_EXT, $rel ) && ! isset( $json['files'][ $rel ] ) ) {
				$result['added'][] = $rel;
			}
		}
		$result['status'] = ( $result['modified'] || $result['added'] ) ? 'issues' : 'ok';
		return $result;
	}

	/**
	 * Elenco ricorsivo dei file (percorsi relativi), con limite.
	 *
	 * @param string $dir Cartella.
	 * @return string[]
	 */
	public static function list_files( $dir ) {
		$dir = untrailingslashit( $dir );
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$out = array();
		try {
			$iterator = new \RecursiveIteratorIterator(
				new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ),
				\RecursiveIteratorIterator::LEAVES_ONLY,
				\RecursiveIteratorIterator::CATCH_GET_CHILD
			);
			foreach ( $iterator as $info ) {
				if ( count( $out ) >= self::MAX_FILES ) {
					break;
				}
				if ( $info->isFile() ) {
					$out[] = str_replace( '\\', '/', substr( $info->getPathname(), strlen( $dir ) + 1 ) );
				}
			}
		} catch ( \Exception $e ) {
			return $out;
		}
		return $out;
	}
}
