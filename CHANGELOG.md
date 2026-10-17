# Changelog

Tutte le modifiche rilevanti a questo plugin. Formato [Keep a Changelog](https://keepachangelog.com/it/1.1.0/), versioni [SemVer](https://semver.org/lang/it/).

## [1.1.1] - 2026-10-17

### Modificato
- Aggiornamenti automatici attivati: `Updater::DEFAULT_REPO` punta al repository pubblico https://github.com/grsdigitaldev/grs-security/ e Plugin Update Checker scarica solo lo zip allegato alla release con il nome `grs-security-x.y.z.zip` (`enableReleaseAssets()` con `REQUIRE_RELEASE_ASSETS`): una release senza quell'allegato non viene offerta, mai il sorgente del repository.
- Considerate solo le release pubblicate (niente tag o branch `main`), come da standard `dev/distribuzione-github.md`.
- Header `Update URI` impostato a https://github.com/grsdigitaldev/grs-security (prima https://grsdigital.it/plugins/grs-security).

## [1.1.0] - 2026-10-17

### Aggiunto
- Azione `grs_security_salts_regenerated` lanciata dopo la rigenerazione verificata delle chiavi SALT, con l'array delle nuove chiavi: i plugin GRS che cifrano dati con chiavi derivate dai SALT (GRS SMTP 1.0.1+) li cifrano di nuovo nella stessa richiesta.
- Componente condiviso "GRS DEVs" 1.0.1 (`includes/grs-devs/`): registrazione nella Panoramica dei plugin GRS.

### Modificato
- Le quattro pagine (Analisi, Registro attività, Integrità file, Impostazioni) diventano schede di un'unica voce "Security" nel menu GRS DEVs; link nella riga del plugin rinominato "Impostazioni".
- I vecchi indirizzi `admin.php?page=grs-security-log|integrity|settings` reindirizzano alla scheda corrispondente.
- Messaggi di conferma della rigenerazione SALT con la nota sui plugin GRS compatibili.

## [1.0.0] - 2026-10-17

### Aggiunto
- Analisi della sicurezza con punteggio, procedura guidata dopo l'attivazione e correzioni applicabili con un clic (reversibili).
- Hardening via hook: editor file, XML-RPC (spento o solo pingback/multicall), enumerazione utenti, header di sicurezza, HSTS, errori di login generici, Application Passwords, versione WP nascosta, aggiornamenti minori del core.
- Regole .htaccess in blocco marcato (uploads senza PHP, file sensibili, Options -Indexes) con verifica del sito e annullamento automatico in caso di errore 5xx.
- Limite tentativi di login con blocco progressivo per IP, sorgente IP configurabile, IP fidati.
- Verifica in due passaggi TOTP con QR generato nel browser, codici di recupero, obbligo per ruolo, azzeramento da amministratore, costante di emergenza.
- Firewall applicativo con modalità blocco o solo registrazione.
- Indirizzo di login personalizzato con email del nuovo indirizzo e costante di emergenza.
- Rigenerazione delle chiavi SALT con controllo di sintassi e ripristino.
- Controllo integrità file a lotti via WP-Cron (core, plugin wordpress.org, uploads, root) con avviso delle nuove anomalie.
- Registro attività, avvisi email limitati nella frequenza, exporter/eraser privacy.
- Aggiornamenti da release GitHub tramite Plugin Update Checker 5.7.
