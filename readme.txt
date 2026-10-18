=== GRS Security ===
Contributors: grsdigital
Tags: sicurezza, security, login, 2fa, firewall
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.3.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Analizza la sicurezza del sito, applica con un clic le correzioni consigliate e protegge login, utenti e file.

== Description ==

GRS Security è un plugin di sicurezza semplice, pensato per i siti dei clienti GRS Digital.

Dopo l'attivazione analizza il sito, assegna un punteggio e propone le correzioni: quelle automatiche sono già selezionate e si applicano con un clic, quelle manuali hanno istruzioni passo passo. Ogni correzione è reversibile e, disattivando il plugin, il sito torna com'era.

**Analisi (circa 35 controlli)**

* aggiornamenti di WordPress, plugin e temi, plugin e temi inutilizzati, versione PHP supportata
* utente "admin", numero di amministratori, registrazione e ruolo predefinito, verifica in due passaggi
* editor di file, errori visibili, debug.log pubblico, chiavi SALT, permessi di wp-config.php, HTTPS, Application Passwords, aggiornamenti automatici, backup
* XML-RPC, elenco degli utenti, header di sicurezza, HSTS, PHP eseguibile in uploads (test reale), file sensibili e copie di backup, elenco dei file delle cartelle

**Protezioni**

* limite ai tentativi di accesso con blocco progressivo per IP (anche XML-RPC e Application Passwords), supporto Cloudflare e proxy, IP fidati
* verifica in due passaggi (TOTP) con codici di recupero, obbligatoria per i ruoli scelti
* firewall applicativo leggero (SQL injection, iniezione di codice, traversal, XSS evidenti, scanner noti), con modalità solo registrazione
* indirizzo di login personalizzato (facoltativo)
* rigenerazione delle chiavi SALT con controllo di sintassi
* regole .htaccess reversibili (Apache e LiteSpeed), con annullamento automatico se il sito risponde con errore
* controllo giornaliero dell'integrità dei file (checksum ufficiali di wordpress.org per core e plugin, PHP in uploads, file estranei nella root)
* registro attività e avvisi email per gli eventi importanti (nuovo amministratore, cambi di ruolo, opzioni sensibili, plugin installati, file modificati)

**Limiti**

* non è un antimalware e non ripulisce siti già compromessi
* il firewall gira dentro WordPress: non sostituisce il WAF dell'hosting o di Cloudflare
* i plugin commerciali o personalizzati non hanno checksum pubblici e non vengono verificati
* multisite non supportato

== Installation ==

1. Plugin > Aggiungi nuovo > Carica plugin, scegli grs-security-1.3.0.zip e attiva.
2. Si apre GRS DEVs > Security, scheda Analisi: controlla le correzioni selezionate e premi "Applica le correzioni selezionate".
3. Configura la verifica in due passaggi dal tuo profilo (Utenti > Profilo).
4. In GRS DEVs > Security, scheda Impostazioni, verifica la sorgente dell'IP (importante se il sito è dietro Cloudflare) e l'email degli avvisi.

Costanti facoltative in wp-config.php:

* `GRS_SECURITY_DISABLE_2FA` (true): disattiva la verifica in due passaggi in emergenza.
* `GRS_SECURITY_DISABLE_LOGIN_URL` (true): ripristina wp-login.php in emergenza.
* `GRS_SECURITY_DISABLE_FIREWALL` (true): spegne il firewall.
* `GRS_SECURITY_UPDATE_REPO`: repository GitHub alternativo per gli aggiornamenti (predefinito https://github.com/grsdigitaldev/grs-security; stringa vuota = aggiornamenti spenti).
* `GRS_SECURITY_GITHUB_TOKEN`: token in sola lettura, solo per un repository privato (non serve con quello ufficiale, che è pubblico).

== Frequently Asked Questions ==

= Ho perso il telefono con l'app di autenticazione =

Usa uno dei codici di recupero. Se non li hai, un altro amministratore può azzerare la verifica dal tuo profilo; in alternativa aggiungi define( 'GRS_SECURITY_DISABLE_2FA', true ); in wp-config.php, accedi, azzera la verifica dal profilo e rimuovi la riga.

= Non trovo più la pagina di login =

Controlla l'email inviata quando hai attivato l'indirizzo personalizzato. In emergenza aggiungi define( 'GRS_SECURITY_DISABLE_LOGIN_URL', true ); in wp-config.php.

= Mi sono bloccato da solo =

Aspetta la fine del blocco, oppure accedi da un'altra rete e sblocca il tuo IP in GRS DEVs > Security, scheda Impostazioni. Aggiungi il tuo IP agli IP fidati.

= Il sito è su Nginx =

Le regole .htaccess non hanno effetto: l'analisi mostra le regole equivalenti da far aggiungere all'hosting.

== Changelog ==

= 1.3.0 =
* Multilingua: testi del plugin in inglese con traduzione italiana inclusa (sui siti in italiano non cambia nulla); ogni amministratore vede il plugin nella lingua del proprio profilo.
* Pagina di login, verifica in due passaggi e messaggi di blocco nella lingua del visitatore (WPML, Polylang, Loco Translate).
* Email di avviso e del nuovo indirizzo di login nella lingua del destinatario.
* Pagina di blocco del firewall in italiano o inglese secondo la lingua del sito.
* Date nel formato impostato in Impostazioni > Generali.

= 1.2.0 =
* Grafica rinnovata con lo stile comune dei plugin GRS (componente GRS DEVs 1.1.0, lo stesso di GRS SMTP): intestazione con il marchio, schede a pillola, punteggio ad anello, contatori dei problemi, sezioni in riquadri arrotondati, pulsante principale giallo GRS, etichette di stato più chiare. Solo CSS, nessuna risorsa esterna.

= 1.1.1 =
* Aggiornamenti automatici attivi: il plugin controlla le release pubblicate su https://github.com/grsdigitaldev/grs-security e scarica lo zip allegato.
* Update URI dell'header impostato all'indirizzo del repository.

= 1.1.0 =
* Il plugin si trova nel menu unico GRS DEVs (voce Security) con le sezioni in schede; i vecchi indirizzi delle pagine reindirizzano alla nuova posizione.
* La rigenerazione delle chiavi SALT avvisa gli altri plugin GRS con l'azione grs_security_salts_regenerated (GRS SMTP 1.0.1+ aggiorna la password cifrata e le email continuano a partire).

= 1.0.0 =
* Prima release.

== Upgrade Notice ==

= 1.3.0 =
Plugin multilingua: nessuna modifica alle impostazioni.

= 1.2.0 =
Nuova grafica delle pagine con lo stile comune dei plugin GRS. Nessuna modifica a impostazioni o dati.

= 1.1.1 =
Da installare a mano una volta: da questa versione gli aggiornamenti arrivano in automatico dalle release GitHub.

= 1.1.0 =
Nuova posizione nel menu GRS DEVs e compatibilità con GRS SMTP nella rigenerazione delle chiavi SALT.

= 1.0.0 =
Prima release.
