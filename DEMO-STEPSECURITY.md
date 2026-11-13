# Dimostrazione di StepSecurity Harden-Runner

Questa PR permette di osservare due modalità di Harden-Runner sui runner
GitHub-hosted. I workflow esistono già: la PR verso `main` li avvia senza
modificarli. Usano richieste HTTPS innocue, senza eseguire il codice della PR
o usare secret.

## Dove guardare

Apri **Checks** nella PR e seleziona i due job:

- **Community audit on GitHub-hosted Ubuntu**, nel workflow
  **Harden-Runner Community audit**.
- **Community block on GitHub-hosted Ubuntu**, nel workflow
  **Harden-Runner Community block**.

Apri i dettagli dei job e confronta le run dello stesso commit. Il nome
«Community» è un'etichetta del workflow: per conoscere l'agente e il tier
effettivi, controlla i log di configurazione di ciascuna run.

## Audit: osservare il traffico

Nel passo **Generate harmless HTTPS traffic**, cerca le risposte HTTP di
`example.com` e `api.github.com/zen`. Dopo il completamento del job, apri il
link **View security insights and recommended policy** prodotto da
Harden-Runner. Negli insights verifica repository, run e job, poi cerca gli
eventi di rete verso `example.com:443` e `api.github.com:443` attribuiti a
quel passo. L'accesso può richiedere l'autenticazione.

Il job verde e le risposte HTTP non dimostrano da soli che il monitoraggio
abbia registrato gli eventi. In modalità audit resta inoltre attiva la
Global Block List di StepSecurity.

## Block: confrontare consentito e bloccato

Nel passo **Verify allowed HTTPS traffic**, verifica che
`api.github.com/zen` risponda: è il controllo positivo per l'indirizzo
consentito dall'allowlist. Nel passo **Verify disallowed HTTPS traffic fails**,
verifica il fallimento della richiesta a `example.com`, fuori dall'allowlist.

Un errore di `curl` può dipendere anche dalla rete. Dopo il passo
**Post Harden Runner**, cerca nei log dell'agente un evento esplicito di blocco
per `example.com`, per esempio `dns-request-dropped` con il dominio e
`matchedPolicy=NONE`. Confrontalo con la richiesta riuscita allo stesso
dominio nella run audit e con il controllo positivo della run block. Se manca
l'evento, il blocco non è verificato.

Il workflow block imposta `disable-telemetry: true`: controlla nei log la
configurazione effettiva e il messaggio sulla telemetria disabilitata. Non
aspettarti eventi di rete nel portale per questa run; la configurazione non
garantisce però l'assenza di traffico verso StepSecurity durante setup e
operazioni di controllo.
