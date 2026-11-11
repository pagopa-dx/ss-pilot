# Benchmark StepSecurity Harden-Runner

**Stato:** raccolta e analisi del protocollo eseguito concluse; valutazione
preliminare, non approvazione al rollout.

**Periodo:** 5–10 novembre 2026

**Ambito:** repository pubblico
[`pagopa-dx/ss-pilot`](https://github.com/pagopa-dx/ss-pilot), runner
GitHub-hosted Ubuntu. Non sono stati modificati `pagopa/dx` o Azure.

## Sintesi

Harden-Runner ha mostrato monitoraggio effettivo e blocco di traffico nei casi
provati, anche durante una build Node/TypeScript con tooling DX. Il pilot
iniziale ha usato l'agente **Community v0.16.2**; la build rappresentativa e il
benchmark successivo hanno invece selezionato **AgentAlpha v1.9.0 Enterprise**.
Per decisione del team, Enterprise è il target accettato del benchmark: i suoi
risultati non dimostrano un comportamento identico del tier Community.

Il limite più importante riguarda l'intento di una allowlist per **hostname
esatto**: dopo una richiesta consentita, una richiesta con IP fissato a un
sottodominio escluso sullo stesso IP CDN è riuscita **3 volte su 3**. Questo è
un gap rispetto all'intento testato, non una dimostrazione di vulnerabilità
generale. Sono inoltre aperti la gestione di indirizzi pre-risolti, il
comportamento in caso di perdita dell'agente e la governance della telemetria.

**Indicazione:** non procedere a un rollout generalizzato sulla base di questo
benchmark. I risultati sono sufficienti per una valutazione Security mirata,
non per certificare isolamento completo, prestazioni o affidabilità
organizzative. Nessun test su `pagopa/dx` è autorizzato senza approvazione
Security.

## Ambiente e metodo

- Action [`step-security/harden-runner` v2.21.0](https://github.com/step-security/harden-runner/tree/05e31511f85b41b11d1cf0ef85d0992719546e2c),
  pinnata al commit `05e31511f85b41b11d1cf0ef85d0992719546e2c`.
- Runner GitHub-hosted `ubuntu-24.04`; non è stato scelto o cambiato
  l'hardware. Le misure hanno incontrato diversi modelli di CPU.
- Workflow separati e controllo senza guard; nei casi block, controlli
  positivi e negativi, con eventi nativi correlati. Una richiesta fallita o un
  job verde, da soli, non dimostrano il blocco.
- Fixture Node/TypeScript con pnpm, lint DX, typecheck, dieci test Vitest,
  build e smoke test. Un hook di dipendenza locale approvato effettua una
  richiesta innocua fuori allowlist, senza inviare dati applicativi o secret.
- La raccolta comprende il benchmark originale da 100 casi, una run separata
  di cancellazione e successivi contrasti mirati su rete, fault e telemetria.
  Questi campioni includono baseline e altri strumenti come controlli storici;
  non sono un punteggio di sicurezza StepSecurity.

## Risultati

| Area | Evidenza | Interpretazione |
| --- | --- | --- |
| Monitoraggio Community | Nella [run 42061220366](https://github.com/pagopa-dx/ss-pilot/actions/runs/42061220366) sono stati osservati nel [portale](https://app.stepsecurity.io/github/pagopa-dx/ss-pilot/actions/runs/42061220366?tab=network-events) due eventi `curl` consentiti, attribuiti allo step e al processo. Il log riporta agente v0.16.2. | Monitoraggio effettivo verificato per quella run. La baseline era ancora in apprendimento; anomaly detection non verificata. |
| Block e build Enterprise | Nella [run 42203434783](https://github.com/pagopa-dx/ss-pilot/actions/runs/42203434783) la build legittima è riuscita e l'hook verso il dominio escluso è stato bloccato, con evento DNS nativo correlato. La [ripetizione 42203877258](https://github.com/pagopa-dx/ss-pilot/actions/runs/42203877258) conferma il caso. | Protezione verificata per il percorso e la fixture testati, non per ogni dipendenza o workload. |
| Porta e IP esclusi | Nel [campione mirato 42800523074](https://github.com/pagopa-dx/ss-pilot/actions/runs/42800523074), porta esclusa, HTTPS escluso pre-risolto e HTTP diretto a IP escluso hanno ciascuno 9/9 deny correlati per PID, IP, porta e intervallo, con controllo senza guard. | L'iniziale risultato inconclusivo del parser è stato chiarito nel nuovo campione. |
| DNS alternativo | Il [contrasto UDP 42800681518](https://github.com/pagopa-dx/ss-pilot/actions/runs/42800681518) ha osservato deny nativi sia per `sendto` sia per socket UDP connesso verso la destinazione di test. | Copertura verificata per questi due percorsi, non per tutti i protocolli o bypass. |
| Indirizzo consentito pre-risolto | Nel [crossover 42801673072](https://github.com/pagopa-dx/ss-pilot/actions/runs/42801673072) lo stesso indirizzo fissato è stato negato prima di una richiesta DNS ordinaria al dominio consentito e permesso dopo. | Possibile incompatibilità con client che usano IP cached o pinned; non considerare un warm-up arbitrario una correzione di produzione. |
| Hostname escluso su IP condiviso | Dopo DNS ordinario per `example.org`, `curl --resolve` verso `www.example.org`, escluso e sullo stesso IP, ha raggiunto il server in tre run indipendenti: [42802597958](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802597958), [42802839149](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802839149), [42802846038](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802846038). | I precedenti deny DNS non garantiscono isolamento hostname quando il client usa un IP già appreso. Chiarire con il fornitore il confine supportato. |
| Timeout e cancellazione | Deadline e timeout del figlio sono stati esercitati nella [run full 42607755421](https://github.com/pagopa-dx/ss-pilot/actions/runs/42607755421); il post nativo è stato osservato nella [cancellazione dedicata 42607580878](https://github.com/pagopa-dx/ss-pilot/actions/runs/42607580878). | Esecuzione dei post osservata, non prova del ripristino di ogni impostazione o di fail-closed. |
| Guasto agente e input | La policy di test non valida è stata accettata; `SIGKILL` all'agente selezionato è stato rifiutato con `EPERM`. | Non sono stati indotti un vero fallimento di avvio o la perdita dell'agente. Il comportamento fail-open/fail-closed resta non verificato. |

Il campione completo ha raccolto **100 risultati** e verificato **161 passaggi
di build legittima** su tutte le configurazioni. La run full è conclusa
`cancelled`, non verde: un fault in un altro guard ha impedito al runner di
comunicare la conclusione; la chiusura server è stata forzata solo dopo la fine
di tutte le sequenze e dei post. Anche la run mirata da 45 casi è `cancelled`
per fault analoghi negli altri guard, dopo la conclusione delle sequenze. Questi
stati non devono essere attribuiti a un crash StepSecurity né nascosti.

## Prestazioni

Il protocollo ha raccolto dieci runner prestazionali per configurazione, con
installazione cold e reinstallazione offline da store warm. Nel sottocampione
comune AMD EPYC 9V74 le mediane della **somma delle sei fasi applicative**, in
secondi, sono:

| Configurazione | Campioni | Cold | Warm offline |
| --- | ---: | ---: | ---: |
| Baseline senza guard | 4 | 5,210 | 4,255 |
| StepSecurity audit | 5 | 5,560 | 4,550 |
| StepSecurity block | 3 | 5,940 | 4,370 |

Questi tempi escludono setup e post del guard e il probe dell'hook. La mediana
del setup StepSecurity nei 26 job funzionali/prestazionali era 4 s, con
intervallo 3–5 s e granularità dei timestamp GitHub al secondo. Campioni
piccoli, carico sintetico e variabilità dei runner non consentono una stima
generalizzabile dell'overhead, un p95 affidabile o una graduatoria.

## Telemetria, insights e check

Nel pilot minimo audit la telemetria era attiva. In block con
`disable-telemetry: true`, la [run 42193478133](https://github.com/pagopa-dx/ss-pilot/actions/runs/42193478133)
ha verificato enforcement locale e configurazione del flag, **non** l'assenza
di eventi nel portale: l'ispezione di quella run richiedeva login.

Nel campione Enterprise mirato, un runner per ciascuna combinazione audit/block
e flag false/true ha mostrato risoluzioni dei nomi StepSecurity in tutti e
quattro i casi. Con block + true è stato osservato
`agent.api.stepsecurity.io`; negli altri tre casi anche
`prod.app-api.stepsecurity.io`. Sono metadati DNS, non una misura del contenuto
TLS, degli upload o dell'ingest: **il flag non dimostra funzionamento offline**.
La [documentazione StepSecurity](https://docs.stepsecurity.io/github-actions/harden-runner)
sconsiglia di disabilitare la telemetria in Enterprise perché detection e
notifiche dipendono da essa.

Nella PR del pilot sono stati osservati check pubblicati da GitHub Actions, non
un check dedicato StepSecurity. I check dedicati sono documentati come
funzionalità Enterprise: disponibilità, configurazione e comportamento nel
nostro contesto restano da verificare. L'App base era stata installata
dall'utente; il pilot non ha modificato App o licenze.

## Community ed Enterprise

| Aspetto | Community | Enterprise e stato della prova |
| --- | --- | --- |
| Repository e runner | Pubblici su GitHub-hosted; 13.000 run/settimana documentate, oltre le quali le protezioni non si applicano. La pagina non specifica l'ambito di aggregazione. | Supporta anche privati e self-hosted; questi ambienti non sono stati provati. |
| Eventi e block | Correlazione di rete e allowlist documentate; monitoraggio Community verificato nel pilot minimo. La Global Block List è documentata anche in audit. | Il benchmark di build, rete e fault usa AgentAlpha Enterprise; non dimostra equivalenza con Community. |
| Check e funzionalità avanzate | I check GitHub dedicati non sono inclusi nella tabella Community upstream. | Check dedicati, maggiore visibilità di file/processi e HTTPS API GitHub sono documentati; non tutte queste funzionalità sono state provate. |
| Self-hosted | Non coperti, anche per repository pubblici. | Richiede Enterprise; senza sottoscrizione l'action può riuscire come no-op senza monitoraggio. Azure Container Apps resta non verificato. |

Fonti: [quickstart Community](https://docs.stepsecurity.io/workspace/getting-started/quickstart-community-tier)
e [tier e compatibilità upstream](https://github.com/step-security/harden-runner#features-and-pricing-tiers).
La selezione di AgentAlpha non chiarisce se l'assetto corrente sia trial o
licenza a pagamento.

## Questioni aperte prima di una decisione

1. **Confine della policy:** chiedere a StepSecurity quale isolamento sia
   previsto per hostname su IP condivisi e per indirizzi cached/pinned,
   includendo le run e i controlli sopra. Le domande sono preparate, non inviate.
2. **Affidabilità:** chiarire validazione di policy sconosciute e una procedura
   supportata per provare avvio fallito e perdita dell'agente senza presumere
   fail-closed.
3. **Dati e accessi:** valutare con Security telemetria effettiva, retention,
   accessi dell'App, condizioni Enterprise e perimetro dei repository.
4. **Integrazione:** verificare il posizionamento per ogni job e il
   comportamento del `pre` annidato, che in un test è partito anche quando lo
   step contenitore era saltato; un `if` sullo step non garantisce isolamento.
5. **Fuori prova:** IPv6 senza baseline funzionante, anomaly detection,
   Global Block List su indicatori reali, scala organizzativa, costi, export
   Azure e compatibilità di runner self-hosted su Container Apps.

Il protocollo e i confronti storici restano nella
[PR #3](https://github.com/pagopa-dx/ss-pilot/pull/3) e nel
[README](../README.md); questo documento concentra la decisione su
StepSecurity. I risultati del prototipo con un detector separato non sono
necessari per concludere questa discovery.
