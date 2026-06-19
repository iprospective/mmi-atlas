/*
 * zabbix-webhook.js — media type « webhook » Zabbix → endpoint /ingest d'Atlas (RM1813).
 *
 * À coller dans Zabbix : Alertes → Types de média → Créer → type « Webhook ».
 * Ce media type vit EN PARALLÈLE du Telegram existant (qui reste le canal humain) :
 * ici on alimente le chemin AUTONOME d'Atlas avec un JSON structuré et SIGNÉ.
 *
 * Paramètres du media type (onglet « Paramètres ») — clés = valeurs :
 *   URL        http://atlas.vrack:8088/ingest      (IP/much vrack du conteneur atlas)
 *   Secret     {$ATLAS_INGEST_SECRET}              (macro globale = même secret que ingest.env)
 *   Host       {HOST.HOST}
 *   Trigger    {TRIGGER.NAME}
 *   Severity   {EVENT.SEVERITY}
 *   State      {EVENT.VALUE}                        (1=PROBLEM, 0=OK)
 *   EventId    {EVENT.ID}
 *   Item       {ITEM.KEY1}
 *   Value      {ITEM.VALUE1}
 *
 * Côté Action : « Operations » → envoyer au media type Atlas ; « Recovery operations »
 * aussi (pour livrer le OK qui referme l'épisode — anti-flap du moteur). Commencer
 * en restreignant l'Action aux sévérités hautes (High/Disaster).
 *
 * Sécurité : corps signé en HMAC-SHA256 (header X-Atlas-Signature) ; l'endpoint
 * rejette tout payload non signé. Le secret ne transite jamais en clair (macro).
 */
var Atlas = {
    params: null,

    sendEvent: function () {
        var body = JSON.stringify({
            host: Atlas.params.Host,
            trigger: Atlas.params.Trigger,
            severity: Atlas.params.Severity,
            // {EVENT.VALUE} : '1' = PROBLEM, '0' = OK
            state: (Atlas.params.State === '0') ? 'OK' : 'PROBLEM',
            event_id: Atlas.params.EventId,
            item: Atlas.params.Item,
            value: Atlas.params.Value
        });

        // Signature HMAC-SHA256 du corps brut (fonction hmac() native Zabbix ≥ 6.4).
        var sig = 'sha256=' + hmac('sha256', Atlas.params.Secret, body);

        var req = new HttpRequest();
        req.addHeader('Content-Type: application/json');
        req.addHeader('X-Atlas-Signature: ' + sig);
        req.setProxy(Atlas.params.HTTPProxy || '');

        var resp = req.post(Atlas.params.URL, body);
        var status = req.getStatus();
        Zabbix.log(4, '[atlas] POST /ingest status=' + status + ' resp=' + resp);

        if (status < 200 || status >= 300) {
            throw 'Atlas /ingest a répondu ' + status + ' : ' + resp;
        }
        return resp;
    }
};

try {
    Atlas.params = JSON.parse(value);

    if (!Atlas.params.URL || !Atlas.params.Secret) {
        throw 'URL et Secret sont requis dans les paramètres du media type.';
    }
    if (!Atlas.params.Host || !Atlas.params.Trigger) {
        throw 'Host et Trigger sont requis (macros {HOST.HOST} / {TRIGGER.NAME}).';
    }

    return Atlas.sendEvent();
}
catch (error) {
    Zabbix.log(3, '[atlas] échec webhook : ' + error);
    throw 'Envoi à Atlas /ingest échoué : ' + error;
}
