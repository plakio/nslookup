<?php

require_once 'vendor/autoload.php';

use Badcow\DNS\Zone;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
use Badcow\DNS\Rdata\Factory;

// Clases de php-domain-parser
use Pdp\Rules;
use Pdp\Cache;
use Pdp\Manager;

/**
 * Para suprimir advertencias obsoletas de PHP (por si Badcow DNS lanza alguna)
 */
error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Formatea los TXT que excedan 500 caracteres dividiéndolos en varias líneas.
 */
function specialTxtFormatter(Badcow\DNS\Rdata\TXT $rdata, int $padding): string {
    if (strlen($rdata->getText()) <= 500) {
        return sprintf('"%s"', addcslashes($rdata->getText(), '"\\'));
    }

    $returnVal = "(\n";
    $chunks = str_split($rdata->getText(), 500);
    foreach ($chunks as $chunk) {
        $returnVal .= str_repeat(' ', $padding).
            sprintf('"%s"', addcslashes($chunk, '"\\')).
            "\n";
    }
    $returnVal .= str_repeat(' ', $padding) . ")";

    return $returnVal;
}

/**
 * Extrae el dominio "registrable" (eTLD+1) usando php-domain-parser,
 * para usarlo en el WHOIS (ej: "sub.dominio.com.pe" => "dominio.com.pe")
 */
function getBaseDomainUsingParser($fullDomain) {
    // Quitar protocolos y slashes en caso de que el usuario ponga "http://"
    $fullDomain = preg_replace('/^https?:\/\//i', '', $fullDomain);
    $fullDomain = explode('/', $fullDomain)[0];
    $fullDomain = trim($fullDomain);

    // Descargamos las reglas de la Public Suffix List (o usamos caché local)
    $manager = new Manager(
        new Cache(), // Usa caché en disco (/tmp) por defecto
        null         // Usa la PSL oficial si no hay una local
    );
    $rules = $manager->getRules();

    // Resolvemos el dominio y extraemos la parte registrable
    $domainObj = $rules->resolve($fullDomain);
    return $domainObj->getRegistrableDomain(); 
}

function run() {

    // Si no se pasa el parámetro "domain", salimos
    if (! isset($_REQUEST['domain'])) {
        return;
    }

    // Dominio (o subdominio) que ingresa el usuario
    $fullDomain = trim($_REQUEST['domain']);

    $errors = [];
    $ip_lookup = [];
    $dns_records = [];

    // Verificamos que estén instalados los bins
    $required_bins = ["whois", "dig", "host"];
    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Validaciones básicas del dominio
    if (! filter_var($fullDomain, FILTER_VALIDATE_DOMAIN)) {
        $errors[] = "Invalid domain.";
    }
    if (filter_var($fullDomain, FILTER_VALIDATE_DOMAIN) && strpos($fullDomain, '.') === false) {
        $errors[] = "Invalid domain.";
    }
    if (strlen($fullDomain) < 4) {
        $errors[] = "No domain name is that short.";
    }
    if (strlen($fullDomain) > 80) {
        $errors[] = "Too long.";
    }
    if (count($errors) > 0) {
        echo json_encode(["errors" => $errors]);
        die();
    }

    // 1) Obtenemos el dominio base usando php-domain-parser
    try {
        $whoisDomain = getBaseDomainUsingParser($fullDomain);
    } catch (\Exception $e) {
        // Si ocurre algún error, por seguridad tomamos el fullDomain:
        $whoisDomain = $fullDomain;
    }

    // 2) WHOIS sobre el dominio base
    $whoisCmd = "whois $whoisDomain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'";
    $whois = shell_exec($whoisCmd);
    $whois = empty($whois) ? "" : trim($whois);

    if (empty($whois)) {
        $errors[] = "Domain not found (whois).";
        echo json_encode(["errors" => $errors]);
        die();
    }

    // Parseamos la salida del WHOIS en un array ordenado
    $whois = explode("\n", $whois);
    foreach ($whois as $key => $record) {
        // Limitamos el explode a 2 partes para no romper valores con ":" dentro
        $split = explode(":", trim($record), 2);
        $name  = trim($split[0]);
        $value = trim($split[1] ?? "");
        if ($name == "Name Server" || $name == "Domain Name") {
            $value = strtolower($value);
        }
        $whois[$key] = [ "name" => $name, "value" => $value ];
    }
    // Eliminamos duplicados
    $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    $col_name  = array_column($whois, 'name');
    $col_value = array_column($whois, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);

    // 3) Creamos la zona DNS (se aplica al dominio o subdominio completo)
    $zone = new Zone($fullDomain . ".");
    $zone->setDefaultTtl(3600);

    // 4) IP lookup (sobre el dominio o subdominio completo)
    $ips = explode("\n", trim(shell_exec("dig $fullDomain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response = empty($response) ? "" : trim($response);
        $ip_lookup[$ip] = $response;
    }

    // 5) Búsqueda de registros DNS en el fullDomain
    //    Ajusta esta lista según tus necesidades
    $records_to_check = [
        [ "a"     => "" ],
        [ "a"     => "*" ],
        [ "a"     => "mail" ],
        [ "a"     => "remote" ],
        [ "a"     => "www" ],
        [ "cname" => "*" ],
        [ "cname" => "www" ],
        [ "cname" => "autodiscover" ],
        [ "cname" => "sip" ],
        [ "cname" => "lyncdiscover" ],
        [ "cname" => "enterpriseregistration" ],
        [ "cname" => "enterpriseenrollment" ],
        [ "cname" => "email.mg" ],
        [ "cname" => "msoid" ],
        [ "cname" => "_acme-challenge" ],
        [ "cname" => "k1._domainkey" ],
        [ "cname" => "k2._domainkey" ],
        [ "cname" => "k3._domainkey" ],
        [ "cname" => "s1._domainkey" ],
        [ "cname" => "s2._domainkey" ],
        [ "cname" => "selector1._domainkey" ],
        [ "cname" => "selector2._domainkey" ],
        [ "cname" => "ctct1._domainkey" ],
        [ "cname" => "ctct2._domainkey" ],
        [ "cname" => "mail" ],
        [ "cname" => "ftp" ],
        [ "mx"    => "" ],
        [ "mx"    => "mg" ],
        [ "txt"   => "" ],
        [ "txt"   => "_dmarc" ],
        [ "txt"   => "_amazonses" ],
        [ "txt"   => "_acme-challenge" ],
        [ "txt"   => "_acme-challenge.www" ],
        [ "txt"   => " _mailchannels" ],
        [ "txt"   => "default._domainkey" ],
        [ "txt"   => "google._domainkey" ],
        [ "txt"   => "mg" ],
        [ "txt"   => "smtp._domainkey.mg" ],
        [ "txt"   => "k1._domainkey" ],
        [ "srv"   => "_sip._tls" ],
        [ "srv"   => "_sipfederationtls._tcp" ],
        [ "ns"    => "" ],
        [ "soa"   => "" ],
    ];

    $wildcard_cname = "";
    $wildcard_a     = "";

    foreach ($records_to_check as $record) {
        $type = key($record);
        $name = $record[$type];

        $pre  = !empty($name) ? "{$name}." : "";
        // Obtenemos la salida principal
        $value = shell_exec("(host -t $type $pre$fullDomain | grep -q 'is an alias for') && echo \"\" || dig $pre$fullDomain $type +short | sort -n");

        // Ajuste especial para los CNAME (usamos host y awk)
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$fullDomain | grep 'alias for' | awk '{print \$NF}'");
        }
        $value = empty($value) ? "" : trim($value);
        if (empty($value)) {
            continue;
        }

        // Manejo de SOA
        if ($type == "soa") {
            $parts = explode(" ", $value);
            if (count($parts) >= 7) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(
                    Factory::Soa(
                        $parts[0], // primary name server
                        $parts[1], // responsible person (email)
                        $parts[2], // serial
                        $parts[3], // refresh
                        $parts[4], // retry
                        $parts[5], // expire
                        $parts[6]  // minimum
                    )
                );
                $zone->addResourceRecord($rr);
            }
            continue;
        }

        // Manejo de NS
        if ($type == "ns") {
            $record_values = explode("\n", $value);
            foreach ($record_values as $rv) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Ns($rv));
                $zone->addResourceRecord($rr);
            }
            $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
            continue;
        }

        // Verificamos si es en realidad un CNAME cuando pedimos un A
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            // Reevaluamos como cname
            $type = "cname";
            $value = shell_exec("dig $pre$fullDomain $type +short | sort -n");
            $value = empty($value) ? "" : trim($value);
            if (empty($value)) {
                continue;
            }
        }

        if ($type == "a") {
            $record_values = explode("\n", $value);
            $setName       = empty($name) ? "@" : $name;
            foreach ($record_values as $rv) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::A($rv));
                $zone->addResourceRecord($rr);
            }
        }

        if ($type == "cname") {
            $setName = empty($name) ? $fullDomain : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rr);
        }

        if ($type == "srv") {
            $srvParts = explode(" ", $value);
            if (count($srvParts) == 4) {
                // priority, weight, port, target
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Srv($srvParts[0], $srvParts[1], $srvParts[2], $srvParts[3]));
                $zone->addResourceRecord($rr);
            }
        }

        if ($type == "mx") {
            $setName       = empty($name) ? "@" : $name;
            $record_values = explode("\n", $value);
            // Ordenar por prioridad
            usort($record_values, function ($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach ($record_values as $line) {
                $mxParts = explode(" ", $line);
                if (count($mxParts) == 2) {
                    $mx_priority = $mxParts[0];
                    $mx_value    = $mxParts[1];
                    $rr = new ResourceRecord;
                    $rr->setName($setName);
                    $rr->setRdata(Factory::Mx($mx_priority, $mx_value));
                    $zone->addResourceRecord($rr);
                }
            }
        }

        if ($type == "txt") {
            $record_values = explode("\n", $value);
            $setName       = empty($name) ? "@" : $name;
            foreach ($record_values as $rv) {
                // Quitamos comillas si vienen
                $txtVal = trim($rv, '"');
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setClass('IN');
                $rr->setRdata(Factory::Txt($txtVal, 0, 200));
                $zone->addResourceRecord($rr);
            }
        }

        // Guardamos para el array final
        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }

    // 6) HTTP headers (se hacen sobre el fullDomain)
    $response = shell_exec("curl -sLI $fullDomain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
    $lines    = explode("\n", trim($response));
    $http_headers = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
            $key   = strtolower($matches[1]);
            $value = $matches[2];
            if (isset($http_headers[$key])) {
                if (is_array($http_headers[$key])) {
                    $http_headers[$key][] = $value;
                } else {
                    $http_headers[$key] = [$http_headers[$key], $value];
                }
            } else {
                $http_headers[$key] = $value;
            }
        }
    }

    // 7) Construcción final de la zona
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    // Respuesta final en JSON
    echo json_encode([
        "whois"        => $whois,         // WHOIS del dominio base
        "http_headers" => $http_headers,  // Headers del subdominio/dominio
        "dns_records"  => $dns_records,   // DNS del subdominio/dominio
        "ip_lookup"    => $ip_lookup,     // IP lookup
        "errors"       => [],
        "zone"         => $builder->build($zone)
    ]);
    die();
}

// Ejecutamos la función principal
run();

?>
<!DOCTYPE html>
<html>
<head>
    <title>WHOIS and NS Lookup</title>
    <link href="prism.css" rel="stylesheet" />
    <link href="https://fonts.googleapis.com/css?family=Roboto:100,300,400,500,700,900" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/@mdi/font@7.4.47/css/materialdesignicons.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/vuetify@v3.7.6/dist/vuetify.min.css" rel="stylesheet">
    <link rel="icon" href="favicon.png" />
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, minimal-ui">
    <style>
        [v-cloak] > * {
            display:none;
        }
        .multiline {
            white-space: pre-wrap;
        }
        .theme--light.v-application code {
            padding: 0px;
            background: transparent;
        }
    </style>
</head>
<body>
  <div id="app" v-cloak>
    <v-app>
      <v-main>
        <v-container>
            <v-text-field 
                variant="outlined" 
                color="primary" 
                label="Dominio o Subdominio" 
                v-model="domain" 
                spellcheck="false" 
                @keydown.enter="lookupDomain()" 
                class="mt-5 mx-auto"
            >
                <template v-slot:append-inner>
                    <v-btn variant="flat" color="primary" @click="lookupDomain()" :loading="loading">
                        Lookup
                        <template v-slot:loader>
                            <v-progress-circular :size="22" :width="2" color="white" indeterminate></v-progress-circular>
                        </template>
                    </v-btn>
                </template>
            </v-text-field>
            
            <v-alert type="warning" v-for="error in response.errors" class="mb-3" v-html="error"></v-alert>
            
            <v-row v-if="response.whois && response.whois != ''">
                <v-col md="5" cols="12">
                    <v-card variant="outlined" color="primary">
                        <v-card-title>Whois (Dominio Base)</v-card-title>
                        <v-card-text>
                            <v-table density="compact">
                                <template v-slot:default>
                                    <thead>
                                        <tr>
                                            <th class="text-left">Nombre</th>
                                            <th class="text-left">Valor</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for='record in response.whois'>
                                            <td>{{ record.name }}</td>
                                            <td>{{ record.value }}</td>
                                        </tr>
                                    </tbody>
                                </template>
                            </v-table>
                        </v-card-text>
                    </v-card>

                    <v-card class="mt-5" variant="outlined" color="primary">
                        <v-card-title>IP information (subdominio o dominio)</v-card-title>
                        <v-card-text>
                            <template v-for='(rows, ip) in response.ip_lookup'>
                                <div class="mt-3">Details for {{ ip }}</div>
                                <v-table density="compact">
                                    <template v-slot:default>
                                        <thead>
                                            <tr>
                                                <th class="text-left">Nombre</th>
                                                <th class="text-left">Valor</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for='row in rows.split("\n")'>
                                                <td>{{ row.split(":")[0] }}</td>
                                                <td>{{ row.split(":")[1] }}</td>
                                            </tr>
                                        </tbody>
                                    </template>
                                </v-table>
                            </template>
                        </v-card-text>
                    </v-card>

                    <v-card class="mt-5" variant="outlined" color="primary">
                        <v-card-title>HTTP headers</v-card-title>
                        <v-card-text>
                            <v-table density="compact">
                                <template v-slot:default>
                                    <thead>
                                        <tr>
                                            <th class="text-left" style="min-width: 200px;">Header</th>
                                            <th class="text-left">Valor</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for='(value, key) in response.http_headers'>
                                            <td>{{ key }}</td>
                                            <td v-if="Array.isArray(value)">
                                                <div v-for="(v, idx) in value" :key="idx">{{ v }}</div>
                                            </td>
                                            <td v-else>{{ value }}</td>
                                        </tr>
                                    </tbody>
                                </template>
                            </v-table>
                        </v-card-text>
                    </v-card>
                </v-col>
                <v-col md="7" cols="12">
                    <v-card variant="outlined" color="primary">
                        <v-card-title>Common DNS records</v-card-title>
                        <v-card-text>
                            <v-table density="compact">
                                <template v-slot:default>
                                    <thead>
                                        <tr>
                                            <th class="text-left">Type</th>
                                            <th class="text-left">Name</th>
                                            <th class="text-left">Value</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr v-for="record in response.dns_records">
                                            <td>{{ record.type }}</td>
                                            <td>{{ record.name }}</td>
                                            <td class="multiline">{{ record.value }}</td>
                                        </tr>
                                    </tbody>
                                </template>
                            </v-table>
                        </v-card-text>
                    </v-card>

                    <v-card class="mt-5" variant="flat">
                        <v-btn size="small" @click="copyZone()" class="position-absolute right-0 mt-6" style="margin-right: 140px;">
                            <v-icon left>mdi-content-copy</v-icon>
                        </v-btn>
                        <v-btn size="small" @click="downloadZone()" class="position-absolute right-0 mt-6 mr-4">
                            <v-icon left>mdi-download</v-icon>
                            Download
                        </v-btn>
                        <pre class="language-dns-zone-file text-body-2" style="border-radius:4px;border:0px">
                            <code class="language-dns-zone-file">{{ response.zone }}</code>
                        </pre>
                        <a ref="download_zone" href="#"></a>
                    </v-card>
                </v-col>
            </v-row>
        </v-container>
        <v-snackbar v-model="snackbar.show" timeout="2000">
            {{ snackbar.message }}
            <template v-slot:actions>
                <v-btn variant="text" @click="snackbar.show = false">Close</v-btn>
            </template>
        </v-snackbar>
      </v-main>
    </v-app>
  </div>
  <script src="prism.js"></script>
  <!-- Vue y Vuetify -->
  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.30/dist/vue.global.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@v3.7.6/dist/vuetify.min.js"></script>
  <script>
    const { createApp } = Vue;
    const { createVuetify } = Vuetify;
    const vuetify = createVuetify();

    createApp({
        data() {
            return {
                domain: "",
                loading: false,
                snackbar: { show: false, message: "" },
                response: { whois: "", errors: [], zone: "" }
            }
        },
        methods: {
            lookupDomain() {
                this.loading = true;
                fetch("?domain=" + encodeURIComponent(this.domain))
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false;
                        this.response = data;
                    })
                    .then(() => {
                        // Resaltar syntax con Prism
                        Prism.highlightAll();
                    })
                    .catch((error) => {
                        this.loading = false;
                        this.response.errors = [error.toString()];
                    });
            },
            downloadZone() {
                const newBlob = new Blob([this.response.zone], {type: "text/dns"});
                this.$refs.download_zone.download = `${this.domain}.zone`;
                this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                this.$refs.download_zone.click();
            },
            copyZone() {
                navigator.clipboard.writeText(this.response.zone);
                this.snackbar.message = "Zone copied to clipboard";
                this.snackbar.show = true;
            }
        }
    }).use(vuetify).mount('#app');
  </script>
</body>
</html>