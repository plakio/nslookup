<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Si el contenido del registro TXT supera los 500 caracteres,
 * lo divide en trozos de 500 para cumplir con la sintaxis correcta.
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
 * Extrae el dominio principal de un subdominio.
 * sub.example.com => example.com
 * example.com     => example.com
 */
function extractDomain($subdomain) {
    $parts = explode('.', $subdomain);
    $count = count($parts);

    // Si tiene más de 2 partes, asumimos que las 2 últimas forman el dominio principal
    if ($count > 2) {
        return implode('.', array_slice($parts, $count - 2));
    }
    // Si solo tiene 2 partes, ya es un dominio principal
    return $subdomain;
}

function run() {

    // Verifica si se recibió algún dominio por parámetro
    if (!isset($_REQUEST['domain'])) {
        return;
    }

    $domain = $_REQUEST['domain'];
    $errors = [];
    $ip_lookup = [];
    $dns_records = [];
    $required_bins = ["whois", "dig", "host"];

    // Comprueba que existan los comandos externos necesarios
    foreach ($required_bins as $bin) {
        $output = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Validaciones básicas del dominio
    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
        $errors[] = "Invalid domain.";
    }
    if (filter_var($domain, FILTER_VALIDATE_DOMAIN) && strpos($domain, '.') === false) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($domain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($domain) > 80) {
        $errors[] = "Too long.";
    }

    if (count($errors) > 0) {
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    // Crea la zona DNS con TTL por defecto
    $zone = new Zone($domain . ".");
    $zone->setDefaultTtl(3600);

    // --------------------------------
    // WHOIS: usamos el dominio principal
    // --------------------------------
    $whois_domain = extractDomain($domain);

    // Ejecuta whois sin grep para obtener la salida completa
    $whois_raw = shell_exec("whois $whois_domain");

    if (empty($whois_raw)) {
        // Si no hay salida alguna, asumimos que no se pudo obtener la info
        $errors[] = "Could not get WHOIS data.";
        echo json_encode(["errors" => $errors]);
        die();
    }

    // Verifica si "no match" o "NOT FOUND" está presente
    if (stripos($whois_raw, "No match") !== false 
        || stripos($whois_raw, "NOT FOUND") !== false
        || stripos($whois_raw, "no entries found") !== false) {
        $errors[] = "Domain not found.";
        echo json_encode(["errors" => $errors]);
        die();
    }

    // Filtra las líneas relevantes (Name Server, Registrar, etc.)
    $lines = explode("\n", $whois_raw);
    $whois_filtered = [];

    // Ajusta el patrón según tus necesidades / TLD
    foreach ($lines as $line) {
        if (preg_match('/(Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:|Domain Status:|Reseller)/i', $line)) {
            $whois_filtered[] = trim($line);
        }
    }

    // Si no encontró nada en el filtrado, usamos todo WHOIS para no perder info
    if (empty($whois_filtered)) {
        $whois_filtered = $lines;
    }

    // Convierte las líneas WHOIS en un array con [name => value]
    $whois_processed = [];
    foreach ($whois_filtered as $key => $record) {
        $split  = explode(":", $record, 2);
        $name   = trim($split[0] ?? '');
        $value  = trim($split[1] ?? '');
        // Forzamos minúsculas en 'Name Server' y 'Domain Name' si queremos
        if ($name == "Name Server" || $name == "Domain Name") {
            $value = strtolower($value);
        }
        $whois_processed[] = ["name" => $name, "value" => $value];
    }

    // Eliminamos duplicados y ordenamos
    $whois_processed = array_map("unserialize", array_unique(array_map("serialize", $whois_processed)));
    $col_name  = array_column($whois_processed, 'name');
    $col_value = array_column($whois_processed, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois_processed);

    // --------------------------------
    // Información de IP
    // --------------------------------
    $ips = explode("\n", trim(shell_exec("dig $domain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response = empty($response) ? "" : trim($response);
        $ip_lookup[$ip] = $response;
    }

    // --------------------------------
    // Preparación para registros wildcard
    // --------------------------------
    $wildcard_cname = "";
    $wildcard_a = "";

    // Lista de registros DNS a consultar
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

    // Bucle para consultar registros DNS
    foreach ($records_to_check as $record) {
        $pre = "";
        $type = key($record);
        $name = $record[$type];
        if (!empty($name)) {
            $pre = "{$name}.";
        }

        // Verifica si el registro es un alias, si no lo es, usa 'dig'
        $value = shell_exec("(host -t $type $pre$domain | grep -q 'is an alias for') && echo \"\" || dig $pre$domain $type +short | sort -n");

        // Para CNAME, obtiene la parte 'alias for'
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$domain | grep 'alias for' | awk '{print \$NF}'");
        }

        $value = empty($value) ? "" : trim($value);
        if (empty($value)) {
            continue;
        }

        // Manejo especial de SOA
        if ($type == "soa") {
            $record_value = explode(" ", $value);
            $setName = empty($name) ? "@" : $name;
            $recordObj = new ResourceRecord;
            $recordObj->setName($setName);
            $recordObj->setRdata(Factory::Soa(
                $record_value[0],
                $record_value[1],
                $record_value[2],
                $record_value[3],
                $record_value[4],
                $record_value[5],
                $record_value[6]
            ));
            $zone->addResourceRecord($recordObj);
            continue;
        }

        // Manejo especial de NS
        if ($type == "ns") {
            $record_values = explode("\n", $value);
            foreach($record_values as $record_value) {
                $setName = empty($name) ? "@" : $name;
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($recordObj);
            }
            continue;
        }

        // Si es un registro A y resultó ser un texto, asumimos que en realidad es un CNAME
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            $type  = "cname";
            $value = shell_exec("dig $pre$domain $type +short | sort -n");
            $value = empty($value) ? "" : trim($value);
            if (empty($value)) {
                continue;
            }
        }

        // Manejo del tipo A (direcciones IP)
        if ($type == "a") {
            if (!empty($wildcard_a) && $wildcard_a == $record_values) {
                continue;
            }
            if ($name == "*") {
                $wildcard_a = $record_values;
            }
            $record_values = explode("\n", $value);
            $setName = empty($name) ? "@" : $name;
            foreach ($record_values as $record_value) {
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::A($record_value));
                $zone->addResourceRecord($recordObj);
            }
        }

        // Manejo del tipo CNAME
        if ($type == "cname") {
            if ($name == "*") {
                $wildcard_cname = $value;
                continue;
            }
            if (!empty($wildcard_cname) && $wildcard_cname == $value) {
                continue;
            }
            $setName = empty($name) ? $domain : $name;
            $recordObj = new ResourceRecord;
            $recordObj->setName($setName);
            $recordObj->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($recordObj);
        }

        // Manejo del tipo SRV
        if ($type == "srv") {
            $record_values = explode(" ", $value);
            if (count($record_values) != 4) {
                continue;
            }
            $setName = empty($name) ? "@" : $name;
            $recordObj = new ResourceRecord;
            $recordObj->setName($setName);
            $recordObj->setRdata(Factory::Srv(
                $record_values[0],
                $record_values[1],
                $record_values[2],
                $record_values[3]
            ));
            $zone->addResourceRecord($recordObj);
        }

        // Manejo de MX
        if ($type == "mx") {
            $setName       = empty($name) ? "@" : $name;
            $record_values = explode("\n", $value);
            // Ordena por prioridad
            usort($record_values, function ($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach($record_values as $record_value) {
                $record_value = explode(" ", $record_value);
                if (count($record_value) != 2) {
                    continue;
                }
                $mx_priority = $record_value[0];
                $mx_value    = $record_value[1];
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($recordObj);
            }
        }

        // Manejo de TXT
        if ($type == "txt") {
            $record_values = explode("\n", $value);
            $setName       = empty($name) ? "@" : "$name";
            foreach ($record_values as $record_value) {
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setClass('IN');
                $recordObj->setRdata(Factory::Txt(trim($record_value,'"'), 0, 200));
                $zone->addResourceRecord($recordObj);
            }
        }

        // Agrega la info al arreglo final de registros DNS
        $dns_records[] = ["type" => $type, "name" => $name, "value" => $value];
    }

    // --------------------------------
    // Encabezados HTTP
    // --------------------------------
    $response = shell_exec("curl -sLI $domain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
    $lines = explode("\n", trim($response));
    $http_headers = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
            $key = strtolower($matches[1]);
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

    // Construye la zona usando AlignedBuilder
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    // Respuesta final en JSON
    echo json_encode([
        "whois"        => $whois_processed,  // <- ahora viene del filtrado en PHP
        "http_headers" => $http_headers,
        "dns_records"  => $dns_records,
        "ip_lookup"    => $ip_lookup,
        "errors"       => [],
        "zone"         => $builder->build($zone)
    ]);
    die();
}

run();

?>
<!DOCTYPE html>
<html>
<head>
    <title>WHOIS</title>
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
            <v-text-field variant="outlined" color="primary" label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()" class="mt-5 mx-auto">
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
                <v-card-title>Whois</v-card-title>
                <v-card-text>
                <v-table density="compact">
                <template v-slot:default>
                <thead>
                    <tr>
                        <th class="text-left">Name</th>
                        <th class="text-left">Value</th>
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
                <v-card-title>IP information</v-card-title>
                <v-card-text>
                    <template v-for='(rows, ip) in response.ip_lookup'>
                    <div class="mt-3">Details for {{ ip }}</div>
                    <v-table density="compact">
                    <template v-slot:default>
                    <thead>
                        <tr>
                            <th class="text-left">Name</th>
                            <th class="text-left">Value</th>
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
                            <th class="text-left" style="min-width: 200px;">Name</th>
                            <th class="text-left">Value</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for='(key, value) in response.http_headers'>
                            <td>{{ value }}</td>
                            <td>{{ key }}</td>
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
                <v-btn variant="text" @click="snackbar.show = false">
                    Close
                </v-btn>
            </template>
        </v-snackbar>
      </v-main>
    </v-app>
  </div>
  <script src="prism.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.30/dist/vue.global.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@v3.6.10/dist/vuetify.min.js"></script>
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
                // El frontend limpia la URL y extrae únicamente el host
                this.domain = this.extractHostname(this.domain);
                fetch("?domain=" + this.domain)
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false;
                        this.response = data;
                    })
                    .then( () => {
                        Prism.highlightAll();
                    });
            },
            extractHostname(url) {
                let hostname;
                if (url.indexOf("//") > -1) {
                    hostname = url.split('/')[2];
                } else {
                    hostname = url.split('/')[0];
                }
                hostname = hostname.split(':')[0];
                hostname = hostname.split('?')[0];
                return hostname;
            },
            downloadZone() {
                let newBlob = new Blob([this.response.zone], {type: "text/dns"});
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