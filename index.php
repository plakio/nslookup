<?php

require_once 'vendor/autoload.php';

// Importar Badcow DNS
use Badcow\DNS\Zone;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\Classes;

error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Formatea los registros TXT largos (más de 500 caracteres)
 * y los divide en varias líneas en la zona DNS resultante.
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
 * Obtiene el "dominio base" (registrable) de un subdominio,
 * contemplando TLD compuestos como .com.pe, .com.mx, .co.uk, etc.
 * (Versión manual SIN php-domain-parser)
 */
function getBaseDomain(string $fullDomain): string
{
    $fullDomain = preg_replace('/^https?:\/\//i', '', $fullDomain);
    $fullDomain = explode('/', $fullDomain)[0];
    $fullDomain = trim($fullDomain);
    $fullDomain = strtolower($fullDomain);

    // Lista de TLD compuestos. Agrega lo que necesites.
    $doubleTlds = [
        'com.pe',
        'com.mx',
        'com.ar',
        'com.co',
        'co.uk',
        'co.nz',
        'co.jp',
        // ...
    ];

    $parts = explode('.', $fullDomain);
    if (count($parts) < 2) {
        return $fullDomain;
    }

    $last2Labels = implode('.', array_slice($parts, -2));
    if (in_array($last2Labels, $doubleTlds)) {
        array_splice($parts, -2);
        $domain = array_pop($parts);
        return $domain . '.' . $last2Labels;
    } else {
        // TLD simple
        $tld    = array_pop($parts);
        $domain = array_pop($parts);
        return $domain . '.' . $tld;
    }
}

function run() {
    if (! isset($_REQUEST['domain'])) {
        return;
    }

    $fullDomain = trim($_REQUEST['domain']);
    $errors = [];
    $ip_lookup = [];
    $dns_records = [];

    // Verificamos si están instalados whois, dig y host
    $required_bins = [ "whois", "dig", "host" ];
    foreach ($required_bins as $bin) {
        $output = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Validaciones del "dominio" ingresado
    if (! filter_var($fullDomain, FILTER_VALIDATE_DOMAIN)) {
        $errors[] = "Invalid domain.";
    }
    if (strpos($fullDomain, '.') === false) {
        $errors[] = "Invalid domain (no dot found).";
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

    // 1) Obtenemos el dominio base usando nuestra función manual
    $whoisDomain = getBaseDomain($fullDomain);

    // 2) WHOIS sobre el dominio base
    $whoisCmd = "whois $whoisDomain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'";
    $whois = shell_exec($whoisCmd);
    $whois = empty($whois) ? "" : trim($whois);

    if (empty($whois)) {
        $errors[] = "Domain not found (whois).";
        echo json_encode(["errors" => $errors]);
        die();
    }

    // Parse WHOIS en array
    $whoisLines = explode("\n", $whois);
    foreach ($whoisLines as $key => $line) {
        $split = explode(":", trim($line), 2);
        $name  = trim($split[0]);
        $value = trim($split[1] ?? "");
        if ($name === "Name Server" || $name === "Domain Name") {
            $value = strtolower($value);
        }
        $whoisLines[$key] = [ "name" => $name, "value" => $value ];
    }
    // Eliminamos duplicados
    $whoisLines = array_map("unserialize", array_unique(array_map("serialize", $whoisLines)));
    $col_name  = array_column($whoisLines, 'name');
    $col_value = array_column($whoisLines, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whoisLines);

    // 3) Creamos la zona DNS (sobre el subdominio o dominio completo)
    $zone = new Zone($fullDomain . ".");
    $zone->setDefaultTtl(3600);

    // 4) IP lookup (sobre el fullDomain)
    $ips = explode("\n", trim(shell_exec("dig $fullDomain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response = empty($response) ? "" : trim($response);
        $ip_lookup[$ip] = $response;
    }

    // 5) Consulta de registros DNS
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

    foreach ($records_to_check as $record) {
        $type = key($record);
        $name = $record[$type];
        $pre  = ($name !== "") ? ($name . ".") : "";

        // Verificamos con dig y host
        $value = shell_exec("(host -t $type $pre$fullDomain | grep -q 'is an alias for') && echo \"\" || dig $pre$fullDomain $type +short | sort -n");
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$fullDomain | grep 'alias for' | awk '{print \$NF}'");
        }
        $value = trim($value ?? "");
        if (empty($value)) {
            continue;
        }

        // SOA
        if ($type == "soa") {
            $parts = explode(" ", $value);
            if (count($parts) >= 7) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord();
                $rr->setName($setName);
                $rr->setRdata(
                    Factory::Soa(
                        $parts[0], // primary nameserver
                        $parts[1], // responsible email
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

        // NS
        if ($type == "ns") {
            $nsValues = explode("\n", $value);
            foreach ($nsValues as $nsVal) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord();
                $rr->setName($setName);
                $rr->setRdata(Factory::Ns($nsVal));
                $zone->addResourceRecord($rr);
            }
            $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
            continue;
        }

        // Verificar si es un CNAME cuando pedimos A
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            $type  = "cname";
            $value = shell_exec("dig $pre$fullDomain $type +short | sort -n");
            $value = trim($value ?? "");
            if (empty($value)) {
                continue;
            }
        }

        if ($type == "a") {
            $aValues = explode("\n", $value);
            $setName = empty($name) ? "@" : $name;
            foreach ($aValues as $aVal) {
                $rr = new ResourceRecord();
                $rr->setName($setName);
                $rr->setClass(Classes::IN);
                $rr->setRdata(Factory::A($aVal));
                $zone->addResourceRecord($rr);
            }
        }

        if ($type == "cname") {
            $setName = empty($name) ? $fullDomain : $name;
            $rr = new ResourceRecord();
            $rr->setName($setName);
            $rr->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rr);
        }

        if ($type == "srv") {
            $srvParts = explode(" ", $value);
            if (count($srvParts) == 4) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord();
                $rr->setName($setName);
                $rr->setRdata(Factory::Srv($srvParts[0], $srvParts[1], $srvParts[2], $srvParts[3]));
                $zone->addResourceRecord($rr);
            }
        }

        if ($type == "mx") {
            $mxLines = explode("\n", $value);
            usort($mxLines, function($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            $setName = empty($name) ? "@" : $name;
            foreach ($mxLines as $mxLine) {
                $mxParts = explode(" ", $mxLine);
                if (count($mxParts) == 2) {
                    $mx_priority = $mxParts[0];
                    $mx_value    = $mxParts[1];
                    $rr = new ResourceRecord();
                    $rr->setName($setName);
                    $rr->setRdata(Factory::Mx($mx_priority, $mx_value));
                    $zone->addResourceRecord($rr);
                }
            }
        }

        if ($type == "txt") {
            $txtLines = explode("\n", $value);
            $setName  = empty($name) ? "@" : $name;
            foreach ($txtLines as $txtVal) {
                $txtVal = trim($txtVal, '"');
                $rr = new ResourceRecord();
                $rr->setName($setName);
                $rr->setClass(Classes::IN);
                $rr->setRdata(Factory::Txt($txtVal, 0, 200));
                $zone->addResourceRecord($rr);
            }
        }

        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }

    // 6) HTTP headers (subdominio o dominio completo)
    $curlResp = shell_exec("curl -sLI $fullDomain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
    $lines = explode("\n", trim($curlResp));
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

    // 7) Construimos la zona
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    // Respuesta final en JSON
    echo json_encode([
        "whois"        => $whoisLines,    // WHOIS del dominio base
        "http_headers" => $http_headers,  // Headers del fullDomain
        "dns_records"  => $dns_records,   // DNS del fullDomain
        "ip_lookup"    => $ip_lookup,     // IP lookup
        "errors"       => [],
        "zone"         => $builder->build($zone),
    ]);
    die();
}

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
                                        <tr v-for="record in response.whois" :key="record.name + record.value">
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
                            <template v-for="(rows, ip) in response.ip_lookup" :key="ip">
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
                                            <tr v-for="row in rows.split('\n')" :key="row">
                                                <td>{{ row.split(':')[0] }}</td>
                                                <td>{{ row.split(':')[1] }}</td>
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
                                        <tr v-for="(value, key) in response.http_headers" :key="key">
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
                                        <tr
                                            v-for="(rec, index) in response.dns_records"
                                            :key="rec.type + rec.name + index"
                                        >
                                            <td>{{ rec.type }}</td>
                                            <td>{{ rec.name }}</td>
                                            <td class="multiline">{{ rec.value }}</td>
                                        </tr>
                                    </tbody>
                                </template>
                            </v-table>
                        </v-card-text>
                    </v-card>

                    <v-card class="mt-5" variant="flat">
                        <v-btn
                            size="small"
                            @click="copyZone()"
                            class="position-absolute right-0 mt-6"
                            style="margin-right: 140px;"
                        >
                            <v-icon left>mdi-content-copy</v-icon>
                        </v-btn>
                        <v-btn
                            size="small"
                            @click="downloadZone()"
                            class="position-absolute right-0 mt-6 mr-4"
                        >
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
                    .then(response => response.json())
                    .then(data => {
                        this.loading = false;
                        this.response = data;
                    })
                    .then(() => {
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