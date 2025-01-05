<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;

error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Formateador especial para registros TXT largos.
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
 * Función para separar dominio raíz (root domain) y subdominio,
 * considerando TLDs comunes de dos niveles (ej: com.pe, com.mx, etc.).
 *
 * Por ejemplo:
 *   - "sub1.midominio.com"       => ["root_domain" => "midominio.com",       "sub_domain" => "sub1"]
 *   - "sub2.midominio.com.pe"    => ["root_domain" => "midominio.com.pe",    "sub_domain" => "sub2"]
 *   - "midominio.com.pe"         => ["root_domain" => "midominio.com.pe",    "sub_domain" => ""]
 *   - "midominio.com"            => ["root_domain" => "midominio.com",       "sub_domain" => ""]
 */
function parseDomain(string $fullDomain): array
{
    // Lista de TLDs (o ccTLDs) de 2 niveles que quieres soportar
    $twoLevelTlds = [
        'co.uk', 'com.ar', 'com.br', 'com.mx', 'com.pe', 'co.pe', 'net.pe', 'org.pe', // Agrega más si lo requieres
    ];

    $fullDomain = strtolower($fullDomain);
    $parts = explode('.', $fullDomain);

    // Si solo tiene 2 partes (ej: midominio.com),
    // entonces no hay subdominio.
    if (count($parts) <= 2) {
        return [
            'root_domain' => $fullDomain,
            'sub_domain'  => '',
        ];
    }

    // Revisamos si el dominio completo termina con alguno de los TLDs de 2 niveles.
    // Ejemplo: midominio.com.pe => partes: ["midominio","com","pe"]
    // Queremos que root_domain sea "midominio.com.pe", sub_domain lo que queda a la izquierda.
    $last2 = implode('.', array_slice($parts, -2)); // últimas 2 partes
    $last3 = implode('.', array_slice($parts, -3)); // últimas 3 partes (por si hubiera sub-subdominios)

    // Determina cuántos "componentes" del final conforman el TLD
    $tldLength = 1; // Por defecto asumimos TLD de 1 nivel (ej: .com)

    // Verificamos si hay un TLD de 2 niveles en la lista
    if (in_array($last2, $twoLevelTlds)) {
        $tldLength = 2;
    }

    // root_domain => unión de las partes "dominio + TLD".
    // sub_domain  => el resto a la izquierda.
    $domainPartsCount = count($parts);
    $rootDomainParts  = $domainPartsCount - $tldLength - 1; 
    // -1 más para incluir la parte inmediatamente anterior al TLD.
    // Ej. si $tldLength=2, restamos 3 a count($parts).

    // Evita casos raros donde no haya subdominio
    if ($rootDomainParts < 1) {
        // Significa que no hay subdominio
        return [
            'root_domain' => $fullDomain,
            'sub_domain'  => '',
        ];
    }

    $rootDomainArray = array_slice($parts, $rootDomainParts);
    $rootDomain = implode('.', $rootDomainArray);

    $subDomainArray = array_slice($parts, 0, $rootDomainParts);
    $subDomain = implode('.', $subDomainArray);

    return [
        'root_domain' => $rootDomain,
        'sub_domain'  => $subDomain,
    ];
}

function run() {

    if (!isset($_REQUEST['domain'])) {
        return;
    }

    $requestedDomain = $_REQUEST['domain'];
    $errors = [];
    $ip_lookup = [];
    $dns_records = [];
    $required_bins = ["whois", "dig", "host"];

    // Verifica si los comandos necesarios están instalados
    foreach ($required_bins as $bin) {
        $output = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Quitamos protocolos o paths para quedarnos con algo tipo "sub1.midominio.com.pe"
    $requestedDomain = preg_replace('#^https?://#', '', rtrim($requestedDomain, '/'));

    // Analiza dominio y subdominio
    $parsed = parseDomain($requestedDomain);
    $rootDomain = $parsed['root_domain'];   // p.e. midominio.com.pe
    $fullDomain = $requestedDomain;         // p.e. sub1.midominio.com.pe (se usará para DNS)

    // Validaciones mínimas de la cadena ingresada
    if (!filter_var($rootDomain, FILTER_VALIDATE_DOMAIN)) {
        $errors[] = "Invalid domain.";
    }
    if (strpos($rootDomain, '.') === false) {
        $errors[] = "Invalid domain (no TLD).";
    }
    if (strlen($rootDomain) < 4) {
        $errors[] = "No domain name is that short.";
    }
    if (strlen($rootDomain) > 80) {
        $errors[] = "Too long.";
    }
    if (count($errors) > 0) {
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    // Creamos el objeto Zone con el dominio completo (para mostrar registros DNS).
    // Nota: Se le agrega un punto final por convención en ZoneFile.
    $zone = new Zone($fullDomain . ".");
    $zone->setDefaultTtl(3600);

    // WHOIS se hace al dominio raíz
    // --------------------------------------
    $whois = shell_exec("whois $rootDomain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'");
    $whois = empty($whois) ? "" : trim($whois);

    if (empty($whois)) {
        $errors[] = "Domain not found (WHOIS).";
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    $whois = explode("\n", $whois);
    foreach ($whois as $key => $record) {
        $split = explode(":", trim($record));
        $name = trim($split[0]);
        $value = isset($split[1]) ? trim($split[1]) : "";
        if ($name == "Name Server" || $name == "Domain Name") {
            $value = strtolower($value);
        }
        $whois[$key] = ["name" => $name, "value" => $value];
    }
    // Eliminamos duplicados en el array de WHOIS
    $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    $col_name = array_column($whois, 'name');
    $col_value = array_column($whois, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);

    // IP Lookup del dominio completo (puede ser sub1.midominio.com.pe)
    $ips = explode("\n", trim(shell_exec("dig $fullDomain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response = empty($response) ? "" : trim($response);
        $ip_lookup["$ip"] = $response;
    }

    // Verificamos registro por registro
    // --------------------------------------
    $records_to_check = [
        ["a" => ""],
        ["a" => "*"],
        ["a" => "mail"],
        ["a" => "remote"],
        ["a" => "www"],
        ["cname" => "*"],
        ["cname" => "www"],
        ["cname" => "autodiscover"],
        ["cname" => "sip"],
        ["cname" => "lyncdiscover"],
        ["cname" => "enterpriseregistration"],
        ["cname" => "enterpriseenrollment"],
        ["cname" => "email.mg"],
        ["cname" => "msoid"],
        ["cname" => "_acme-challenge"],
        ["cname" => "k1._domainkey"],
        ["cname" => "k2._domainkey"],
        ["cname" => "k3._domainkey"],
        ["cname" => "s1._domainkey"],
        ["cname" => "s2._domainkey"],
        ["cname" => "selector1._domainkey"],
        ["cname" => "selector2._domainkey"],
        ["cname" => "ctct1._domainkey"],
        ["cname" => "ctct2._domainkey"],
        ["cname" => "mail"],
        ["cname" => "ftp"],
        ["mx" => ""],
        ["mx" => "mg"],
        ["txt" => ""],
        ["txt" => "_dmarc"],
        ["txt" => "_amazonses"],
        ["txt" => "_acme-challenge"],
        ["txt" => "_acme-challenge.www"],
        ["txt" => " _mailchannels"],
        ["txt" => "default._domainkey"],
        ["txt" => "google._domainkey"],
        ["txt" => "mg"],
        ["txt" => "smtp._domainkey.mg"],
        ["txt" => "k1._domainkey"],
        ["srv" => "_sip._tls"],
        ["srv" => "_sipfederationtls._tcp"],
        ["ns" => ""],
        ["soa" => ""],
    ];

    $wildcard_cname = "";
    $wildcard_a = "";

    foreach ($records_to_check as $record) {
        $pre = "";
        $type = key($record);
        $name = $record[$type];
        if (!empty($name)) {
            $pre = "{$name}.";
        }

        // Usamos el dominio completo ($fullDomain) para las consultas DNS
        $value = shell_exec("(host -t $type $pre$fullDomain | grep -q 'is an alias for') && echo \"\" || dig $pre$fullDomain $type +short | sort -n");
        
        // Para el caso de los CNAME, preferimos host
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$fullDomain | grep 'alias for' | awk '{print \$NF}'");
        }

        $value = empty($value) ? "" : trim($value);
        if (empty($value)) {
            continue;
        }

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

        if ($type == "ns") {
            $record_values = explode("\n", $value);
            foreach ($record_values as $record_value) {
                $setName = empty($name) ? "@" : $name;
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($recordObj);
            }
        }

        // Verificar si A es CNAME
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            $type = "cname";
            $value = shell_exec("dig $pre$fullDomain $type +short | sort -n");
            $value = empty($value) ? "" : trim($value);
            if (empty($value)) {
                continue;
            }
        }

        if ($type == "a") {
            $record_values = explode("\n", $value);
            if ($name == "*") {
                $wildcard_a = $record_values;
            }
            $setName = empty($name) ? "@" : $name;
            foreach ($record_values as $record_value) {
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::A($record_value));
                $zone->addResourceRecord($recordObj);
            }
        }

        if ($type == "cname") {
            if ($name == "*") {
                $wildcard_cname = $value;
                continue;
            }
            $setName = empty($name) ? $fullDomain : $name;
            $recordObj = new ResourceRecord;
            $recordObj->setName($setName);
            $recordObj->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($recordObj);
        }

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

        if ($type == "mx") {
            $setName = empty($name) ? "@" : $name;
            $record_values = explode("\n", $value);
            usort($record_values, function ($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach ($record_values as $record_value) {
                $parts = explode(" ", $record_value);
                if (count($parts) != 2) {
                    continue;
                }
                $mx_priority = $parts[0];
                $mx_value = $parts[1];
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($recordObj);
            }
        }

        if ($type == "txt") {
            $record_values = explode("\n", $value);
            $setName = empty($name) ? "@" : "$name";
            foreach ($record_values as $record_value) {
                $recordObj = new ResourceRecord;
                $recordObj->setName($setName);
                $recordObj->setClass('IN');
                // Eliminamos comillas que puedan venir de "dig"
                $cleanValue = trim($record_value, '"');
                $recordObj->setRdata(Factory::Txt($cleanValue, 0, 200));
                $zone->addResourceRecord($recordObj);
            }
        }

        $dns_records[] = [
            "type"  => $type,
            "name"  => $name,
            "value" => $value
        ];
    }

    // HTTP HEADERS del subdominio (o dominio completo) consultado
    // -----------------------------------------------------------------
    $response = shell_exec("curl -sLI $fullDomain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
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

    // Construimos la zona con el formateador especial para TXT
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    echo json_encode([
        "whois"        => $whois,
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
                                    <tr v-for='(value, key) in response.http_headers'>
                                        <td>{{ key }}</td>
                                        <td>
                                            <!-- Si hay múltiples valores para la misma key, los mostramos en una lista -->
                                            <div v-if="Array.isArray(value)">
                                                <div v-for="val in value">{{ val }}</div>
                                            </div>
                                            <div v-else>
                                                {{ value }}
                                            </div>
                                        </td>
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
                // Limpiamos algo básico de la URL en caso de que el usuario ponga http://...
                let domainClean = this.domain.replace(/^https?:\/\//, '').replace(/\/+$/, '');

                fetch("?domain=" + encodeURIComponent(domainClean))
                    .then(response => response.json())
                    .then(data => {
                        this.loading = false
                        this.response = data
                    })
                    .then(() => {
                        Prism.highlightAll()
                    })
                    .catch((err) => {
                        this.loading = false
                        console.error(err)
                    });
            },
            downloadZone() {
                let newBlob = new Blob([this.response.zone], {type: "text/dns"});
                this.$refs.download_zone.download = `${this.domain}.zone`;
                this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                this.$refs.download_zone.click();
            },
            copyZone() {
                navigator.clipboard.writeText(this.response.zone)
                this.snackbar.message = "Zone copied to clipboard"
                this.snackbar.show = true
            }
        }
    }).use(vuetify).mount('#app');
  </script>
</body>
</html>