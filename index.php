<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Verifica si $domain es subdominio,
 * considerándolo así si tiene más de 2 partes (ej. sub.ejemplo.com).
 */
function isSubdomain($domain) {
    $domain = rtrim($domain, ".");
    $parts  = explode(".", $domain);
    return (count($parts) > 2);
}

/**
 * Formateador de TXT para partidas largas.
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

function run() {

    if (!isset($_REQUEST['domain'])) {
        return;
    }

    $domain      = $_REQUEST['domain'];
    $errors      = [];
    $ip_lookup   = [];
    $dns_records = [];

    // Comandos que deben existir en el sistema
    $required_bins = ["whois", "dig", "host"];
    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Validaciones mínimas de dominio
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
        echo json_encode(["errors" => $errors]);
        die();
    }

    // Creamos la zona DNS
    $zone = new Zone($domain . ".");
    $zone->setDefaultTtl(3600);

    // WHOIS
    $whois = [];
    if (isSubdomain($domain)) {
        // Si es subdominio, no hacemos whois
        $errors[] = "Skipping whois for subdomain";
    } else {
        // Solución #2: Leemos TODO el whois (sin grep), y lo parseamos
        $whois_raw = shell_exec("whois " . escapeshellarg($domain));
        if (empty($whois_raw)) {
            // Si sale vacío, asumimos "Domain not found"
            // Solución #3: No matamos el proceso, sólo agregamos error.
            $errors[] = "Domain not found. (WHOIS vacío)";
        } else {
            // Buscamos mensajes de dominio no encontrado en la salida
            // (hay muchos formatos posibles dependiendo del TLD)
            if (
                stripos($whois_raw, "No match for") !== false ||
                stripos($whois_raw, "NOT FOUND")    !== false ||
                stripos($whois_raw, "Domain Status: available") !== false ||
                stripos($whois_raw, "Domain not found") !== false
            ) {
                // No detenemos el script; sólo reportamos error
                $errors[] = "Domain not found (WHOIS indica no registrado).";
            } else {
                // Parseo línea a línea
                $lines = explode("\n", $whois_raw);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if ($line === "") {
                        continue;
                    }
                    // Si la línea tiene ":", separamos en "campo: valor"
                    if (strpos($line, ":") !== false) {
                        $parts = explode(":", $line, 2);
                        $field = trim($parts[0]);
                        $value = trim($parts[1] ?? "");
                        // Guardamos
                        $whois[] = ["name" => $field, "value" => $value];
                    }
                }

                // Eliminamos duplicados y ordenamos (similar a tu código original)
                $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
                $col_name  = array_column($whois, 'name');
                $col_value = array_column($whois, 'value');
                array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);
            }
        }
    }

    // IP lookup
    $ips = explode("\n", trim(shell_exec("dig " . escapeshellarg($domain) . " +short")));
    foreach ($ips as $ip) {
        $ip = trim($ip);
        if (!$ip) {
            continue;
        }
        // Con IP whois, sí seguimos usando grep -E, pero podríamos parsear completo si gustas
        $response = shell_exec("whois " . escapeshellarg($ip) . " | grep -E 'NetName:|Organization:|OrgName:'");
        $response = trim($response ?? "");
        $ip_lookup[$ip] = $response;
    }

    // Common DNS records
    $wildcard_cname = "";
    $wildcard_a     = "";

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
        $pre  = $name ? "{$name}." : "";

        // Usamos host/dig para checar
        $value = shell_exec("(host -t $type " . escapeshellarg($pre.$domain) . " | grep -q 'is an alias for') && echo \"\" || dig " . escapeshellarg($pre.$domain) . " $type +short | sort -n");
        if ($type === "cname") {
            $value = shell_exec("host -t cname " . escapeshellarg($pre.$domain) . " | grep 'alias for' | awk '{print \$NF}'");
        }
        $value = trim($value ?? "");
        if (!$value) {
            continue;
        }

        // Si es SOA
        if ($type === "soa") {
            $record_value = explode(" ", $value);
            if (count($record_value) >= 7) {
                $setName = ($name === "") ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(
                    Factory::Soa(
                        $record_value[0],
                        $record_value[1],
                        $record_value[2],
                        $record_value[3],
                        $record_value[4],
                        $record_value[5],
                        $record_value[6]
                    )
                );
                $zone->addResourceRecord($rr);
            }
            continue;
        }

        // Si es NS
        if ($type === "ns") {
            $record_values = explode("\n", $value);
            foreach ($record_values as $rv) {
                $setName = ($name === "") ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Ns($rv));
                $zone->addResourceRecord($rr);
            }
            continue;
        }

        // Verificamos si A en realidad es CNAME
        if ($type === "a" && preg_match("/[a-z]/i", $value)) {
            $type  = "cname";
            $value = shell_exec("dig " . escapeshellarg($pre.$domain) . " $type +short | sort -n");
            $value = trim($value ?? "");
            if (!$value) {
                continue;
            }
        }

        // A
        if ($type === "a") {
            $record_values = explode("\n", $value);
            $setName = ($name === "") ? "@" : $name;
            if ($name === "*") {
                $wildcard_a = $record_values;
            }
            foreach ($record_values as $rv) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::A($rv));
                $zone->addResourceRecord($rr);
            }
        }

        // CNAME
        if ($type === "cname") {
            if ($name === "*") {
                $wildcard_cname = $value;
                continue;
            }
            // Observa que en tu código original pones: empty($name)?$domain:$name
            // Lo mantenemos
            $setName = empty($name) ? $domain : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rr);
        }

        // SRV
        if ($type === "srv") {
            $record_values = explode(" ", $value);
            if (count($record_values) === 4) {
                $setName = ($name === "") ? "@" : $name;
                $rr      = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(
                    Factory::Srv(
                        $record_values[0],
                        $record_values[1],
                        $record_values[2],
                        $record_values[3]
                    )
                );
                $zone->addResourceRecord($rr);
            }
        }

        // MX
        if ($type === "mx") {
            $setName       = ($name === "") ? "@" : $name;
            $record_values = explode("\n", $value);
            usort($record_values, function ($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach ($record_values as $rv) {
                $mx_parts = explode(" ", $rv);
                if (count($mx_parts) === 2) {
                    $mx_priority = $mx_parts[0];
                    $mx_target   = $mx_parts[1];
                    $rr          = new ResourceRecord;
                    $rr->setName($setName);
                    $rr->setRdata(Factory::Mx($mx_priority, $mx_target));
                    $zone->addResourceRecord($rr);
                }
            }
        }

        // TXT
        if ($type === "txt") {
            $record_values = explode("\n", $value);
            $setName       = ($name === "") ? "@" : $name;
            foreach ($record_values as $rv) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setClass('IN');
                $rr->setRdata(Factory::Txt(trim($rv, '"'), 0, 200));
                $zone->addResourceRecord($rr);
            }
        }

        // Guardamos en array final
        $dns_records[] = [
            "type"  => $type,
            "name"  => $name,
            "value" => $value
        ];
    }

    // HTTP HEADERS
    $curl_response = shell_exec("curl -sLI " . escapeshellarg($domain) . " | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
    $lines = explode("\n", trim($curl_response ?? ""));
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

    // Construimos la salida final
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    echo json_encode([
        "whois"        => $whois,        // array de resultados parseados (o vacío)
        "http_headers" => $http_headers, 
        "dns_records"  => $dns_records,
        "ip_lookup"    => $ip_lookup,
        "errors"       => $errors,       // array de advertencias ("Skipping subdomain", "Domain not found", etc.)
        "zone"         => $builder->build($zone)
    ]);
    die();
}

run();

?><!DOCTYPE html>
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
            label="Domain"
            v-model="domain"
            spellcheck="false"
            @keydown.enter="lookupDomain()"
            class="mt-5 mx-auto"
          >
            <template v-slot:append-inner>
              <v-btn
                variant="flat"
                color="primary"
                @click="lookupDomain()"
                :loading="loading"
              >
                Lookup
                <template v-slot:loader>
                  <v-progress-circular
                    :size="22"
                    :width="2"
                    color="white"
                    indeterminate
                  ></v-progress-circular>
                </template>
              </v-btn>
            </template>
          </v-text-field>
          
          <!-- Mostramos errores -->
          <v-alert
            type="warning"
            v-for="error in response.errors"
            class="mb-3"
            :key="error"
            v-html="error"
          ></v-alert>

          <v-row v-if="response.whois && response.whois.length">
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
                        <tr v-for="(row, i) in response.whois" :key="i">
                          <td>{{ row.name }}</td>
                          <td>{{ row.value }}</td>
                        </tr>
                      </tbody>
                    </template>
                  </v-table>
                </v-card-text>
              </v-card>

              <v-card class="mt-5" variant="outlined" color="primary">
                <v-card-title>IP information</v-card-title>
                <v-card-text>
                  <template v-for="(rows, ip) in response.ip_lookup" :key="ip">
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
                          <tr
                            v-for="(line, idx) in rows.split('\\n')"
                            :key="idx"
                          >
                            <td>{{ line.split(':')[0] }}</td>
                            <td>{{ line.split(':')[1] }}</td>
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
                        <tr
                          v-for="(val, key) in response.http_headers"
                          :key="key"
                        >
                          <td>{{ val }}</td>
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
                        <tr
                          v-for="(record, idx) in response.dns_records"
                          :key="idx"
                        >
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

        <!-- Snackbar para copiar -->
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
                response: {
                    whois: [],
                    errors: [],
                    dns_records: [],
                    ip_lookup: {},
                    http_headers: {},
                    zone: ""
                }
            }
        },
        methods: {
            lookupDomain() {
                this.loading = true;
                this.domain = this.extractHostname(this.domain);
                fetch("?domain=" + this.domain)
                    .then(res => res.json())
                    .then(data => {
                        this.loading = false;
                        this.response = data;
                        Prism.highlightAll();
                    })
                    .catch(err => {
                        this.loading = false;
                        console.error(err);
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