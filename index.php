<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Función auxiliar para extraer la parte 'registrable' del dominio.
 *
 * Ejemplos:
 *   - sub.example.com -> example.com
 *   - www.ejemplo.org -> ejemplo.org
 *   - example.com     -> example.com
 */
function getRegistrableDomain($domain) {
    // Manejo de IDN (dominios con tildes o caracteres no ASCII)
    if (function_exists('idn_to_ascii')) {
        $domain = idn_to_ascii($domain);
    }
    $parts = explode('.', $domain);
    $count = count($parts);
    // Si tiene 2 partes o menos, se asume que ya es un dominio base.
    if ($count <= 2) {
        return $domain;
    }
    // Retorna las dos últimas partes, por ejemplo "example.com"
    return $parts[$count - 2] . '.' . $parts[$count - 1];
}

/**
 * Formatea registros TXT largos en múltiples líneas.
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

    // Dominio completo (subdominio o no)
    $fullDomain    = $_REQUEST['domain'];  
    $errors        = [];
    $ip_lookup     = [];
    $dns_records   = [];
    $required_bins = ["whois", "dig", "host"];

    // Verificación de binarios requeridos
    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Determinamos el dominio base
    $baseDomain = getRegistrableDomain($fullDomain);
    if (!filter_var($baseDomain, FILTER_VALIDATE_DOMAIN)) {
        $errors[] = "Invalid domain (baseDomain).";
    }
    if (filter_var($baseDomain, FILTER_VALIDATE_DOMAIN) && strpos($baseDomain, '.') === false) {
        $errors[] = "Invalid domain (missing dot).";
    }
    if (strlen($baseDomain) < 4) {
        $errors[] = "No domain name is that short.";
    }
    if (strlen($baseDomain) > 80) {
        $errors[] = "Too long.";
    }
    if (count($errors) > 0) {
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    // Construimos la zona usando el dominio completo (subdominio)
    // Si prefieres usar el dominio base, usa en su lugar: new Zone($baseDomain . '.');
    $zone = new Zone(rtrim($fullDomain, ".") . ".");
    $zone->setDefaultTtl(3600);

    // WHOIS sobre el dominio base
    $whois = shell_exec("whois $baseDomain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'");
    $whois = empty($whois) ? "" : trim($whois);

    if (empty($whois)) {
        $errors[] = "Domain not found.";
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    // Parseo de WHOIS
    $whois = explode("\n", $whois);
    foreach ($whois as $key => $record) {
        $split  = explode(":", trim($record));
        $name   = trim($split[0]);
        $value  = trim($split[1] ?? "");
        if ($name == "Name Server" || $name == "Domain Name") {
            $value = strtolower($value);
        }
        $whois[$key] = ["name" => $name, "value" => $value];
    }
    $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    $col_name  = array_column($whois, 'name');
    $col_value = array_column($whois, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);

    // Obtenemos IPs
    $ips = explode("\n", trim(shell_exec("dig $fullDomain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response           = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response           = empty($response) ? "" : trim($response);
        $ip_lookup[$ip]     = $response;
    }

    // Lista completa de registros a chequear
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

    // Consultas DNS por cada registro
    foreach ($records_to_check as $record) {
        $type = key($record);
        $name = $record[$type];
        $pre  = !empty($name) ? "{$name}." : "";

        $value = shell_exec("(host -t $type $pre$fullDomain | grep -q 'is an alias for') && echo \"\" || dig $pre$fullDomain $type +short | sort -n");
        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$fullDomain | grep 'alias for' | awk '{print \$NF}'");
        }
        $value = empty($value) ? "" : trim($value);
        if (empty($value)) {
            continue;
        }

        if ($type == "soa") {
            $record_value = explode(" ", $value);
            $setName      = empty($name) ? "@" : $name;
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
            continue;
        }

        if ($type == "ns") {
            $record_values = explode("\n", $value);
            foreach ($record_values as $record_value) {
                $setName = empty($name) ? "@" : $name;
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($rr);
            }
            continue;
        }

        // Verificar si la respuesta "A" en realidad era un CNAME
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            $type  = "cname";
            $value = shell_exec("dig $pre$fullDomain $type +short | sort -n");
            $value = empty($value) ? "" : trim($value);
            if (empty($value)) {
                continue;
            }
        }

        // A records
        if ($type == "a") {
            $record_values = explode("\n", $value);
            $setName       = empty($name) ? "@" : $name;
            foreach ($record_values as $record_value) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::A($record_value));
                $zone->addResourceRecord($rr);
            }
        }

        // CNAME
        if ($type == "cname") {
            $setName = empty($name) ? "@" : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rr);
        }

        // SRV
        if ($type == "srv") {
            $record_values = explode(" ", $value);
            if (count($record_values) != 4) {
                continue;
            }
            $setName = empty($name) ? "@" : $name;
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

        // MX
        if ($type == "mx") {
            $setName       = empty($name) ? "@" : $name;
            $record_values = explode("\n", $value);
            usort($record_values, function ($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach ($record_values as $record_value) {
                $record_value = explode(" ", $record_value);
                if (count($record_value) != 2) {
                    continue;
                }
                $mx_priority = $record_value[0];
                $mx_target   = $record_value[1];
                $rr          = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Mx($mx_priority, $mx_target));
                $zone->addResourceRecord($rr);
            }
        }

        // TXT
        if ($type == "txt") {
            $record_values = explode("\n", $value);
            $setName       = empty($name) ? "@" : $name;
            foreach ($record_values as $record_value) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setClass('IN');
                // Se eliminan comillas externas, si las hubiera
                $rr->setRdata(Factory::Txt(trim($record_value, '"'), 0, 200));
                $zone->addResourceRecord($rr);
            }
        }

        // Agregamos el registro al array para la respuesta JSON
        $dns_records[] = [
            "type"  => $type,
            "name"  => $name,
            "value" => $value
        ];
    }

    // Headers HTTP sobre el dominio completo
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

    // Construimos la salida final
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
            
            <v-alert
              type="warning"
              v-for="error in response.errors"
              class="mb-3"
              v-html="error"
            ></v-alert>
            
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
          // Quitamos protocolo y puertos
          this.domain = this.extractHostname(this.domain);
          
          fetch("?domain=" + this.domain)
            .then(response => response.json())
            .then(data => {
              this.loading = false;
              this.response = data;
            })
            .then(() => {
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
          let newBlob = new Blob([this.response.zone], { type: "text/dns" });
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