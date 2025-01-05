<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
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
 * Función muy básica para obtener el dominio base (registrable) de un subdominio.
 * 
 * Ejemplo:
 *   getBaseDomain("sub.example.com") => "example.com"
 *   getBaseDomain("www.mi-dominio.net") => "mi-dominio.net"
 * 
 * ¡Esta función NO cubre casos de TLD complicados como .co.uk, .com.mx, etc.!
 */
function getBaseDomain(string $fullDomain): string {
    // Eliminamos http://, https:// o slashes, si los hubiera
    $fullDomain = preg_replace('/^https?:\/\//i', '', $fullDomain);
    $fullDomain = explode('/', $fullDomain)[0];

    // Dividimos en partes por el punto
    $parts = explode('.', $fullDomain);

    // Si tiene menos de 2 partes, devolvemos tal cual
    if (count($parts) < 2) {
        return $fullDomain;
    }

    // Tomamos las últimas dos partes: dominio y TLD
    $tld = array_pop($parts);
    $domain = array_pop($parts);
    return $domain . '.' . $tld;
}

function run() {

    if ( ! isset( $_REQUEST['domain'] ) ) {
        return;
    }

    // Aquí guardaremos el nombre ingresado por el usuario (que puede ser subdominio).
    $fullDomain = trim($_REQUEST['domain']);

    // Extraemos el dominio base para el whois.
    // Si alguien escribió "sub.dominio.com", $whoisDomain contendrá "dominio.com".
    $whoisDomain = getBaseDomain($fullDomain);

    $errors        = [];
    $ip_lookup     = [];
    $dns_records   = [];
    $required_bins = [ "whois", "dig", "host" ];

    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec( "command -v $bin", $output, $return_var );
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // Validamos lo que viene del formulario:
    // 1) Checamos que $fullDomain no sea demasiado largo/corto, etc.
    if ( ! filter_var( $fullDomain, FILTER_VALIDATE_DOMAIN ) ) {
        $errors[] = "Invalid domain.";
    }
    
    if ( filter_var( $fullDomain, FILTER_VALIDATE_DOMAIN ) && strpos( $fullDomain, '.') === false ) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($fullDomain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($fullDomain) > 80) {
        $errors[] = "Too long.";
    }

    if ( count( $errors ) > 0 ) {
        echo json_encode( [
            "errors" => $errors,
        ] );
        die();
    }

    // NOTA: Acá, para la parte de DNS, usaremos $fullDomain (sea subdominio o no).
    $zone = new Zone( $fullDomain ."." );
    $zone->setDefaultTtl(3600);

    // ----------------------------------------
    // WHOIS: se hará sobre el dominio base
    // ----------------------------------------
    // Ejemplo: si alguien puso "sub.dominio.com", el whois será:
    // whois dominio.com
    $whoisCommand = "whois $whoisDomain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:|Reseller:'";
    $whois = shell_exec($whoisCommand);
    $whois = empty( $whois ) ? "" : trim( $whois );

    if ( empty( $whois ) ) {
        $errors[] = "Domain not found (whois).";
        echo json_encode( [
            "errors" => $errors,
        ] );
        die();
    }

    $whois = explode( "\n", $whois );
    foreach( $whois as $key => $record ) {
        $split  = explode( ":", trim( $record ) );
        $name   = trim( $split[0] );
        $value  = trim( $split[1] ?? "" );
        if ( $name == "Name Server" || $name == "Domain Name"  ) {
            $value = strtolower( $value );
        }
        $whois[ $key ] = [ "name" => $name, "value" => $value ];
    }
    // Eliminamos duplicados
    $whois     = array_map("unserialize", array_unique(array_map("serialize", $whois)));
    $col_name  = array_column($whois, 'name');
    $col_value = array_column($whois, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);

    // ----------------------------------------
    // IP lookup: esto lo hacemos ya sobre $fullDomain
    // ----------------------------------------
    $ips = explode( "\n", trim( shell_exec( "dig $fullDomain +short" ) ) );
    foreach ( $ips as $ip ) {
        if ( empty( $ip ) ) {
            continue;
        }
        $response           = shell_exec( "whois $ip | grep -E 'NetName:|Organization:|OrgName:'" );
        $response           = empty( $response ) ? "" : trim( $response );
        $ip_lookup[ "$ip" ] = $response;
    }

    // ----------------------------------------
    // Búsqueda de registros DNS en $fullDomain
    // ----------------------------------------
    $wildcard_cname   = "";
    $wildcard_a       = "";
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

    foreach( $records_to_check as $record ) {
        $pre  = "";
        $type = key( $record );
        $name = $record[ $type ];
        if ( ! empty( $name ) ) {
            $pre = "{$name}.";
        }
        $value = shell_exec( "(host -t $type $pre$fullDomain | grep -q 'is an alias for') && echo \"\" || dig $pre$fullDomain $type +short | sort -n" );
        
        // Ajuste especial para cname:
        if ( $type == "cname" ) {
            $value = shell_exec( "host -t $type $pre$fullDomain | grep 'alias for' | awk '{print \$NF}'" );
        }
        $value = empty( $value ) ? "" : trim( $value );
        if ( empty( $value ) ) {
            continue;
        }

        if ( $type == "soa" ) {
            $record_value = explode( " ", $value );
            $setName = empty( $name ) ? "@" : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(
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
            $zone->addResourceRecord($record);
            continue;
        }

        if ( $type == "ns" ) {
            $record_values = explode( "\n", $value );
            foreach( $record_values as  $record_value ) {
                $setName = empty( $name ) ? "@" : $name;
                $rec  = new ResourceRecord;
                $rec->setName( $setName );
                $rec->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($rec);
            }
        }

        // Verificamos si es en realidad un CNAME
        if(  $type == "a" && preg_match("/[a-z]/i", $value)){
            $type  = "cname";
            $value = shell_exec( "dig $pre$fullDomain $type +short | sort -n" );
            $value = empty( $value ) ? "" : trim( $value );
            if ( empty( $value ) ) {
                continue;
            }
        }

        if ( $type == "a" ) {
            $record_values = explode( "\n", $value );
            if ( $name == "*" ) {
                // Manejo de wildcard A
                $wildcard_a = $record_values;
            }
            $setName = empty( $name ) ? "@" : $name;
            foreach( $record_values as $record_value ) {
                $rec = new ResourceRecord;
                $rec->setName( $setName );
                $rec->setRdata(Factory::A($record_value));
                $zone->addResourceRecord($rec);
            }
        }

        if ( $type == "cname" ) {
            if ( $name == "*" ) {
                $wildcard_cname = $value;
                continue;
            }
            $setName = empty( $name ) ? $fullDomain : $name;
            $rec  = new ResourceRecord;
            $rec->setName( $setName );
            $rec->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rec);
        }

        if ( $type == "srv" ) {
            $record_values = explode( " ", $value );
            if ( count ( $record_values ) != 4 ) {
                continue;
            }
            $setName = empty( $name ) ? "@" : $name;
            $rec  = new ResourceRecord;
            $rec->setName( $setName );
            $rec->setRdata(Factory::Srv($record_values[0], $record_values[1], $record_values[2], $record_values[3]));
            $zone->addResourceRecord($rec);
        }

        if ( $type == "mx" ) {
            $setName       = empty( $name ) ? "@" : $name;
            $record_values = explode( "\n", $value );
            usort($record_values, function ($a, $b) {
                $a_value = explode( " ", $a );
                $b_value = explode( " ", $b );
                return (int) $a_value[0] - (int) $b_value[0];
            });
            foreach( $record_values as $rv ) {
                $record_value = explode( " ", $rv );
                if ( count( $record_value ) != 2 ) {
                    continue;
                }
                $mx_priority  = $record_value[0];
                $mx_value     = $record_value[1];
                $rec       = new ResourceRecord;
                $rec->setName( $setName );
                $rec->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($rec);
            }
        }

        if ( $type == "txt" ) {
            $record_values = explode( "\n", $value );
            $setName       = empty( $name ) ? "@" : "$name";
            foreach( $record_values as $rv ) {
                // Eliminamos comillas al inicio/fin
                $rvTrimmed = trim($rv, '"');
                $rec = new ResourceRecord;
                $rec->setName( $setName );
                $rec->setClass('IN');
                $rec->setRdata(Factory::Txt($rvTrimmed, 0, 200));
                $zone->addResourceRecord($rec);
            }
        }

        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }

    // ----------------------------------------
    // HTTP headers: Se hacen sobre $fullDomain
    // ----------------------------------------
    $response = shell_exec( "curl -sLI $fullDomain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'" );
    $lines    = explode("\n", trim( $response ) );
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

    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    echo json_encode( [
        "whois"        => $whois,         // WHOIS del dominio base
        "http_headers" => $http_headers,  // Headers del subdominio
        "dns_records"  => $dns_records,   // DNS del subdominio
        "ip_lookup"    => $ip_lookup,     // IP lookup del subdominio
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
            <v-text-field variant="outlined" color="primary" label="Dominio o subdominio" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()" class="mt-5 mx-auto">
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
                        <v-card-title>Whois (dominio base)</v-card-title>
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
                                                <td>{{ row.split( ":" )[0] }}</td>
                                                <td>{{ row.split( ":" )[1] }}</td>
                                            </tr>
                                        </tbody>
                                    </template>
                                </v-table>
                            </template>
                        </v-card-text>
                    </v-card>

                    <v-card class="mt-5" variant="outlined" color="primary">
                        <v-card-title>HTTP headers (subdominio o dominio)</v-card-title>
                        <v-card-text>
                            <v-table density="compact">
                                <template v-slot:default>
                                    <thead>
                                        <tr>
                                            <th class="text-left" style="min-width: 200px;">
                                                Header
                                            </th>
                                            <th class="text-left">
                                                Valor
                                            </th>
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
                        <v-card-title>Common DNS records (subdominio o dominio)</v-card-title>
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
                fetch("?domain=" + encodeURIComponent(this.domain))
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false;
                        this.response = data;
                    })
                    .then( () => {
                        // Resaltamos el bloque de zone con Prism
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
                navigator.clipboard.writeText( this.response.zone );
                this.snackbar.message = "Zone copied to clipboard";
                this.snackbar.show = true;
            }
        }
    }).use(vuetify).mount('#app');
  </script>
</body>
</html>