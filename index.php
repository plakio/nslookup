<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

function specialTxtFormatter(Badcow\DNS\Rdata\TXT $rdata, int $padding): string {
    //If the text length is less than or equal to 50 characters, just return it unaltered.
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

function extractMainDomain($domain) {
    // Split the domain by dots
    $parts = explode('.', $domain);
    $partsCount = count($parts);
    
    // If we have more than 2 parts, take the last two parts
    // This handles cases like sub.example.com -> example.com
    if ($partsCount > 2) {
        // Special handling for country codes like .co.uk, .com.br
        $knownTlds = ['co.uk', 'com.br', 'co.jp', 'com.au', 'co.nz'];
        $lastTwoParts = $parts[$partsCount - 2] . '.' . $parts[$partsCount - 1];
        
        if (in_array($lastTwoParts, $knownTlds)) {
            // If it's a known TLD with three parts, return last three parts
            if ($partsCount > 3) {
                return $parts[$partsCount - 3] . '.' . $lastTwoParts;
            }
            return $domain;
        }
        
        return $parts[$partsCount - 2] . '.' . $parts[$partsCount - 1];
    }
    
    return $domain;
}

function run() {

    if ( ! isset( $_REQUEST['domain'] ) ) {
        return;
    }

    $domain        = $_REQUEST['domain'];
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

    if ( ! filter_var( $domain, FILTER_VALIDATE_DOMAIN ) ) {
        $errors[] = "Invalid domain.";
    }
    
    if ( filter_var( $domain, FILTER_VALIDATE_DOMAIN ) && strpos( $domain, '.') === false ) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($domain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($domain) > 80) {
        $errors[] = "Too long.";
    }

    if ( count( $errors ) > 0 ) {
        echo json_encode( [
            "errors" => $errors,
        ] );
        die();
    }

    // Extract main domain for WHOIS lookup
    $main_domain = extractMainDomain($domain);
    $is_subdomain = ($main_domain !== $domain);
    
    $bash_ip_lookup = <<<EOT
for ip in $( dig $domain +short ); do
    echo "Details on \$ip"
    whois \$ip | grep -E 'NetName:|Organization:|OrgName:'
done
EOT;

    // Initialize whois array
    $whois = [];

    // Only perform WHOIS lookup if it's not a subdomain
    if (!$is_subdomain) {
        // Use main domain for WHOIS lookup with more flexible pattern matching
        $whois_output = shell_exec("whois $main_domain");
        
        if (!empty($whois_output)) {
            // Define patterns to match common WHOIS fields
            $patterns = [
                'Name Server' => '/Name Server:?\s*([^\n]+)/i',
                'Registrar' => '/Registrar:?\s*([^\n]+)/i',
                'Domain Name' => '/Domain Name:?\s*([^\n]+)/i',
                'Updated Date' => '/Updated Date:?\s*([^\n]+)/i',
                'Creation Date' => '/Creation Date:?\s*([^\n]+)/i',
                'Registrar IANA ID' => '/Registrar IANA ID:?\s*([^\n]+)/i',
                'Domain Status' => '/Domain Status:?\s*([^\n]+)/i',
                'Reseller' => '/Reseller:?\s*([^\n]+)/i'
            ];

            foreach ($patterns as $field => $pattern) {
                if (preg_match_all($pattern, $whois_output, $matches)) {
                    foreach ($matches[1] as $value) {
                        $value = trim($value);
                        if ($field == "Name Server" || $field == "Domain Name") {
                            $value = strtolower($value);
                        }
                        $whois[] = [
                            "name" => $field,
                            "value" => $value
                        ];
                    }
                }
            }

            // Remove duplicates and sort
            $whois = array_map("unserialize", array_unique(array_map("serialize", $whois)));
            $col_name = array_column($whois, 'name');
            $col_value = array_column($whois, 'value');
            array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);
        }
    }

    // Validate domain exists by checking DNS records instead of WHOIS
    $dns_check = shell_exec("dig $domain +short");
    if (empty($dns_check) && empty($whois)) {
        $errors[] = "Domain or subdomain not found in DNS.";
        echo json_encode([
            "errors" => $errors,
        ]);
        die();
    }

    // Use full domain (including subdomain) for all other lookups
    $ips      = explode( "\n", trim( shell_exec( "dig $domain +short" ) ) );
    foreach ( $ips as $ip ) {
        if ( empty( $ip ) ) {
            continue;
        }
        $response           = shell_exec( "whois $ip | grep -E 'NetName:|Organization:|OrgName:'" );
        $response           = empty( $response ) ? "" : trim( $response );
        $ip_lookup[ "$ip" ] = $response;
    }

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
        $value = shell_exec( "(host -t $type $pre$domain | grep -q 'is an alias for') && echo \"\" || dig $pre$domain $type +short | sort -n" );
        if ( $type == "cname" ) {
            $value = shell_exec( "host -t $type $pre$domain | grep 'alias for' | awk '{print \$NF}'" );
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
            $record->setRdata(Factory::Soa($record_value[0],$record_value[1],$record_value[2],$record_value[3],$record_value[4],$record_value[5],$record_value[6]));
            $zone->addResourceRecord($record);
            continue;
        }
        if ( $type == "ns" ) {
            $record_values = explode( "\n", $value );
            foreach( $record_values as  $record_value ) {
                $setName = empty( $name ) ? "@" : $name;
                $record  = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::Ns($record_value));
                $zone->addResourceRecord($record);
            }
        }
        // Verify A record is not a CNAME record
        if(  $type == "a" && preg_match("/[a-z]/i", $value)){
            $type  = "cname";
            $value = shell_exec( "dig $pre$domain $type +short | sort -n" );
            $value = empty( $value ) ? "" : trim( $value );
            if ( empty( $value ) ) {
                continue;
            }
        }
        if ( $type == "a" ) {
            if ( ! empty( $wildcard_a ) && $wildcard_a == $record_values ) {
                continue;
            }
            if ( $name == "*" ) {
                $wildcard_a = $record_values;
            }
            $record_values = explode( "\n", $value );
            $setName       = empty( $name ) ? "@" : $name;
            foreach( $record_values as $record_value ) {
                $record    = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::A( $record_value ));
                $zone->addResourceRecord($record);
            }
        }
        if ( $type == "cname" ) {
            if ( $name == "*" ) {
                $wildcard_cname = $value;
                continue;
            }
            if ( ! empty( $wildcard_cname ) && $wildcard_cname == $value ) {
                continue;
            }
            $setName = empty( $name ) ? $domain : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($record);
        }
        if ( $type == "srv" ) {
            $record_values = explode( " ", $value );
            if ( count ( $record_values ) != "4" ) {
                continue;
            }
            $setName = empty( $name ) ? "@" : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Srv($record_values[0], $record_values[1], $record_values[2], $record_values[3]));
            $zone->addResourceRecord($record);
        }
        if ( $type == "mx" ) {
            $setName       = empty( $name ) ? "@" : $name;
            $record_values = explode( "\n", $value );
            usort($record_values, function ($a, $b) {
                $a_value = explode( " ", $a );
                $b_value = explode( " ", $b );
                return (int) $a_value[0] - (int) $b_value[0];
            });
            foreach( $record_values as $record_value ) {
                $record_value = explode( " ", $record_value );
                if ( count( $record_value ) != "2" ) {
                    continue;
                }
                $mx_priority  = $record_value[0];
                $mx_value     = $record_value[1];
                $record       = new ResourceRecord;
                $record->setName( $setName );
                $record->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($record);
            }
        }
        if ( $type == "txt" ) {
            $record_values = explode( "\n", $value );
            $setName       = empty( $name ) ? "@" : "$name";
            foreach( $record_values as $record_value ) {
                $record = new ResourceRecord;
                $record->setName( $setName );
                $record->setClass('IN');
                $record->setRdata(Factory::Txt(trim($record_value,'"'), 0, 200));
                $zone->addResourceRecord($record);
            }
        }
        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }

    $response = shell_exec( "curl -sLI $domain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'" );
    $lines    = explode("\n", trim( $response ) );
    $http_headers = [];
    foreach ($lines as $line) {
        // Trim whitespace from each line
        $line = trim($line);
        // Match key-value pairs (lines with a colon)
        if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
            $key = strtolower($matches[1]); // Use lowercase keys for consistency
            $value = $matches[2];
            // Handle duplicate keys (e.g., "vary" appears twice)
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
            <v-text-field variant="outlined" color="primary" label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()" class="mt-5 mx-auto">
            <template v-slot:append-inner>
                <v-btn variant="flat" color="primary" @click="lookupDomain()" :loading="loading">
                    Lookup
                    <template v-slot:loader><v-progress-circular :size="22" :width="2" color="white" indeterminate></v-progress-circular></template>
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
                    <th class="text-left">
                        Name
                    </th>
                    <th class="text-left">
                        Value
                    </th>
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
                        <th class="text-left">
                            Name
                        </th>
                        <th class="text-left">
                            Value
                        </th>
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
            </v-card>
            <v-card class="mt-5" variant="outlined" color="primary">
                <v-card-title>HTTP headers</v-card-title>
                <v-card-text>
                    <v-table density="compact">
                    <template v-slot:default>
                    <thead>
                        <tr>
                        <th class="text-left" style="min-width: 200px;">
                            Name
                        </th>
                        <th class="text-left">
                            Value
                        </th>
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
                    <th class="text-left">
                        Type
                    </th>
                    <th class="text-left">
                        Name
                    </th>
                    <th class="text-left">
                        Value
                    </th>
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
            </v-card>
            <v-card class="mt-5" variant="flat">
                <v-btn size="small" @click="copyZone()" class="position-absolute right-0 mt-6" style="margin-right: 140px;">
                  <v-icon left>mdi-content-copy</v-icon>
                </v-btn>
                <v-btn size="small" @click="downloadZone()" class="position-absolute right-0 mt-6 mr-4">
                  <v-icon left>mdi-download</v-icon>
                  Download
                </v-btn>
                <pre class="language-dns-zone-file text-body-2" style="border-radius:4px;border:0px"><code class="language-dns-zone-file">{{ response.zone }}</code></pre>
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
                this.loading = true
                this.domain = this.extractHostname( this.domain )
                fetch( "?domain=" + this.domain )
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false
                        this.response = data
                    })
                    .then( done => {
                        Prism.highlightAll()
                    })
            },
            extractHostname( url ) {
                var hostname;
                //find & remove protocol (http, ftp, etc.) and get hostname

                if (url.indexOf("//") > -1) {
                    hostname = url.split('/')[2];
                } else {
                    hostname = url.split('/')[0];
                }

                //find & remove port number
                hostname = hostname.split(':')[0];
                //find & remove "?"
                hostname = hostname.split('?')[0];

                return hostname;
            },
            downloadZone() {
                newBlob = new Blob([this.response.zone], {type: "text/dns"})
                this.$refs.download_zone.download = `${this.domain}.zone`;
                this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                this.$refs.download_zone.click();
            },
            copyZone() {
                navigator.clipboard.writeText( this.response.zone )
                this.snackbar.message = "Zone copied to clipboard"
                this.snackbar.show = true
            }
        }
    }).use(vuetify).mount('#app');
  </script>
</body>
</html>