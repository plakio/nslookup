<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;
error_reporting(E_ALL & ~E_DEPRECATED);

/**
 * Manejo de registros TXT largos (más de 500 caracteres).
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
 * Extrae el dominio principal a partir de un subdominio.
 * Ejemplo:
 *   sub.example.co.uk => example.co.uk
 *   sub.example.com    => example.com
 * Ajusta la lógica si trabajas con TLDs especiales (.co.uk, .com.ar, etc.)
 */
function extractDomain($subdomain) {
    $parts = explode('.', $subdomain);
    $count = count($parts);

    // Ejemplo mínimo: tomamos las últimas 2 partes siempre
    // (Ajustar según sea necesario para TLDs más complejos)
    if ($count > 2) {
        return implode('.', array_slice($parts, $count - 2));
    }
    return $subdomain;
}

function run() {

    if (!isset($_REQUEST['domain'])) {
        return;
    }

    $domain        = $_REQUEST['domain'];
    $errors        = [];
    $ip_lookup     = [];
    $dns_records   = [];
    $required_bins = ["whois", "dig", "host"];

    // 1) Verificar que existan los comandos whois, dig, host
    foreach ($required_bins as $bin) {
        $output     = null;
        $return_var = null;
        exec("command -v $bin", $output, $return_var);
        if ($return_var != 0) {
            $errors[] = "Required command \"$bin\" is not installed.";
        }
    }

    // 2) Validaciones mínimas del dominio
    if (!filter_var($domain, FILTER_VALIDATE_DOMAIN)) {
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

    // 3) Creamos la zona DNS
    $zone = new Zone($domain . ".");
    $zone->setDefaultTtl(3600);

    // 4) Extraer dominio principal
    $whois_domain = extractDomain($domain);

    // 5) WHOIS sin grep (salida completa)
    $whois_raw = shell_exec("whois $whois_domain");

    if (empty($whois_raw)) {
        $errors[] = "Could not get WHOIS data.";
        echo json_encode(["errors" => $errors]);
        die();
    }

    // 6) Verificar que no sea un caso de "NOT FOUND" real del dominio principal
    //    Buscamos evidencia de que el dominio principal está registrado
    $foundDomainData = false;
    if (preg_match('/Domain Name:\s?' . preg_quote($whois_domain, '/') . '/i', $whois_raw)) {
        $foundDomainData = true;
    } elseif (preg_match('/Registry Domain ID:/i', $whois_raw)) {
        $foundDomainData = true;
    }

    // Si no hay evidencia del dominio, y detectamos "No match" etc., lo marcamos como "Domain not found."
    if (!$foundDomainData) {
        if (stripos($whois_raw, "No match") !== false
            || stripos($whois_raw, "NOT FOUND") !== false
            || stripos($whois_raw, "no entries found") !== false) {
            $errors[] = "Domain not found. (No valid domain data in WHOIS for $whois_domain)";
            echo json_encode(["errors" => $errors]);
            die();
        }
    }

    // 7) Filtrar las líneas relevantes en PHP
    $lines = explode("\n", $whois_raw);
    $whois_filtered = [];
    foreach ($lines as $line) {
        if (preg_match('/(Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:|Domain Status:|Reseller)/i', $line)) {
            $whois_filtered[] = trim($line);
        }
    }
    // Si no hay nada filtrado, guardamos toda la salida
    if (empty($whois_filtered)) {
        $whois_filtered = $lines;
    }

    // 8) Procesamos WHOIS
    $whois_processed = [];
    foreach ($whois_filtered as $record) {
        $split = explode(":", $record, 2);
        $name  = trim($split[0] ?? '');
        $value = trim($split[1] ?? '');
        if ($name == "Name Server" || $name == "Domain Name") {
            $value = strtolower($value);
        }
        $whois_processed[] = ["name" => $name, "value" => $value];
    }
    // Quitamos duplicados y ordenamos
    $whois_processed = array_map("unserialize", array_unique(array_map("serialize", $whois_processed)));
    $col_name  = array_column($whois_processed, 'name');
    $col_value = array_column($whois_processed, 'value');
    array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois_processed);

    // 9) IP lookup
    $ips = explode("\n", trim(shell_exec("dig $domain +short")));
    foreach ($ips as $ip) {
        if (empty($ip)) {
            continue;
        }
        $response = shell_exec("whois $ip | grep -E 'NetName:|Organization:|OrgName:'");
        $response = empty($response) ? "" : trim($response);
        $ip_lookup[$ip] = $response;
    }

    // 10) Variables para wildcard
    $wildcard_cname = "";
    $wildcard_a     = "";

    // 11) Lista completa de registros a consultar (no reducida)
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

    // 12) Consulta DNS para cada registro
    foreach ($records_to_check as $record) {
        $pre  = "";
        $type = key($record);
        $name = $record[$type];
        if (!empty($name)) {
            $pre = "{$name}.";
        }

        // Verifica si el registro es un alias
        $value = shell_exec("(host -t $type $pre$domain | grep -q 'is an alias for') && echo \"\" || dig $pre$domain $type +short | sort -n");

        if ($type == "cname") {
            $value = shell_exec("host -t $type $pre$domain | grep 'alias for' | awk '{print \$NF}'");
        }

        $value = trim($value ?? "");
        if (empty($value)) {
            continue;
        }

        // Manejo de SOA
        if ($type == "soa") {
            $record_value = explode(" ", $value);
            $setName = empty($name) ? "@" : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Soa(
                $record_value[0],
                $record_value[1],
                $record_value[2],
                $record_value[3],
                $record_value[4],
                $record_value[5],
                $record_value[6]
            ));
            $zone->addResourceRecord($rr);
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
            continue;
        }

        // Si es A y devolvió texto, lo tomamos como CNAME
        if ($type == "a" && preg_match("/[a-z]/i", $value)) {
            $type  = "cname";
            $value = shell_exec("dig $pre$domain $type +short | sort -n");
            $value = trim($value ?? "");
            if (empty($value)) {
                continue;
            }
        }

        // Manejo de A
        if ($type == "a") {
            if ($name == "*") {
                $wildcard_a = $value;
            }
            $record_values = explode("\n", $value);
            $setName = empty($name) ? "@" : $name;
            foreach ($record_values as $rv) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::A($rv));
                $zone->addResourceRecord($rr);
            }
        }

        // Manejo de CNAME
        if ($type == "cname") {
            if ($name == "*") {
                $wildcard_cname = $value;
                continue;
            }
            $setName = empty($name) ? $domain : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Cname($value));
            $zone->addResourceRecord($rr);
        }

        // Ejemplo manejo SRV
        if ($type == "srv") {
            $record_values = explode(" ", $value);
            if (count($record_values) != 4) {
                continue;
            }
            $setName = empty($name) ? "@" : $name;
            $rr = new ResourceRecord;
            $rr->setName($setName);
            $rr->setRdata(Factory::Srv(
                $record_values[0],
                $record_values[1],
                $record_values[2],
                $record_values[3]
            ));
            $zone->addResourceRecord($rr);
        }

        // Ejemplo manejo MX
        if ($type == "mx") {
            $setName = empty($name) ? "@" : $name;
            $record_values = explode("\n", $value);
            usort($record_values, function($a, $b) {
                $a_value = explode(" ", $a);
                $b_value = explode(" ", $b);
                return (int)$a_value[0] - (int)$b_value[0];
            });
            foreach ($record_values as $rv) {
                $mx_parts = explode(" ", $rv);
                if (count($mx_parts) != 2) {
                    continue;
                }
                $mx_priority = $mx_parts[0];
                $mx_value    = $mx_parts[1];
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setRdata(Factory::Mx($mx_priority, $mx_value));
                $zone->addResourceRecord($rr);
            }
        }

        // Ejemplo manejo TXT
        if ($type == "txt") {
            $record_values = explode("\n", $value);
            $setName = empty($name) ? "@" : $name;
            foreach ($record_values as $rv) {
                $rr = new ResourceRecord;
                $rr->setName($setName);
                $rr->setClass('IN');
                $rr->setRdata(Factory::Txt(trim($rv, '"'), 0, 200));
                $zone->addResourceRecord($rr);
            }
        }

        // Agrega al array final
        $dns_records[] = ["type" => $type, "name" => $name, "value" => $value];
    }

    // 13) Encabezados HTTP
    $response = shell_exec("curl -sLI $domain | awk 'BEGIN{RS=\"\\r\\n\\r\\n\"}; END{print}'");
    $lines = explode("\n", trim($response));
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

    // 14) Construcción de la zona
    $builder = new AlignedBuilder();
    $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

    // 15) Respuesta final en JSON
    echo json_encode([
        "whois"        => $whois_processed,
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
    <title>WHOIS Lookup</title>
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
            <!-- El resto de tu interfaz con Vue y Vuetify -->
            <!-- Ajusta según tu proyecto -->
        </v-container>
      </v-main>
    </v-app>
  </div>
  <script src="prism.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vue@3.4.30/dist/vue.global.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@v3.7.6/dist/vuetify.min.js"></script>
  <script>
    // El JavaScript del frontend se queda igual al tuyo original,
    // solo ten en cuenta que llamarás a "?domain=<dominio>" como siempre.
  </script>
</body>
</html>