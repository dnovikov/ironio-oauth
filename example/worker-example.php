<?php

require_once './vendor/autoload.php';

$ini_data = parse_ini_file('./config-example.ini', true);
$payload = getPayload();

$ironio_oauth = new IronIoOAuth\IronIoOAuth($ini_data, $payload);

// Use that method because $payload can be an object or an url-encoded string.
$payload = $ironio_oauth->parsePayload($payload);

// Authorization has two stages. They both are handled by the single function.
$ironio_oauth->authorize();

// Check if second stage of authorization was successful.
if ($ironio_oauth->hasAccessToken()) {
    // Fire a callback.
    if ($json_string = $ironio_oauth->request('http://yoursite.com/ironio-callback')) {
        echo print_r($json_string, 1) . "\n";
    }
}
