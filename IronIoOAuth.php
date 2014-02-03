<?php

namespace IronIoOAuth;

use OAuth\ServiceFactory;
use OAuth\Common\Http\Uri;
use OAuth\Common\Storage\Session;
use OAuth\Common\Consumer\Credentials;

/**
 * A wrapper around lusitanian\OAuth class,
 * which (I believe) makes Iron.Io workers authorization easier.
 * 
 * @author dnovikov
 *
 */
class IronIoOAuth {

    private $service = null;

    private $environment = null;

    private $ini_data = array();

    private $payload = null;

    private $authorization_code = null;

    /**
     * Create and configure OAuth service object.
     * 
     * @param array $ini_data
     * @param object $payload
     * @throws ErrorException
     */
    public function __construct($ini_data, $payload) {
        $payload = $this->parsePayload($payload);

        $this->environment = $payload->env;
        $this->ini_data = $ini_data;
        
        if (!isset($this->ini_data[$this->environment])) {
            throw new ErrorException("No configuration data found for this environment: {$this->environment}\n");
        }

        if (isset($payload->authorization_code)) {
            $this->authorization_code = $payload->authorization_code;
        }

        $service_factory = new \OAuth\ServiceFactory();
        $session_storage = new Session();

        // Iron.io callback URL.
        // That will be used to pass authorization code back to the worker.
        $webhook_url = 'https://worker-aws-us-east-1.iron.io/2/projects/'
            . $this->getIniData('project_id')
            . '/tasks/webhook?code_name='
            . $this->getIniData('worker_name')
            . '&oauth=' . $this->getIniData('token')
            . '&env=' . $this->environment;

        // Setup credentials for OAuth requests.
        $credentials = new Credentials(
            $this->getIniData('username'),
            $this->getIniData('password'),
            $webhook_url
        );

        $api_uri = new Uri\Uri($this->getIniData('api_uri'));

        $this->service = $service_factory->createService(
            'IronIoOAuthService',
            $credentials,
            $session_storage,
            array(),
            $api_uri
        );

        $this->service->setAuthorizationEndpoint($this->getIniData('oauth_auth_endpoint'));
        $this->service->setAccessTokenEndpoint($this->getIniData('oauth_token_endpoint'));
    }

    /**
     * Try to get variable from the ini_data array.
     * 
     * @param string $var_name
     * @throws ErrorException
     */
    private function getIniData($var_name) {
        if (!isset($this->ini_data[$this->environment][$var_name])
            && !isset($this->ini_data[$var_name])) {
            throw new \ErrorException('ini_data variable "' . $var_name . '" not found.');
        }

        return isset($this->ini_data[$this->environment][$var_name])
                ? $this->ini_data[$this->environment][$var_name]
                : $this->ini_data[$var_name];
    }

    /**
     * Check if worker was called via webhook and try to parse input.
     * 
     * @param string|object $payload
     * @throws ErrorException
     */
    public function parsePayload($payload) {
        if (is_string($payload)) {
            $post = array();
            parse_str($payload, $post);
            if (empty($post)) {
                throw new ErrorException('Cannot parse payload string.');
            }
            $payload = new \stdClass();
            if (isset($post['env'])) {
                $payload->env = $post['env'];
            }

            if (isset($post['code'])) {
                $payload->authorization_code = $post['code'];
            }
        }

        if (!is_object($payload) || !property_exists($payload, 'env')) {
            throw new ErrorException("Payload 'env' property is not specified.\n" . print_r($payload, 1) . "\n");
        }

        return $payload;
    }


    /**
     * Check if authorization code is already set.
     */
    public function hasAuthorizationCode() {
        return (bool) (
            is_string($this->authorization_code)
            && !empty($this->authorization_code)
        );
    }

    /**
     * Check if access token is already set.
     */
    public function hasAccessToken() {
        $storage = $this->service->getStorage();
        return $storage->hasAccessToken($this->service->service());
    }

    /**
     * Get access token.
     */
    public function getAccessToken() {
        $storage = $this->service->getStorage();
        return $storage->retrieveAccessToken($this->service->service())->getAccessToken();
    }

    /**
     * Run authorization code request.
     */
    public function requestAuthorizationCode() {
        if ($this->hasAuthorizationCode()) {
            return;
        }

        $url = $this->service->getAuthorizationUri(array('state' => 'DCEEFWF45453sdffef424'));

        $curl_options = array(
            CURLOPT_URL => $url,
            CURLOPT_FOLLOWLOCATION => true,
        );

        $ch = curl_init();
        curl_setopt_array($ch, $curl_options);
        curl_exec($ch);
        curl_close($ch);
    }

    /**
     * Request access token.
     */
    public function requestAccessToken() {
        if (!$this->hasAccessToken() && $this->hasAuthorizationCode()) {
            $this->service->requestAccessToken($this->authorization_code);
        }
    }

    /**
     * Return IronIoOAuthService service object.
     */
    public function getService() {
        return $this->service;
    }

    /**
     * Do actual request to server.
     * 
     * @param string $url
     */
    public function request($url) {
        if (!$this->hasAccessToken()) {
            throw new ErrorException('We do not have an access token to make a request.');
        }

        return $this->service->request($url);
    }

    /**
     * Authorize against service provider.
     */
    public function authorize() {
        $this->requestAuthorizationCode();
        $this->requestAccessToken();
    }

}
