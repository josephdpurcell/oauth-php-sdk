<?php
/**
 * OAuth
 *
 * The base OAuth file modeled after Facebook's PHP SDK. The goal of this file is to:
 *
 *      - make OAuth easy to use
 *      - sever as a base for most major OAuth providers
 *
 * Supported OAuth Providers:
 *
 *      - Twitter
 *      - Netflix
 *
 * OAuth Version Support: 1.0 (hopefully 2.0 to come soon)
 *
 * Requires cookie support (for session).
 *
 * OAuth.php must also be included for this file to work.
 *
 * If anyone knows anything about licensing and would like to adivse me on how
 * to license this file, please email me at: josephdpurcell@gmail.com.
 *
 * The oauth_utilities.php file came from:
 * http://oauth.googlecode.com/svn/code/php/OAuth.php
 *
 * @author Joseph D. Purcell <josephdpurcell@gmail.com>
 * @package OAuth_PHP_SDK
 * @version 1.0
 */

if (!class_exists('OAuthUtil')) {
    require_once('oauth_utilities.php');
}

class OAuth
{
    protected $authorized = false;

    protected $consumer_key;
    protected $consumer_secret;

    protected $request_token;
    protected $request_token_secret;
    protected $request_token_verifier;
    protected $request_token_response;

    protected $access_token;
    protected $access_token_secret;
    protected $access_token_response;

    public $request_token_url;
    public $request_token_method;
    public $request_token_params;
    public $access_token_url;
    public $access_token_method;
    public $access_token_params;
    public $authorize_url;
    public $authorize_method;
    public $authorize_params;
    //public $authorize_callback;

    public $service;
    public $cookie = true;
    public $autocapture = false;

    function __construct ($params) {
        if (empty($params['consumer_key']) || empty($params['consumer_secret'])) {
            throw new Exception('Missing consumer key or secret.');
        }

        if (isset($params['service'])) {
            $this->service = $params['service'];
        }

        $this->consumer_key = $params['consumer_key'];
        $this->consumer_secret = $params['consumer_secret'];

        if (isset($params['autocapture'])) {
            $this->autocapture = $params['autocapture'];
        }

        if (isset($params['access_token'])) {
            $this->access_token = $params['access_token'];
        }

        if (isset($params['access_token'])) {
            $this->access_token_secret = $params['access_token_secret'];
        }

        /*
        if (isset($params['authorize_callback'])) {
            $this->authorize_callback = $params['authorize_callback'];
        }
        */

        if ($this->service=='netflix') {
            $this->api_url = 'http://api.netflix.com/';
            $this->request_token_url = 'http://api.netflix.com/oauth/request_token';
            $this->request_token_method = 'GET';
            $this->access_token_url = 'http://api.netflix.com/oauth/access_token';
            $this->access_token_params = array(
                    'request_token'=>'oauth_token'
                    );
            $this->access_token_method = 'GET';
            $this->authorize_url = 'https://api-user.netflix.com/oauth/login';
            $this->authorize_params = array(
                    'application_name',
                    'consumer_key'=>'oauth_consumer_key',
                    'request_token'=>'oauth_token',
                    'redirect_url'=>'oauth_callback'
                    );
        } else if ($this->service=='twitter') {
            $this->api_url = 'http://api.twitter.com/1/';
            $this->request_token_url = 'https://api.twitter.com/oauth/request_token';
            $this->request_token_method = 'POST';
            $this->request_token_params = array(
                    'redirect_url'=>'oauth_callback'
                    );
            $this->authorize_url = 'https://api.twitter.com/oauth/authorize';
            $this->authorize_params = array(
                    'request_token'=>'oauth_token'
                    );
            $this->access_token_url = 'https://api.twitter.com/oauth/access_token';
            $this->access_token_method = 'POST';
            $this->access_token_params = array(
                    'request_token_verifier'=>'oauth_token'
                    );
        } else {
            $this->api_url = $params['api_url'];
            $this->request_token_url = $params['request_token_url'];
            $this->request_token_method = $params['request_token_method'];
            $this->authorize_url = $params['authorize_url'];
            $this->authorize_params = $params['authorize_params'];
            $this->access_token_url = $params['access_token_url'];
            $this->access_token_method = $params['access_token_method'];
        }

        // load request token
        if (empty($this->request_token) && isset($_SESSION['phpoauth_request_token'])) {
            $this->request_token = $_SESSION['phpoauth_request_token'];
            $this->request_token_secret = $_SESSION['phpoauth_request_token_secret'];
        }

        // load access token
        if (empty($this->access_token) && isset($_SESSION['phpoauth_access_token'])) {
            $this->access_token = $_SESSION['phpoauth_access_token'];
            $this->access_token_secret = $_SESSION['phpoauth_access_token_secret'];
        }

        // load request response
        if (empty($this->request_token_response) && isset($_SESSION['phpoauth_request_token_response'])) {
            $this->request_token_response = $_SESSION['phpoauth_request_token_response'];
        }

        // load access response
        if (empty($this->access_token_response) && isset($_SESSION['phpoauth_access_token_response'])) {
            $this->access_token_response = $_SESSION['phpoauth_access_token_response'];
            $this->access_token = isset($_SESSION['phpoauth_access_token_response']['oauth_token']) ? $_SESSION['phpoauth_access_token_response']['oauth_token'] : null;
            $this->access_token_secret = isset($_SESSION['phpoauth_access_token_response']['oauth_token_secret']) ? $_SESSION['phpoauth_access_token_response']['oauth_token_secret'] : null;
        }

        // grab access token
        if ($this->autocapture && !empty($_GET)) {
            $this->capture_access_token();
        }

        if (!empty($this->access_token)) {
            $this->authorized=true;
        }
    }

    function set_access_token($access_token) {
        $this->access_token = $access_token;
    }

    function set_access_token_secret($access_token_secret) {
        $this->access_token_secret = $access_token_secret;
    }

    function is_authorized() {
        return $this->authorized;
    }

    /**
     * @param array $params The params to use for the request token request
     */
    function get_login_url($params=null) {
        // unset vars
        $this->reset_tokens();

        $this->fetch_request_token($params);
        $authorize_params = array();
        if (!is_array($this->authorize_params)) {
            $this->authorize_params = explode(',',$this->authorize_params);
        }
        foreach ($this->authorize_params as $key=>$param) {
            if (!is_int($key)) {
                // map from key to param
                if (isset($this->$key)) {
                    $authorize_params[$param] = $this->$key;
                } else if (isset($this->request_token_response[$key])) {
                    $authorize_params[$param] = $this->request_token_response[$key];
                } else if (isset($params[$key])) {
                    $authorize_params[$param] = $params[$key];
                } else {
                    $authorize_params[$param] = '';
                }
            } else {
                if (isset($this->$param)) {
                    $authorize_params[$param] = $this->$param;
                } else if (isset($this->request_token_response[$param])) {
                    $authorize_params[$param] = $this->request_token_response[$param];
                } else {
                    $authorize_params[$param] = '';
                }
            }
        }
        return $this->authorize_url.'?'.http_build_query($authorize_params);
    }

    function get_request_token() {
        if (is_null($this->request_token)) {
            $this->fetch_request_token();
        }
        return $this->request_token;
    }

    function get_request_token_secret() {
        if (is_null($this->request_token_secret)) {
            throw new Exception('Request token is not set. Be sure to call the get_request_token function first.');
        }
        return $this->request_token_secret;
    }

    /**
     * @param string $callback The callback URL to use in the authorization step
     */
    function fetch_request_token($params=null) {
        // set request token params
        if (!empty($this->request_token_params)) {
            if (!is_null($params)) {
                $request_params = array();
                if (!is_array($this->request_token_params)) {
                    $this->request_token_params = explode(',',$this->request_token_params);
                }
                foreach ($this->request_token_params as $key=>$param) {
                    if (isset($params[$key])) {
                        $request_params[$param]=$params[$key];
                    } else if (isset($this->$param)) {
                        $request_params[$param]=$this->$param;
                    } else if (isset($this->$key)) {
                        $request_params[$param]=$this->$key;
                    }
                }
                $this->request_token_params = http_build_query($request_params);
            } else {
                $this->request_token_params=array();
            }
        }

        $resp = $this->api( $this->request_token_url, $this->request_token_method, $this->request_token_params, false );

        $resp = OAuthUtil::parse_parameters($resp);

        $this->request_token_response = $resp;
        $_SESSION['phpoauth_request_token_response']= $resp;

        if (isset($resp['oauth_token'])) {
            $this->request_token = $resp['oauth_token'];
            $this->request_token_secret = $resp['oauth_token_secret'];
            $_SESSION['phpoauth_request_token'] = $resp['oauth_token'];
            $_SESSION['phpoauth_request_token_secret'] = $resp['oauth_token_secret'];
        } else {
            // error
        }

        return $resp;
    }

    function get_access_token() {
        if (is_null($this->access_token)) {
            $this->fetch_access_token();
        }
        return $this->access_token;
    }

    function get_access_token_secret() {
        if (is_null($this->access_token)) {
            throw new Exception('Access token is not set. Be sure to call the get_access_token function first.');
        }
        return $this->access_token_secret;
    }

    function fetch_access_token() {
        // format params
        $params = array();
        if (!is_array($this->access_token_params)) {
            $this->access_token_params = explode(',',$this->access_token_params);
        }
        foreach ($this->access_token_params as $key=>$param) {
            if (isset($this->$param)) {
                $params[$param]=$this->$param;
            } else if (isset($this->$key)) {
                $params[$param]=$this->$key;
            } else if (isset($this->access_token_response[$param])) {
                $params[$param]=$this->access_token_response[$param];
            } else if (isset($this->access_token_response[$key])) {
                $params[$param]=$this->access_token_response[$key];
            } else {
                $params[$param]='';
            }
        }
        $params = http_build_query($params);

        $resp = $this->api( $this->access_token_url, $this->access_token_method, $params, false );

        $resp = OAuthUtil::parse_parameters($resp);

        $this->access_token_response = $resp;
        $_SESSION['phpoauth_access_token_response']= $resp;

        if (isset($resp['oauth_token'])) {
            $this->access_token = $resp['oauth_token'];
            $this->access_token_secret = $resp['oauth_token_secret'];
            $_SESSION['phpoauth_access_token'] = $resp['oauth_token'];
            $_SESSION['phpoauth_access_token_secret'] = $resp['oauth_token_secret'];
        } else {
            // error
        }

        return $resp;
    }

    /**
     * api
     *
     * Makes API calls to the given URL with params by the
     * method specified.
     *
     * @param string $url The URL or endpoint to make a request to
     * @param string $method The HTTP method
     * @param string|array $params Parameters to send (GET or POST)
     * @param bool $auth Require authentication before making the request
     * @param bool $execute Execute the request, else return the signed URL
     *
     * @return array Response of data, else false if network fail
     */
    function api( $url, $method='GET', $params='', $auth=true, $execute = true ) {
        // authorize if not and force auth is true
        if ( !$this->authorized && $auth==true ){
            return false;
        }
        // user is authorized
        else {
            // VALIDATE INPUT
            if ($method!="POST" && $method!="GET" && $method!="MOVE" && $method!="DELETE") {
                return false;
            }

            $url = $this->get_hydrated_url($url);

            // construct objects the signing function needs
            $consumer = new OAuthConsumer( $this->consumer_key, $this->consumer_secret );
            if( $this->access_token ){
                $token = new OAuthToken( $this->access_token, $this->access_token_secret );
            } else {
                $token = new OAuthToken( $this->request_token, $this->request_token_secret );
            }
            $request = OAuthRequest::from_consumer_and_token( $consumer, $token, $method, $url, $params );

            // the signature method requires the three params be sent of specific objects:
            //	OAuthRequest::from_consumer_and_token, OAuthToken, OAuthConsumer
            $signature = OAuthSignatureMethod_HMAC_SHA1::build_signature( $request, $consumer, $token );

            $url = $request->to_url();
            $url .= '&oauth_signature='.urlencode($signature);

            if( !$execute ){ return $url; }

            $ch = curl_init();
            if (defined('CURL_CA_BUNDLE_PATH')){
                curl_setopt($ch, CURLOPT_CAINFO, CURL_CA_BUNDLE_PATH);
            }

            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

            if( $method=='POST' ){
                curl_setopt($ch, CURLOPT_POST, 1);
                //curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
            }

            $response = curl_exec($ch);
            $this->http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->last_api_call = $url;
            curl_close ($ch);

            return $response;
        }
    }

    /**
     * @param string $url The URL to hydrate
     * @return string The $url merged with $this->api_url
     */
    public function get_hydrated_url($url) {
        $parts = parse_url($url);

        $scheme = (isset($parts['scheme'])) ? $parts['scheme'] : 'http';
        $port = (isset($parts['port'])) ? $parts['port'] : (($scheme == 'https') ? '443' : '80');
        if (!isset($parts['host'])) {
            $api_parts = parse_url($this->api_url);
            $host = strtolower($api_parts['host']);
        } else {
            $host = strtolower($parts['host']);
        }
        $path = (isset($parts['path'])) ? $parts['path'] : '';

        if (($scheme == 'https' && $port != '443')
                || ($scheme == 'http' && $port != '80')) {
            $host = "$host:$port";
        }
        return "$scheme://$host$path";
    }

    /**
     * There is no need for this function because we use get_login_url.
    function authorize() {
    }
    */

    /**
     * deauthorize
     *
     * Deletes oauth tokens.
     */
    function deauthorize() {

        $this->request_token = '';
        $this->request_token_secret = '';
        $this->access_token = '';
        $this->access_token_secret = '';
        $this->user_id = '';

        return $this->authorized;
    }

    function capture_access_token() {
        $retval = false;

        if (!empty($this->access_token)) {
            $retval = true;
        } else if (isset($_GET['oauth_token'])) {
            // check the request_token
            if (!isset($_SESSION['phpoauth_request_token']) || $_SESSION['phpoauth_request_token']!=$_GET['oauth_token']) {
                // this is bad news
            }

            // get the verifier
            if (isset($_GET['oauth_verifier'])) {
                $this->request_token_verifier = $_GET['oauth_token'];
                $_SESSION['phpoauth_request_token_verifier'] = $_GET['oauth_verifier'];
            }

            if ($this->fetch_access_token()) {
                $this->authorized = true;
                $retval = true;
            }
        }

        return $retval;
    }

    function reset_tokens() {
        $_SESSION['phpoauth_request_token'] = '';
        $_SESSION['phpoauth_request_token_secret'] = '';
        $_SESSION['phpoauth_request_token_verifier'] = '';
        $_SESSION['phpoauth_request_token_response'] = '';
        $_SESSION['phpoauth_access_token'] = '';
        $_SESSION['phpoauth_access_token_secret'] = '';
        $_SESSION['phpoauth_access_token_response'] = '';
        $this->request_token = '';
        $this->request_token_secret = '';
        $this->request_token_verifier = '';
        $this->request_token_response = '';
        $this->access_token = '';
        $this->access_token_secret = '';
        $this->access_token_response = '';
    }

    function get_user_from_available_data($key='user_id') {
        return isset($this->access_token_response[$key]) ? $this->access_token_response[$key] : null;
    }
}
