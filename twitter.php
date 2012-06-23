<?php
/**
 * This is meant to model Facebook's SDK, for sanity's sake. So, in theory, all
 * the calls you make to the Facebook PHP SDK can be made similarly here.
 *
 * The idea is to keep this file distinct from OAuth, so we inject the OAuth
 * class into this one rather than extending it. Think: the concept of Twitter
 * isn't limited to OAuth.
 *
 * @package Twitter_PHP_SDK
 */

require_once('oauth.php');

class Twitter
{
    protected $oauth;

    protected $user;

    public function __construct($config) {
        if (!session_id()) {
            session_start();
        }
        $this->oauth = new OAuth(array(
                    'service'=>'twitter',
                    'consumer_key'=>$config['consumerKey'],
                    'consumer_secret'=>$config['consumerSecret']
                    ));
    }

    public function setConsumerKey($consumerKey) {
        $this->consumerKey = $consumerKey;
        $this->oauth->consumer_key = $consumerKey;
    }

    public function setConsumerSecret($consumerSecret) {
        $this->consumerSecret = $consumerSecret;
        $this->oauth->consumer_secret = $consumerSecret;
    }

    public function setAccessToken($accessToken) {
        $this->oauth->set_access_token($accessToken);
    }

    public function setAccessTokenSecret($accessTokenSecret) {
        $this->oauth->set_access_token_secret($accessTokenSecret);
    }

    public function getLoginUrl($params=array()) {
        return $this->oauth->get_login_url($params);
    }

    public function getAccessToken() {
        return $this->oauth->get_access_token();
    }

    public function getAccessTokenSecret() {
        return $this->oauth->get_access_token_secret();
    }

    /**
     * Listens to the request for the oauth_token. If found, it will be stored
     * in the oauth object and get be retrieved with getAccessToken.
     */
    public function capture() {
        $this->oauth->capture_access_token();
    }

    public function getUser($key='user_id') {
        if ($this->oauth->is_authorized()) {
            return $this->oauth->get_user_from_available_data($key);
        } else {
            return null;
        }
    }

}
