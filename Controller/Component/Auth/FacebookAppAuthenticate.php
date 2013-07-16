<?php

App::uses('BaseAuthenticate', 'Controller/Component/Auth');
//App::uses('ClassRegistry', 'Utility');
App::uses('CakeSession', 'Model/Datasource');
App::uses('HttpSocket', 'Network/Http');

/**
 * PHP 5
 *
 * Licensed under The MIT License
 *
 * @license       MIT License (http://www.opensource.org/licenses/mit-license.php)
 * @author Angel S. Moreno <angelxmoreno@gmail.com>
 * @link https://github.com/angelxmoreno/CakePHP-FacebookApp CakePHP-FacebookApp
 *
 * @property HttpSocket $http
 * @property SessionComponent $Session
 * @property FacebookAppComponent $FacebookApp
 */
class FacebookAppAuthenticate extends BaseAuthenticate {

	/**
	 * Settings for this object.
	 *
	 * - `fields` The fields to use to identify a user by.
	 * - `userModel` The model name of the User, defaults to User.
	 * - `scope` Additional conditions to use when looking up and authenticating users,
	 *    i.e. `array('User.is_active' => 1).`
	 * - `recursive` The value of the recursive key passed to find(). Defaults to 0.
	 * - `contain` Extra models to contain and store in session.
	 *
	 * @var array
	 */
	public $settings = array(
	    'app_id' => null,
	    'app_secret' => null,
	    'canvas_page' => null,
	    'userModel' => 'FacebookCanvas.CanvasUser',
	    'fields' => array(
		'username' => 'username',
		'password' => 'password'
	    ),
	    'recursive' => 0,
	    'contain' => null,
	    'session_namespace' => 'Facebook',
	    'loginAction' => array(
		'admin' => false,
		'plugin' => 'facebook_canvas',
		'controller' => 'canvas_users',
		'action' => 'login',
	    ),
	    'urls' => array(
		'get_access_token' => 'https://graph.facebook.com/oauth/access_token',
		'get_user_data' => 'https://graph.facebook.com/me',
	    ),
	);

	/**
	 * Constructor
	 *
	 * @param ComponentCollection $collection The Component collection used on this request.
	 * @param array $settings Array of settings to use.
	 */
	public function __construct(ComponentCollection $collection, $settings) {
		$settings = array_merge($this->settings, $settings);
		parent::__construct($collection, $settings);
		$this->http = new HttpSocket();
		$this->_initComponentCollection();
	}

	/**
	 * Initializes all the loaded Components for the Authentication Object.
	 * Attaches a reference of each component to the Authentication Object.
	 *
	 * @return void
	 */
	protected function _initComponentCollection() {
		$components = $this->_Collection->loaded();
		if (!empty($components)) {
			foreach ($components as $name) {
				$this->{$name} = $this->_Collection->__get($name);
			}
		}
	}

	/**
	 * Get a user based on information in the request. Primarily used by stateless authentication
	 * systems like basic and digest auth.
	 *
	 * @param CakeRequest $request Request object.
	 * @return mixed Either false or an array of user information
	 */
	public function getUser(CakeRequest $request) {
		return $this->authenticate($request, new CakeResponse());
	}

	/**
	 * Authenticate a user based on the request information.
	 *
	 * @param CakeRequest $request Request to get authentication information from.
	 * @param CakeResponse $response A response object that can have headers added.
	 * @return mixed Either false on failure, or an array of user data on success.
	 */
	public function authenticate(CakeRequest $request, CakeResponse $response) {
		/**
		 * @todo the state param is sent during the login but it is not coming back. not sure if this is still needed
		 */
		//$state = $this->FacebookApp->sessionRead('state');
		$access_token = false;

		if (isset($request->query['code'])) {// && isset($request->query['state']) && $request->query['state'] == $state) {
			$auth_params = $this->_getAccessToken($request->query['code']);
			if (isset($auth_params['access_token'])) {
				$access_token = $auth_params['access_token'];
			}
		}

		if (isset($request->data['signed_request'])) {
			$signed_request = $request->data['signed_request'];
			$decoded_request = $this->_parse_signed_request($signed_request);
			$this->FacebookApp->sessionWrite('signed_request', $signed_request);
			$this->FacebookApp->sessionWrite('decoded_request', $decoded_request);
		}
		if ($this->FacebookApp->sessionRead('decoded_request.user_id') && $this->FacebookApp->sessionRead('decoded_request.oauth_token')) {
			$access_token = $this->FacebookApp->sessionRead('decoded_request.oauth_token');
		}

		if ($access_token) {
			$token_expires = isset($auth_params['expires']) ? $auth_params['expires'] : null;

			$fbuserData = $this->_getFBUserData($access_token);
			if (!isset($fbuserData['id'])) {
				return false;
			}
			$fbuserData['access_token'] = $access_token;
			$this->_saveUser($fbuserData);
			$conditions = array(
			    'id' => $fbuserData['id']
			);
			return $this->_findUser($conditions);
		}
		return false;
	}

	/**
	 * Calls Facebook for an access token
	 */
	protected function _getAccessToken($code) {
		$query = array(
		    'client_id' => $this->settings['app_id'],
		    'redirect_uri' => Router::url($this->settings['loginAction'], true),
		    'client_secret' => $this->settings['app_secret'],
		    'code' => $code,
		);

		$response = $this->http->get($this->settings['urls']['get_access_token'], $query);
		$params = null;
		parse_str($response->body, $params);
		return $params;
	}

	/**
	 * Uses an access token to get user data
	 */
	protected function _getFBUserData($access_token) {
		$query = array(
		    'access_token' => $access_token,
		);

		$response = $this->http->get($this->settings['urls']['get_user_data'], $query);
		$data = json_decode($response->body, true);
		return $data;
	}

	/**
	 * Saves the user and returns an array on success
	 * @todo This method is too spesific. Instead, the auth object should take in a model and method to send data to.
	 */
	protected function _saveUser($userData) {
		$userData['is_registered'] = true;
		$userModel = $this->settings['userModel'];
		list(, $model) = pluginSplit($userModel);
		$result = ClassRegistry::init($userModel)->save($userData);
		return current($result);
	}

	/**
	 * parses the signed request
	 */
	protected function _parse_signed_request($signed_request) {
		list($encoded_sig, $payload) = explode('.', $signed_request, 2);
		$sig = $this->_base64_url_decode($encoded_sig);
		$expected_sig = hash_hmac('sha256', $payload, $this->settings['app_secret'], $raw = true);
		if ($sig !== $expected_sig) {
			throw new CakeException('Bad Signed JSON signature!');
		}
		$data = json_decode($this->_base64_url_decode($payload), true);

		return $data;
	}

	/**
	 * helper function for decoding
	 *
	 * @param string $encoded
	 * @return string $decoded
	 */
	protected function _base64_url_decode($encoded) {
		$decoded = base64_decode(strtr($input, '-_', '+/'));
		return $decoded;
	}

}
