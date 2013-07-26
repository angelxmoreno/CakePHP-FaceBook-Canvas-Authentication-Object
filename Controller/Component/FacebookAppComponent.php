<?php

App::uses('Component', 'Controller');

/**
 * Loads the settings for AuthComponent and FacebookAppAuthenticate
 *
 * @author amoreno
 *
 * @property SessionComponent $Session
 * @property AuthComponent $Auth
 */
class FacebookAppComponent extends Component {

	/**
	 * Settings for this Component
	 * The entire settings array is sent to the FacebookApp authentication object
	 *
	 * @var array
	 */
	public $settings = array(
	    'autoLogin' => true,
	    'app_id' => null,
	    'app_secret' => null,
	    'canvas_page' => null,
	    'perms' => array('email'),
	    'session_namespace' => 'FacebookApp',
	    'registerMethod' => null,
	    'fields' => array('facebook_id' => 'facebook_id')
	);

	/**
	 * Required sesstings
	 * These can be set via $Controller ->comomponents() or
	 * Configure('FacebookApp', array());
	 *
	 * @var array
	 */
	protected $_requiredSettings = array(
	    'app_id',
	    'app_secret',
	    'canvas_page',
	);

	/**
	 * Other Components this component uses.
	 *
	 * @var array
	 */
	public $components = array('Session', 'Auth');

	/**
	 * Constructor
	 *
	 * @param ComponentCollection $collection A ComponentCollection this component can use to lazy load its components
	 * @param array $settings Array of configuration settings.
	 */
	public function __construct(ComponentCollection $collection, $settings = array()) {
		$boostrapSettings = Configure::check('FacebookApp') ? Configure::read('FacebookApp') : array();
		$settings = array_merge($this->settings, $boostrapSettings, $settings);
		parent::__construct($collection, $settings);
		foreach ($this->_requiredSettings as $requiredSetting) {
			if (is_null($this->settings[$requiredSetting])) {
				throw new CakeException('Missing parameter:"' . $requiredSetting . '"');
			}
		}
	}

	/**
	 * Called before the Controller::beforeFilter().
	 *
	 * @param Controller $controller Controller with components to initialize
	 * @return void
	 */
	public function initialize(Controller $controller) {
		$this->Auth->authenticate['FacebookCanvas.FacebookApp'] = $this->settings;
		if (!$this->Auth->loggedIn() && $user = $this->Auth->identify($controller->request, $controller->response)) {
			$this->Auth->login($user);
		}
		$controller->set('CanvasSettings', $this->settings);
	}

	/**
	 * Creates the url for authenticating the FacebookApp
	 *
	 * @return string
	 */
	public function getAuthUrl() {
		$state = $this->_createStateSecret();
		$auth_url = 'https://www.facebook.com/dialog/oauth?client_id=';
		$auth_url .= $this->settings['app_id'];
		$auth_url .= '&scope=';
		$auth_url .= implode(',', $this->settings['perms']);
		$auth_url .= '&state=';
		$auth_url .= $state;
		$auth_url .= '&redirect_uri=';
		$auth_url .= urlencode($this->settings['canvas_page']);
		return $auth_url;
	}

	/**
	 * Create a random string and saves it to session. This is used to protect against Cross-site Request Forgery
	 *
	 * @return String
	 * @deprecated API might no longer need this
	 */
	protected function _createStateSecret() {
		$state = sprintf('fb_%s_state', $this->Auth->password(String::uuid()));
		$this->sessionWrite('state', $state);
	}

	/**
	 * deletes all session data
	 * @return void
	 */
	public function logout() {
		$this->Session->delete($this->settings['session_namespace']);
	}

	/**
	 * write to session
	 *
	 * @param string $name The name of the key your are setting in the session.
	 * @param string $value The value you want to store in a session.
	 * @return boolean Success
	 */
	public function sessionWrite($name, $value) {
		$name = $this->settings['session_namespace'] . '.' . $name;
		return $this->Session->write($name, $value);
	}

	/**
	 * read from session
	 *
	 * @param string $name the name of the session key you want to read
	 * @return mixed value from the session vars
	 */
	public function sessionRead($name = null) {
		$name = $this->settings['session_namespace'] . '.' . $name;
		return $this->Session->read($name);
	}

	/**
	 * delete in session
	 *
	 * @param string $name the name of the session key you want to delete
	 * @return boolean true is session variable is set and can be deleted, false is variable was not set.
	 */
	public function sessionDelete($name) {
		$name = $this->settings['session_namespace'] . '.' . $name;
		return $this->Session->delete($name);
	}

}
