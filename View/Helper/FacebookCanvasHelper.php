<?php

App::uses('Helper', 'View/Helper');
App::uses('HtmlHelper', 'View/Helper');

/**
 * AmazonProductsApi Helper
 *
 * @property HtmlHelper $Html
 */
class FacebookCanvasHelper extends Helper {

	public $helpers = array('Html');

	/*
	 * possible options for the userImage() function
	 *
	 * These options will be intercepted and used in the forming of the url and
	 * will then be removed from the options array before it is passed to the HtmlHelper::image() function
	 */
	protected $_userImageOptions = array(
	    'ssl',
	    'type',
	    'access_token',
	);

	/*
	 * possible sizes for the userImage() function
	 *
	 * 'square' 50px Wide 50px High
	 * 'small' 50px Wide Variable Height
	 * 'normal' 100px Width Variable Height
	 * 'large' 200px Wide Variable Height
	 *
	 * Or you can use the width and height argument. The image returned will:
	 * Sliced to the width and height using a source that's larger than the size you've requested (for better scaling.)
	 * Be a square image if width and height have the same value.
	 */
	protected $_userImageSizes = array(
	    'square',
	    'small',
	    'normal',
	    'large'
	);

	public function userImage($fbid, $options = array()) {
		$image_options = array_diff_key($options, array_flip($this->_userImageOptions));
		$path_options = array_diff_key($options, $image_options);
		$path = 'https://graph.facebook.com/' . $fbid . '/picture?' . http_build_query($path_options);
		return $this->Html->image($path, $image_options);
	}

}