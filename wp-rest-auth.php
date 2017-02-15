<?php
/*
Plugin Name: REST Authentication
Description: RESTful Authentication via 3rd party EndPoint.
Version: 1.2
Author: cdebellis
License: None
*/

if(!defined('ABSPATH')) exit; // Exit if accessed directly.

class pcr_auth_class {
    /**
     * Instance of this class.
     *
     * @var object
     *
     * @since 1.0.0
     */
    protected static $instance = null;

    /**
     * Slug.
     *
     * @var string
     *
     * @since 1.0.0
     */
    protected static $text_domain = 'pcr-auth';

    /**
     * Initialize the plugin
     *
     * @since 1.0.0
     */
    private function __construct() {

        // # replace default authentication hook
        remove_action('authenticate', array($this, 'wp_authenticate_username_password'), 20);

        // # run session check on init
        add_action('init', array($this, 'pcr_auth_session_start'));

        // # use our authentication hook and trigger pcr_auth() function
        add_filter('authenticate', array($this, 'pcr_auth'), 10, 3);

         // # force the login action without user input only on mobile login from app
        if(wp_is_mobile() && strpos($_SERVER['REQUEST_URI'], 'login') !== false) {
            add_filter('init', array($this, 'pcr_auth'), 10, 3);
        }

        // # after login success, redirect accordingly.
        add_filter('login_redirect', array($this, 'pcr_auth_redirect'), 10, 3); 

        // # kill the session and remove session var request_uri on logout
        add_action('wp_logout', array($this, 'pcr_auth_session_kill'));

        // # extend http timeout if php.ini returns too low of a number
        add_filter('http_request_timeout', array($this,'pcr_auth_timeout_extend'));

        // # remove email requirement from admin User Update form - not relevant to rest-auth - consider moving to template
        add_action('user_profile_update_errors', function($arg) {
            if(isset($arg->errors['empty_email'])) unset($arg->errors['empty_email']);
        });
    }

    /**
    * Return an instance of this class.
    *
    *
    * @since 1.0.0
    *
    * @return object A single instance of this class.
    */
    public static function get_instance() {
      // # If the single instance hasn't been set, set it now.
      if ( null == self::$instance ) {
        self::$instance = new self;
      }

      return self::$instance;
    }

    /**
     * Load the plugin text domain for translation.
     *
     *
     * @since 1.0.0
     *
     * @return void
     */
    public function load_plugin_textdomain() {
      load_plugin_textdomain( self::$text_domain, false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );
    }


    public function pcr_auth($user, $username='', $password='') {

        // # Define application environment - obtained from environmental var in virtual host
        $env = (getenv('APPLICATION_ENV') == 'dev') ? 'https://dev.domain.com/api/' : 'https://domain.com/api/';

        // # Define application API key
        $apikey = (!empty(getenv('API_KEY')) ? getenv('API_KEY') : '');

        $token = (isset($_GET['token']) ? filter_var($_GET['token'], FILTER_SANITIZE_STRING) : false);

        // # retrieve the current sessions id
        $sess_id = session_id();

        // # detect mobile client and if token exists
        if($token && wp_is_mobile()) {

            $request_array = array('apiProgram' => 'CGDRUA', 
                                   'token' => $token, 
                                   'apikey' => $apikey
                                  );
        } else { // not mobile

            // # check if username and password are present
            if(empty($username) || empty($password)) return;

            $request_array = array('apiProgram' => 'CGDRUA', 
                                   'access' => $username, 
                                   'password' => md5(strtolower($password)), 
                                   'sess_id' => $sess_id, 
                                   'apikey' => $apikey
                                   );
        }

        $response = wp_remote_post($env, array(
            'method' => 'POST',
            'timeout' => 45,
            'redirection' => 5,
            'httpversion' => '1.0',
            'blocking' => true,
            'headers' => array(),
            'body' => $request_array,
            'cookies' => array()
            )
        );

        if(is_wp_error($response)) {
            error_log(print_r($response->get_error_message(), 1));
        }

        $ext_auth = json_decode($response['body'], true);

        if($ext_auth['status'] == 403) {
            return;
        }

        $department = (!empty($ext_auth['department']) ? $ext_auth['department'] : 'Unassigned');
        $dept_code = (!empty($ext_auth['department_code']) ? strtolower($ext_auth['department_code']) : 'subscriber');

        if(empty($ext_auth['salesman_number'])) {
            // # User does not exist,  send back an error message
            $user = new WP_Error( 'denied', __("ERROR: Access Number or Password incorrect") );

        } else {

            // # External user exists, try to load the user info from the WordPress user table
            $userobj = new WP_User();
            $user = $userobj->get_data_by('login', $ext_auth['salesman_number']); // Does not return a WP_User object 🙁

            $user = new WP_User($user); // Attempt to load up the user with that ID

            if( $user->ID == 0 ) {
                // # The user does not currently exist in the WordPress user table.
                // # You have arrived at a fork in the road, choose your destiny wisely

                // # If you do not want to add new users to WordPress if they do not
                // # already exist uncomment the following line and remove the user creation code
                //$user = new WP_Error( 'denied', __("ERROR: Not a valid user for this system") );

                // # Setup the minimum required user information for this example
                $userdata = array('user_login' => $ext_auth['salesman_number'],
                                  'user_email' => strtolower($ext_auth['email']),
                                  'first_name' => $ext_auth['first_name'],
                                  'last_name'  => $ext_auth['last_name']
                                 );

                $new_user_id = wp_insert_user($userdata); // A new user has been created
                
                // # Load the new user info
                $user = new WP_User($new_user_id);

                // # if department (role) doesnt not exist, create it
                if(empty(get_role($dept_code))) {
                    add_role($dept_code, $department, array('read' => true,));
                }
                
                // # set_role() will overwrite ALL existing assigned roles (including administrator)
                $user->set_role($dept_code);

            } else { 

            // ######################
            // # update existing user
            // ######################

                // # update the minimum required user information
                $userdata = array('ID' => $user->ID,
                                  'user_email' => strtolower($ext_auth['email']),
                                  'first_name' => $ext_auth['first_name'],
                                  'last_name'  => $ext_auth['last_name']
                                 );

                // # force user info update
                wp_update_user($userdata);

                // # if department (role) doesnt not exist, create it!
                if(empty(get_role($dept_code))) {      
                    add_role($dept_code, $department, array('read' => true,));
                }

                // # loop through all user assigned roles
                foreach ($user->roles as $role) {

                    // # SKIP default wordpress roles
                    if ($role != 'administrator' && 
                        $role != 'editor' && 
                        $role != 'author' && 
                        $role != 'contributor' && 
                        $role != 'app_subscriber') {
                        
                        // # remove all non-WP department (role) capabilities for clean role assignment.
                        $user->remove_role($role);
                    }
                }

                // # add the response [department] (role) to current user
                // # we broke free of the loop so we can iterate through it again
                $user->add_role($dept_code);

                // # find default WP roles assigned to user
                foreach ($user->roles as $role) {

                    // # match on default wordpress roles
                    if ($role == 'administrator' || 
                        $role == 'editor' || 
                        $role == 'author' || 
                        $role == 'contributor' || 
                        $role == 'app_subscriber') {
                        
                        // # remove any default WP roles found in primary position and re-add as secondary role
                        $user->remove_cap($role);
                        $user->add_cap($role);
                    }
                }

            }

            if(!empty($ext_auth['internalIPs'])) {

                $allowedIPs = $ext_auth['internalIPs'];

                if (get_option('allowedIPs') !== false ) {
                    // # The wp-option already exists, so we just update it.
                    update_option( 'allowedIPs', $allowedIPs, 1);

                } else {
                    // # The wp-option hasn't been added yet. We'll add it with $autoload set to 'no'.
                    add_option('allowedIPs', $allowedIPs, null, 0);
                }
            }

            if($token && wp_is_mobile()) {
                // # set the wordpress auth cookie and redirect to dashboard
                wp_set_auth_cookie($user->ID);
                wp_redirect(home_url());
                exit;
            }
        }

        // # Comment out this line if you wish to fall back on WordPress authentication
        // # Useful for times when the external service is offline
        remove_action('authenticate', 'wp_authenticate_username_password', 20);

        return $user;
    }

        // # avoid 408 timeouts by extending request timeout
    public function pcr_auth_timeout_extend($time) {

        $max_execution_time = ini_get('max_execution_time');

        if($max_execution_time < 60) {
            $time = $max_execution_time + 60;
        } else {
            $time = $max_execution_time;
        }
        
        return $time;
    }

    ////////////////////////////////////
    // # Session check and set session var request_uri
    public function pcr_auth_session_start() {

        // # check session_status()
        if(session_status() === PHP_SESSION_NONE) {
          session_start();
        }

        $request_uri = $_SERVER['REQUEST_URI'];

        // # due to wp nonce in some request_uri's, lets partial match login and logout strings
        // # also look for onesignal references even though we match on entire troublsome URL's below.
        if(stripos('login', $request_uri) !== true && stripos('logout', $request_uri) !== true && stripos('onesignal', $request_uri) !== true) {

            // # build the array of known url's to skip
            $skip_urls = array('/',
                               '/login/',
                               '/wp-admin/admin-ajax.php',
                               '/wp-cron.php?doing_wp_cron',
                               '/login/?login=false',
                               '/login/?login=failed',
                               '/wp-login.php'
                               );

            // # check if reuest uri is empty and does not match skip_urls array
            if(!empty($request_uri) && !in_array($request_uri, $skip_urls)) {

                // # all is good, set the session
                $_SESSION['request_uri'] = $request_uri;
            }
        }
    }

    public function pcr_auth_redirect($redirect_to, $request, $user) {

        // # check if the session request_uri us set
        if(isset($_SESSION['request_uri'])) {
            
            $redirect_to = $_SESSION['request_uri'];
            return $redirect_to;

        } else {

            // # request_uri is not set, return the home_url
            return home_url();
        }
    }

    public function pcr_auth_session_kill() {
        if(isset($_SESSION['request_uri'])) {
            $_SESSION['request_uri'] = '';
            unset($_SESSION['request_uri']);

        }
    }
}

add_action( 'plugins_loaded', array( 'pcr_auth_class', 'get_instance' ), 0 );