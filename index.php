<?php
	require_once 'AltoRouter.php';

	// http_response_code(403); // Forbidden
	// http_response_code(400); // Bad request
	// http_response_code(500); // Internal Server Error
	header('Content-Type: application/json');
	header("Access-Control-Allow-Origin: *");

	$config = @json_decode(file_get_contents("conf.json"), true);

	function dbConnect(){
		$config = $GLOBALS['config'];
		$db = @new mysqli($config['db']['host'], $config['db']['username'], $config['db']['password'], $config['db']['database']);

		if(mysqli_connect_errno()){
			@$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Could not connect to database"));
			exit;
		}else{
			return $db;
		}
	}

	@define('PW_SALT_BEGIN', md5($config['pw_salt']['begin']));
	@define('PW_SALT_END', md5($config['pw_salt']['end']));

	@define('TOKEN_MAX_AGE', $config['token_age']['created']);
	@define('TOKEN_MAX_UNUSED', $config['token_age']['unused']);

	@define('REGISTRATION_ENABLED', $config['registration_enabled']);

	@define('TAG_DELIMITER', $config['tag_delimiter']);

	@define('BASE_PATH', $config['base_path']);

	$user_info = null;
	$token_info = null;

	function cleanTokens(){
		$db = dbConnect();

		$query = "DELETE FROM tokens WHERE created < DATE_ADD(NOW(), INTERVAL -" . TOKEN_MAX_AGE . " MINUTE) OR last_time < DATE_ADD(NOW(), INTERVAL -" . TOKEN_MAX_UNUSED . " MINUTE)";

		$db->query($query);

		$db->close();
	}
	cleanTokens();

	/**
	* When not authenticated, returns array with error: string and errno: -1
	*/
	$verify_auth = function($token) use (&$user_info, &$token_info){
		$db = dbConnect();

		if(!empty($token)){
			$query = "SELECT * FROM tokens WHERE value=?";

			$token_stmt = $db->prepare($query);

			if($token_stmt){
				$token_stmt->bind_param("s", $token);
				$token_stmt->execute();
				$token_stmt->store_result();

				if(!mysqli_errno($db) && $token_stmt->num_rows == 1){
					$token_stmt->bind_result($token_id, $token_userid, $token_value, $token_created, $token_last_ip, $token_last_time);
					$token_stmt->fetch();

					$token_info = array(
						"id"=>$token_id,
						"userid"=>$token_userid,
						"value"=>$token_value,
						"created"=>$token_created,
						"last_ip"=>$token_last_ip,
						"last_time"=>$token_last_time,
					);

					$query = "SELECT * FROM users WHERE id=?";

					$user_stmt = $db->prepare($query);

					if($user_stmt){
						$user_stmt->bind_param("i", $token_info['userid']);
						$user_stmt->execute();
						$user_stmt->store_result();

						if(!mysqli_errno($db) && $user_stmt->num_rows == 1){
							$user_stmt->bind_result($user_id, $user_username, $user_email, $user_password, $user_active);
							$user_stmt->fetch();

							$user_info = array(
								"id"=>$user_id,
								"username"=>$user_username,
								"email"=>$user_email,
								"password"=>$user_password,
								"active"=>$user_active
							);

							if($user_info['active']){
								$query = "UPDATE tokens SET last_ip=?, last_time=current_timestamp WHERE value=?";

								$update_stmt = $db->prepare($query);

								if($update_stmt){
									$update_stmt->bind_param("ss", $last_ip, $token);

									$last_ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);

									$update_stmt->execute();
									$update_stmt->close();
								}

								$token_stmt->close();
								$user_stmt->close();
								$db->close();

								return true;
							}
						}

						$user_stmt->close();
					}
				}

				$token_stmt->close();
			}
		}

		$db->close();

		http_response_code(403);
		echo json_encode(array("error"=>"Not authenticated", "errno"=>-1));
		exit;
	};

	$router = new AltoRouter();

	$router->setBasePath(BASE_PATH);

	$router->map( 'GET', '/', function() {
		echo json_encode(array("info"=>"Passwordmanager API v1.0"));
		exit;
	});

	$router->map( 'POST', '/login', function() {
		if(!empty($_POST['username']) && !empty($_POST['password'])){
			$db = dbConnect();

			$query = "SELECT * FROM users WHERE (username=? OR email=?) AND password=?";

			$user_stmt = $db->prepare($query);

			if($user_stmt){
				$user_stmt->bind_param("sss", $_POST['username'], $_POST['username'], $password);

				$password = md5(PW_SALT_BEGIN . $_POST['password'] . PW_SALT_END);

				$user_stmt->execute();

				if(!mysqli_errno($db)){
					$user_stmt->store_result();

					if($user_stmt->num_rows == 1){
						$user_stmt->bind_result($user_id, $user_username, $user_email, $user_password, $user_active);
						$user_stmt->fetch();

						$user = array(
							"id"=>$user_id,
							"username"=>$user_username,
							"email"=>$user_email,
							"active"=>$user_active
						);

						if($user['active']){
							$token = md5(date('d.m.Y-H:i:s') . $user['username']);

							$query = "INSERT INTO tokens (userid, value, last_ip) VALUES (?, ?, ?)";

							$token_stmt = $db->prepare($query);

							if($token_stmt){
								$token_stmt->bind_param("iss", $user['id'], $token, $last_ip);

								$last_ip = $_SERVER['REMOTE_ADDR']?:($_SERVER['HTTP_X_FORWARDED_FOR']?:$_SERVER['HTTP_CLIENT_IP']);

								$token_stmt->execute();

								if(!mysqli_errno($db)){
									echo json_encode(array(
										"user"=>$user,
										"token"=>$token
									));
								}else{
									http_response_code(500);
									echo json_encode(array("error"=>"A database-error occured"));
								}

								$token_stmt->close();
							}
						}else{
							http_response_code(403);
							echo json_encode(array("error"=>"User inactive"));
						}
					}else{
						http_response_code(403);
						echo json_encode(array("error"=>"Username or password wrong"));
					}
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}
				$user_stmt->close();
				$db->close();
				exit;
			}

			$db->close();
		}else{
			http_response_code(400);
			echo json_encode(array("error"=>"Username or password not set"));
			exit;
		}

		http_response_code(500);
		echo json_encode(array("error"=>"Error"));
		exit;
	});

	$router->map( 'POST', '/register', function() {
		if(!REGISTRATION_ENABLED){
			http_response_code(400);
			echo json_encode(array("error"=>"Registration is disabled"));
			exit;
		}

		if(!empty($_POST['username']) && !empty($_POST['email']) && !empty($_POST['password'])){
			if(filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)){
				$db = dbConnect();

				$query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";

				$user_stmt = $db->prepare($query);

				if($user_stmt){
					$user_stmt->bind_param("sss", $_POST['username'], $_POST['email'], $password);

					$password = md5(PW_SALT_BEGIN . $_POST['password'] . PW_SALT_END);

					$user_stmt->execute();

					if(!mysqli_errno($db)){
						echo json_encode(array("info"=>"Registration successfull"));
					}else if(mysqli_errno($db) == 1062){
						http_response_code(400);
						echo json_encode(array("error"=>"Username/email already taken"));
					}else{
						http_response_code(500);
						echo json_encode(array("error"=>"A database-error occured"));
					}
					$user_stmt->close();
					$db->close();
					exit;
				}

				$db->close();
			}else{
				http_response_code(400);
				echo json_encode(array("error"=>"Enter a valid email"));
				exit;
			}
		}else{
			http_response_code(400);
			echo json_encode(array("error"=>"Username, email or password not set"));
			exit;
		}

		http_response_code(500);
		echo json_encode(array("error"=>"Error"));
		exit;
	});

	$router->map('GET', '/registration_enabled', function() {
		echo json_encode(array("value"=>REGISTRATION_ENABLED));
		exit;
	});

	$router->map( 'GET', '/auth/[:token]', function($token) use ($verify_auth) {
		if($verify_auth($token)){
			echo json_encode(array("info"=>"Authenticated"));
			exit;
		}
	});

	$router->map( 'GET', '/logout/[:token]', function($token) use ($verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "DELETE FROM tokens WHERE value=?";
			$logout_stmt = $db->prepare($query);

			if($logout_stmt){
				$logout_stmt->bind_param("s", $token);

				$logout_stmt->execute();

				if(!mysqli_errno($db)){
					echo json_encode(array("info"=>"Logged-out","errno"=>0));
					$logout_stmt->close();
					$db->close();
					exit;
				}

				$logout_stmt->close();
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"A database-error occured", "errno"=>-2));
			exit;
		}
	});

	$router->map( 'GET', '/logout/[:token]/[:id]', function($token, $id) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "DELETE FROM tokens WHERE id=? AND userid=?";
			$logout_stmt = $db->prepare($query);

			if($logout_stmt){
				$logout_stmt->bind_param("ii", $id, $user_info['id']);

				$logout_stmt->execute();

				if(!mysqli_errno($db)){
					echo json_encode(array("info"=>"Logged-out","errno"=>0));
					$logout_stmt->close();
					$db->close();
					exit;
				}

				$logout_stmt->close();
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"A database-error occured", "errno"=>-2));
			exit;
		}
	});

	$router->map( 'GET', '/logout_all/[:token]', function($token) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "DELETE FROM tokens WHERE userid=?";
			$logout_stmt = $db->prepare($query);

			if($logout_stmt){
				$logout_stmt->bind_param("i", $user_info['id']);

				$logout_stmt->execute();

				if(!mysqli_errno($db)){
					echo json_encode(array("info"=>"Logged-out","errno"=>0));
					$logout_stmt->close();
					$db->close();
					exit;
				}

				$logout_stmt->close();
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"A database-error occured", "errno"=>-2));
			exit;
		}
	});

	$router->map( 'GET', '/logins/[:token]', function($token) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "SELECT id, created, last_ip, last_time, value FROM tokens WHERE userid=" . $user_info['id'] . " ORDER BY last_time DESC";

			$tokens = $db->query($query);

			if(!mysqli_errno($db)){
				$ret_tokens = array();

				while($row = $tokens->fetch_assoc()){
					if($row['value'] == $token){
						$row['current'] = true;
					}else{
						$row['current'] = false;
					}
					unset($row['value']);

					$ret_tokens[] = $row;
				}

				echo json_encode($ret_tokens);
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"A database-error occured", "errno"=>-2));
			exit;
		}
	});

	$router->map( 'POST', '/settings/[:token]', function($token) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			if(!empty($_POST['password']) || !empty($_POST['email'])){
				if(empty($_POST['email']) || filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)){
					$db = dbConnect();

					$query = "UPDATE users SET password=?, email=? WHERE id=?";

					$settings_stmt = $db->prepare($query);

					if($settings_stmt){
						$settings_stmt->bind_param('ssi', $settings_password, $settings_email, $user_info['id']);

						$settings_password = $user_info['password'];
						$settings_email = $user_info['email'];

						$changed = false;

						if(!empty($_POST['password'])){
							$pw_salt = md5(PW_SALT_BEGIN . $_POST['password'] . PW_SALT_END);

							if($pw_salt != $user_info['password']){
								$settings_password = $pw_salt;
								$changed = true;
							}
						}

						if(!empty($_POST['email']) && $_POST['email'] != $user_info['email']){
							$settings_email = $_POST['email'];
							$changed = true;
						}

						$settings_stmt->execute();

						if(!mysqli_errno($db)){
							if($changed){
								$query = "DELETE FROM tokens WHERE userid=?";
								$logout_stmt = $db->prepare($query);

								if($logout_stmt){
									$logout_stmt->bind_param("i", $user_info['id']);
									$logout_stmt->execute();
									$logout_stmt->close();
								}
							}

							echo json_encode(array("info"=>"Updated successfully"));
							$db->close();
							exit;
						}
					}

					$db->close();

					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured", "errno"=>-2));
					exit;
				}else{
					http_response_code(400);
					echo json_encode(array("error"=>"Enter a valid email"));
					exit;
				}
			}else{
				http_response_code(400);
				echo json_encode(array("error"=>"No data specified"));
				exit;
			}
		}
	});

	$router->map( 'GET', '/load/[:token]', function($token) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "SELECT id, enc_key, data, last_changed, tags FROM passwords WHERE userid=?";
			$load_stmt = $db->prepare($query);

			if($load_stmt){
				$load_stmt->bind_param("i", $user_info['id']);

				$load_stmt->execute();
				$load_stmt->store_result();

				if(!mysqli_errno($db)){
					$load_stmt->bind_result($password_id, $password_enc_key, $password_data, $password_last_changed, $password_tags);

					$passwords = array();

					while($load_stmt->fetch()){
						$tags = explode(TAG_DELIMITER, $password_tags);
						array_shift($tags);

						$passwords[] = array(
							"id"=>$password_id,
							"enc_key"=>$password_enc_key,
							"data"=>$password_data,
							"last_changed"=>$password_last_changed,
							"tags"=>$tags
						);
					}

					echo json_encode($passwords);
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}

				$load_stmt->close();
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'GET', '/load/headers/[:token]', function($token) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "SELECT id, last_changed FROM passwords WHERE userid=?";
			$load_stmt = $db->prepare($query);

			if($load_stmt){
				$load_stmt->bind_param("i", $user_info['id']);

				$load_stmt->execute();
				$load_stmt->store_result();

				if(!mysqli_errno($db)){
					$load_stmt->bind_result($password_id, $password_last_changed);

					$passwords = array();

					while($load_stmt->fetch()){
						$passwords[] = array(
							"id"=>$password_id,
							"last_changed"=>$password_last_changed
						);
					}

					echo json_encode($passwords);
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}

				$load_stmt->close();
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'GET', '/load/headers/[:token]/[:id]', function($token, $id) use (&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "SELECT id, last_changed FROM passwords WHERE userid=? AND id=?";
			$load_stmt = $db->prepare($query);

			if($load_stmt){
				$load_stmt->bind_param("ii", $user_info['id'], $id);

				$load_stmt->execute();
				$load_stmt->store_result();

				if(!mysqli_errno($db)){
					$load_stmt->bind_result($password_id, $password_last_changed);

					$passwords = array();

					while($load_stmt->fetch()){
						$passwords[] = array(
							"id"=>$password_id,
							"last_changed"=>$password_last_changed
						);
					}

					echo json_encode($passwords);
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}

				$load_stmt->close();
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'DELETE', '/delete/[:token]/[:id]', function($token, $id) use(&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "DELETE FROM passwords WHERE userid=? AND id=?";

			$delete_stmt = $db->prepare($query);

			if($delete_stmt){
				$delete_stmt->bind_param("ii", $user_info['id'], $id);

				$delete_stmt->execute();

				if(!mysqli_errno($db)){
					echo json_encode(array("info"=>"Success", "errno"=>0));
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}

				$delete_stmt->close();
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'DELETE', '/delete/[:token]', function($token) use(&$user_info, $verify_auth) {
		if($verify_auth($token)){
			$db = dbConnect();

			$query = "DELETE FROM passwords WHERE userid=?";

			$delete_stmt = $db->prepare($query);

			if($delete_stmt){
				$delete_stmt->bind_param("i", $user_info['id']);

				$delete_stmt->execute();

				if(!mysqli_errno($db)){
					echo json_encode(array("info"=>"Success", "errno"=>0));
				}else{
					http_response_code(500);
					echo json_encode(array("error"=>"A database-error occured"));
				}

				$delete_stmt->close();
				$db->close();
				exit;
			}

			$db->close();

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'POST', '/update/[:token]', function($token) use(&$user_info, $verify_auth) {
		if($verify_auth($token)){
			if(!empty($_POST['data'])){
				$data = json_decode(str_replace("%2B", "+", $_POST['data']), true);

				if(json_last_error() == JSON_ERROR_NONE){
					$db = dbConnect();

					$insert_stmt = $db->prepare("INSERT INTO passwords (userid, enc_key, data, tags) VALUES (?, ?, ?, ?)");
					$update_stmt = $db->prepare("UPDATE passwords SET enc_key = ?, data = ?, tags= ? WHERE id= ? AND userid = ?");
					$check_stmt  = $db->prepare("SELECT id FROM passwords WHERE id=?");

					if($insert_stmt && $update_stmt){
						$insert_stmt->bind_param("isss", $update_userid, $update_enc_key, $update_data, $update_tags);
						$update_stmt->bind_param("sssii", $update_enc_key, $update_data, $update_tags, $update_id, $update_userid);
						$check_stmt->bind_param("i", $check_id);

                        $update_userid = $user_info['id'];
                        
                        $ids = [];

						foreach($data as $value){
                            $id = -1;
							if(isset($value['id']) && isset($value['enc_key']) && isset($value['data']) && isset($value['tags'])){
								if(is_integer($value['id'])){
									$update_enc_key = $value['enc_key'];
									$update_data = $value['data'];
									$update_tags = "";

									foreach($value['tags'] as $tag){
										$update_tags .= ';' . $tag;
									}

									if($value['id'] != -1){
										$check_id = $value['id'];
										$check_stmt->execute();
										
										if($check_stmt->get_result()->num_rows != 1){
											$value['id'] = -1;
										}
									}

									if($value['id'] == -1){
                                        $insert_stmt->execute();
                                        
                                        $id = $insert_stmt->insert_id;
									}else{
										$update_id = $value['id'];
                                        $update_stmt->execute();
                                        
                                        $id = $value['id'];
									}
								}
                            }
                            $ids[] = $id;
						}

						echo json_encode($ids);
						$insert_stmt->close();
						$update_stmt->close();
						$check_stmt->close();
						$db->close();
						exit;
					}

					$db->close();
				}
			}else{
				http_response_code(400);
				echo json_encode(array("error"=>"No data specified"));
				exit;
			}

			http_response_code(500);
			echo json_encode(array("error"=>"Error"));
			exit;
		}
	});

	$router->map( 'OPTIONS', '*', function(){
		header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
		echo json_encode(array("info"=>"Passwordmanager API v1.0"));
		exit;
	});

	$match = $router->match();

	if( $match && is_callable( $match['target'] ) ) {
		call_user_func_array( $match['target'], $match['params'] );
	} else {
		http_response_code(400);
		echo json_encode(array("error"=>"Method not found"));
		exit;
	}
 ?>
