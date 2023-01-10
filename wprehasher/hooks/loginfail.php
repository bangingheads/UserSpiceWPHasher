<?php if(count(get_included_files()) ==1) die(); //Direct Access Not Permitted ?>

<?php

include __DIR__ . "/../assets/class-phpass.php";
global $db, $user, $remember, $abs_us_root, $us_url_root;

$q = $db->query("SELECT * FROM users WHERE email = ? OR username = ?;", [Input::get('username'), Input::get('username')]);

if($q->error() || $q->count() == 0) {
    return;
}

$test = $q->first();
$hash = $test->password;
$id = $test->id;

$password_hash = new PasswordHash(8, true);

if ($password_hash->CheckPassword($_POST['password'], $hash)) {
    $password = password_hash(Input::get('password', true), PASSWORD_BCRYPT, ['cost' => 12]);
    $db->query("UPDATE users SET password = ? WHERE id = ?", [$password, $id]);
    $user->loginEmail(Input::get('username'), Input::get('password'), $remember);
    $hooks =  getMyHooks(['page'=>'loginSuccess']);
    includeHook($hooks,'body');
    $dest = sanitizedDest('dest');
    # if user was attempting to get to a page before login, go there
    $_SESSION['last_confirm']=date("Y-m-d H:i:s");

    if (!empty($dest)) {
      $redirect=Input::get('redirect');
      if(!empty($redirect) || $redirect!=='') Redirect::to($redirect);
      else Redirect::to($dest);
    } elseif (file_exists($abs_us_root.$us_url_root.'usersc/scripts/custom_login_script.php')) {

      # if site has custom login script, use it
      # Note that the custom_login_script.php normally contains a Redirect::to() call
      require_once $abs_us_root.$us_url_root.'usersc/scripts/custom_login_script.php';
    } else {
      if (($dest = Config::get('homepage')) ||
      ($dest = 'account.php')) {
        Redirect::to($dest);
      }
    }
}