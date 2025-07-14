<?php
/*
 phpMochiAdmin - Enhanced MySQL Database Administration Tool
 Based on PHP Mini MySQL Admin by Oleg Savchuk

*/

// CRITICAL SECURITY SETTING: Set a strong password to protect database access
// This password protects your entire database from unauthorized access
// Use a strong password with at least 12 characters, including letters, numbers, and symbols
$ACCESS_PWD = ''; #!!!IMPORTANT!!! this is script access password, SET IT if you want to protect you DB from public access

#DEFAULT db connection settings
# --- WARNING! --- if you set defaults - it's recommended to set $ACCESS_PWD to protect your db!
$DBSERVERS = []; #array of arrays ['iname'=>'srv name', 'config'=>[see $DBDEF]] - define if you need manage multiple db servers
$DBDEF = array(
'user' => "",#required
'pwd' => "", #required
#optional:
'db' => "",  #default DB
'host' => "",
'port' => "",
'socket' => "",
'chset' => "utf8mb4",#optional, default charset
#optional paths for ssl
'ssl_key' => null,
'ssl_cert' => null,
'ssl_ca' => '',#minimum this is required for ssl connections, if set - ssl connection will try to be established. Example: /path/to/cacert.pem
);
// Security setting: LOAD DATA LOCAL INFILE disabled by default to prevent data exfiltration
// This prevents attackers from reading arbitrary files from the server
$IS_LOCAL_INFILE = false; #by default disable LOAD DATA LOCAL INFILE
$IS_COUNT = false; #set to true if you want to see Total records when pagination occurs (SLOWS down all select queries!)
$DUMP_FILE = dirname(__FILE__).'/pmadump'; #path to file without extension used for server-side exports (timestamp, .sql/.csv/.gz extension added) or imports(.sql)
if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set('UTC');
}#required by PHP 5.1+

//constants
$VERSION = 'phpMochiAdmin 0.1';
$MAX_ROWS_PER_PAGE = 50; #max number of rows in select per one page
$D = "\r\n"; #default delimiter for export
$BOM = chr(239).chr(187).chr(191);
$SHOW_D = "SHOW DATABASES";
$SHOW_T = "SHOW TABLE STATUS";
$DB = []; #working copy for DB settings
$SRV = '';#selected server iname
$self = $_SERVER['PHP_SELF'];

$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
@session_set_cookie_params(0, null, null, $secure, true);
ini_set('session.use_only_cookies', 1);
@session_start();

// Security improvement: Generate stronger CSRF token using dedicated function
if (!isset($_SESSION['XSS'])) {
    $_SESSION['XSS'] = create_safe_token(32);
}
$xurl = 'XSS='.$_SESSION['XSS'];

ini_set('display_errors', 0);  #turn on to debug db or script issues
error_reporting(E_ALL ^ E_NOTICE);

file_exists($f = dirname(__FILE__) . '/phpminiconfig.php') && require($f); // Read from config (easier to update/override)

// Security improvement: Clean functional login handling
if (isset($_REQUEST['login'])) {
    $provided_password = $_REQUEST['pwd'] ?? '';
    $login_result = process_login_attempt($provided_password, $ACCESS_PWD);

    if (!$login_result['success']) {
        $err_msg = $login_result['error'];
    } else {
        loadcfg();
    }
}

if (isset($_REQUEST['logoff'])) {
    check_xss();
    $_SESSION = [];
    savecfg();
    session_destroy();
    $url = $self;
    if (!$ACCESS_PWD) {
        $url = '/';
    }
    header("location: $url");
    exit;
}

if (!isset($_SESSION['is_logged'])) {
    if (empty($ACCESS_PWD)) {
        if (isTrusted()) {
            $_SESSION['is_logged'] = true;
            loadcfg();
        } else {
            die("Set ACCESS_PWD to protect your database.");
        }
    } else {
        print_login();
        exit;
    }
}
if (isset($_REQUEST['savecfg'])) {
    check_xss();
    savecfg();
}

loadsess();

if (isset($_REQUEST['showcfg'])) {
    print_cfg();
    exit;
}

//get initial values
$SQLq = trim(b64d($_REQUEST['q'] ?? ''));
$page = intval($_REQUEST['p'] ?? 0);
$isRefresh = intval($_REQUEST['refresh'] ?? 0);
if ($isRefresh && $DB['db'] && preg_match('/^show/', $SQLq)) {
    $SQLq = $SHOW_T;
}

if (db_connect('nodie')) {
    $time_start = microtime_float();

    // Functional router - clean and simple
    $response = route_request($_REQUEST, $DB, $SQLq, $isRefresh);

    $time_all = ceil((microtime_float() - $time_start) * 10000) / 10000;
    print_screen();
} else {
    print_cfg();
}

// =====================================================================
// FUNCTIONAL ROUTER SYSTEM - Laravel/CodeIgniter inspired but functional
// =====================================================================

/**
 * Main router - determines which handler to call based on request
 */
function route_request($request, $db, $sql_query, $is_refresh)
{
    // Define routes with their conditions and handlers (PHP 7.0+ compatible)
    $routes = [
        'phpinfo' => ['condition' => 'pi', 'handler' => 'handle_phpinfo'],
        'export_show' => ['condition' => 'shex', 'handler' => 'handle_export_show'],
        'export_do' => ['condition' => 'doex', 'handler' => 'handle_export_do'],
        'import_show' => ['condition' => 'shim', 'handler' => 'handle_import_show'],
        'import_do' => ['condition' => 'doim', 'handler' => 'handle_import_do'],
        'show_tables' => ['condition' => 'dosht', 'handler' => 'handle_show_tables'],
        'create_db' => ['condition' => 'crdb', 'handler' => 'handle_create_database'],
        'sql_query' => ['condition' => null, 'handler' => 'handle_sql_query'] // fallback
    ];

    // Route resolution (PHP 7.0+ compatible)
    foreach ($routes as $route_name => $route) {
        $condition_key = $route['condition'];

        // Check if condition matches (null means fallback route)
        if ($condition_key === null || isset($request[$condition_key])) {
            return call_user_func($route['handler'], $request, $db, $sql_query, $is_refresh);
        }
    }

    return ['status' => 'no_route'];
}

/**
 * Route handlers - clean, functional, single responsibility
 */
function handle_phpinfo($request, $db, $sql_query, $is_refresh)
{
    global $sqldr;
    ob_start();
    phpinfo();
    $html = ob_get_clean();
    preg_match("/<body[^>]*>(.*?)<\/body>/is", $html, $m);
    $sqldr = '<div class="pi">' . $m[1] . '</div>';
    return ['status' => 'success', 'type' => 'phpinfo'];
}

function handle_export_show($request, $db, $sql_query, $is_refresh)
{
    if (!$db['db']) {
        return handle_no_database($request, $db, $sql_query, $is_refresh);
    }
    print_export();
    return ['status' => 'success', 'type' => 'export_show'];
}

function handle_export_do($request, $db, $sql_query, $is_refresh)
{
    if (!$db['db']) {
        return handle_no_database($request, $db, $sql_query, $is_refresh);
    }
    check_xss();
    do_export();
    return ['status' => 'success', 'type' => 'export_do'];
}

function handle_import_show($request, $db, $sql_query, $is_refresh)
{
    if (!$db['db']) {
        return handle_no_database($request, $db, $sql_query, $is_refresh);
    }
    print_import();
    return ['status' => 'success', 'type' => 'import_show'];
}

function handle_import_do($request, $db, $sql_query, $is_refresh)
{
    if (!$db['db']) {
        return handle_no_database($request, $db, $sql_query, $is_refresh);
    }
    check_xss();
    do_import();
    return ['status' => 'success', 'type' => 'import_do'];
}

function handle_show_tables($request, $db, $sql_query, $is_refresh)
{
    if (!$db['db']) {
        return handle_no_database($request, $db, $sql_query, $is_refresh);
    }
    check_xss();
    do_sht();
    return ['status' => 'success', 'type' => 'show_tables'];
}

function handle_create_database($request, $db, $sql_query, $is_refresh)
{
    global $err_msg, $SHOW_D;

    check_xss();
    $new_db = trim($request['new_db'] ?? '');
    $validation = validate_database_name($new_db);

    if (!$validation['valid']) {
        $err_msg = $validation['error'];
        return ['status' => 'error', 'message' => $validation['error']];
    }

    try {
        do_sql('CREATE DATABASE ' . dbqid($new_db));
        do_sql($SHOW_D);
        return ['status' => 'success', 'type' => 'create_database'];
    } catch (Exception $e) {
        $err_msg = "Invalid database name: " . htmlspecialchars($new_db);
        return ['status' => 'error', 'message' => $err_msg];
    }
}

function handle_sql_query($request, $db, $sql_query, $is_refresh)
{
    global $err_msg, $SHOW_D;

    if ($db['db']) {
        // Database selected - handle SQL queries
        if (!$is_refresh || preg_match('/^select|with|show|explain|desc/i', $sql_query)) {
            if ($sql_query) {
                check_xss();
            }
            do_sql($sql_query);
            return ['status' => 'success', 'type' => 'sql_query'];
        }
    } else {
        // No database selected
        if ($is_refresh) {
            check_xss();
            do_sql($SHOW_D);
            return ['status' => 'success', 'type' => 'show_databases'];
        } elseif (preg_match('/^(?:show\s+(?:databases|status|variables|process)|create\s+database|grant\s+)/i', $sql_query)) {
            check_xss();
            $validation = validate_sql_query($sql_query);

            if (!$validation['valid']) {
                $err_msg = $validation['error'];
                return ['status' => 'error', 'message' => $validation['error']];
            }

            do_sql($sql_query);
            return ['status' => 'success', 'type' => 'sql_query'];
        } else {
            $err_msg = "Select Database first";
            if (!$sql_query) {
                do_sql($SHOW_D);
            }
            return ['status' => 'error', 'message' => 'No database selected'];
        }
    }

    return ['status' => 'success', 'type' => 'default'];
}

function handle_no_database($request, $db, $sql_query, $is_refresh)
{
    global $err_msg;
    $err_msg = "Select Database first";
    return ['status' => 'error', 'message' => 'No database selected'];
}

function print_screen()
{
    global $sqldr, $time_all, $out_message, $SQLq, $reccount, $is_sht;

    print_header();

    // Prepare template data for main interface
    $template_data = [
        'sql_query' => $SQLq ?? '',
        'has_results' => !empty($sqldr),
        'content' => $sqldr ?? '',
        'execution_time' => $time_all ?? 0,
        'message' => $out_message ?? '',
        'record_count' => $reccount ?? 0,
        'is_show_tables' => $is_sht ?? false
    ];

    // Render main interface using template
    echo render_template('main_interface', $template_data);

    // Use print_footer
    print_footer();
}

function print_footer()
{
    echo tpl_footer();
}

function do_sql($q)
{
    global $dbh,$last_sth,$last_sql,$reccount,$out_message,$SQLq,$SHOW_T,$DB;
    $SQLq = $q;

    $is_shts = 0;
    if ($q == $SHOW_T) {
        #emulate show table status faster
        $is_shts = 1;
        $q = "select TABLE_NAME as Name,Engine,Version,Row_format,TABLE_ROWS as `Rows`,Avg_row_length,Data_length,Max_data_length,Index_length,TABLE_COMMENT as Comment
from information_schema.TABLES where TABLE_TYPE IN ('BASE TABLE','VIEW')
and TABLE_SCHEMA=".dbq($DB['db']);
    }

    if (!do_multi_sql($q)) {
        $out_message = "Error: ".mysqli_error($dbh);
    } else {
        if ($last_sth && $last_sql) {
            if ($is_shts) {
                $last_sql = $SHOW_T;
            }
            $SQLq = $last_sql;
            if (preg_match("/^select|with|show|explain|desc/i", $last_sql)) {
                if ($q != $last_sql) {
                    $out_message = "Results of the last select displayed:";
                }
                display_select($last_sth, $last_sql);
            } else {
                $reccount = mysqli_affected_rows($dbh);
                $out_message = "Done.";
                if (preg_match("/^insert|replace/i", $last_sql)) {
                    $out_message .= " Last inserted id=".get_identity();
                }
                if (preg_match("/^drop|truncate/i", $last_sql)) {
                    do_sql($SHOW_T);
                }
            }
        }
    }
}

// Functional refactored display_select - clean and maintainable!
function display_select($sth, $q)
{
    global $dbh, $SRV, $DB, $sqldr, $reccount, $is_sht, $xurl, $is_sm;

    // Early return for invalid results
    if ($sth === false || $sth === true) {
        return;
    }

    // Extract data from result set
    $reccount = mysqli_num_rows($sth);
    $fields_num = mysqli_field_count($dbh);

    // Detect query type using pure function
    $query_type = detect_query_type($q);
    $is_sht = $query_type['is_show_tables']; // Update global for compatibility

    // Create configuration object
    $config = [
        'xurl' => $xurl,
        'db' => ue($DB['db']),
        'srv' => ue($SRV),
        'is_sm' => $is_sm
    ];

    // Get field names
    $field_names = [];
    mysqli_field_seek($sth, 0);
    for ($i = 0; $i < $fields_num; $i++) {
        $meta = mysqli_fetch_field($sth);
        $field_names[] = $meta->name;
    }

    // Build HTML using pure functions
    $sqldr = '';

    // Add info card for special query types
    $sqldr .= create_info_card($query_type, $config);

    // Add table actions section if needed
    $table_actions = create_table_actions_section($query_type);
    $sqldr .= $table_actions;

    // Determine table classes
    $table_classes = 'res';
    if ($config['is_sm']) {
        $table_classes .= ' sm';
    }
    if ($query_type['is_show_tables'] || $query_type['is_show_databases']) {
        $table_classes .= ' wa';
    }

    // Start table with proper container structure
    $sqldr .= "<div class='table-container'>";

    // Only add table-container-inner div if not show_tables (which adds it in table_actions)
    if (!$query_type['is_show_tables']) {
        $sqldr .= "<div class='table-container-inner'>";
    }

    $sqldr .= "<table id='res' class='{$table_classes}'>";

    // Add headers
    $sqldr .= create_table_headers($query_type, $field_names);

    // Add rows
    $sqldr .= render_table_rows($sth, $query_type, $config, $field_names, $fields_num);

    // Close table
    $sqldr .= "</table>";

    // Close table-container-inner if we opened it
    if (!$query_type['is_show_tables']) {
        $sqldr .= "</div>"; // Close table-container-inner
    }

    // Close main table container
    $sqldr .= "</div>\n"; // Close table-container
}

function render_table_rows($sth, $query_type, $config, $field_names, $fields_num)
{
    $html = '';
    $row_classes = ["o", "e"];
    $row_toggle = false;

    mysqli_data_seek($sth, 0); // Reset result pointer

    while ($row = mysqli_fetch_row($sth)) {
        $row_class = $row_classes[$row_toggle = !$row_toggle];

        if ($query_type['is_show_tables']) {
            $content = render_show_tables_row($row, $config, $fields_num);
        } elseif ($query_type['is_show_databases']) {
            $content = render_show_databases_row($row, $config);
        } else {
            $content = render_regular_row($row, $fields_num, $query_type['is_show_create']);
        }

        $template_data = [
            'row_class' => $row_class,
            'content' => $content
        ];

        $html .= render_template('table_row', $template_data);
    }

    return $html;
}

function render_show_tables_row($row, $config, $fields_num)
{
    $table_name = $row[0];
    $table_quoted = dbqid($table_name);
    $url = "?{$config['xurl']}&db={$config['db']}&srv={$config['srv']}&t=" . b64u($table_name);
    $table_url = $url . "&q=" . b64u("select * from {$table_quoted}");

    $template_data = [
        'table_quoted' => $table_quoted,
        'table_url' => $table_url,
        'table_name' => $table_name,
        'engine' => $row[1],
        'rows' => $row[4],
        'data_size' => $row[6],
        'index_size' => $row[8],
        'actions' => render_table_row_actions($url, $table_name, $table_quoted),
        'comment' => $row[$fields_num - 1]
    ];

    return render_template('show_tables_row', $template_data);
}

function render_show_databases_row($row, $config)
{
    $db_name = $row[0];
    $db_quoted = dbqid($db_name);
    $url = "?{$config['xurl']}&db=" . ue($db_name) . "&srv={$config['srv']}";
    $db_url = $url . "&q=" . b64u("SHOW TABLE STATUS");

    $template_data = [
        'db_name' => $db_name,
        'db_url' => $db_url,
        'actions' => render_database_row_actions($url, $db_name, $db_quoted)
    ];

    return render_template('show_databases_row', $template_data);
}

function render_regular_row($row, $fields_num, $is_show_create)
{
    $cells = [];

    for ($i = 0; $i < $fields_num; $i++) {
        $cells[] = format_cell_value($row[$i], $is_show_create);
    }

    $template_data = [
        'cells' => $cells
    ];

    return render_template('regular_row', $template_data);
}

function print_header()
{
    global $err_msg,$VERSION,$DBSERVERS,$SRV,$DB,$dbh,$self,$is_sht,$xurl,$SHOW_T;

    // Use the new template system!
    $template_data = [
        'title' => 'phpMochiAdmin',
        'version' => $VERSION,
        'is_logged' => $_SESSION['is_logged'] ?? false,
        'has_connection' => !!$dbh,
        'servers' => $DBSERVERS,
        'current_server' => $SRV,
        'db' => $DB['db'],
        'xurl' => $xurl,
        'self' => $self,
        'show_tables' => $SHOW_T,
        'db_options' => get_db_select($DB['db']),
        'xss_token' => $_SESSION['XSS'] ?? '',
        'error_message' => $err_msg,
        'content' => ''
    ];

    echo render_template('layout_start', $template_data);
}


function print_login()
{
    global $err_msg;

    $template_data = [
        'self' => $_SERVER['PHP_SELF'],
        'error_message' => $err_msg
    ];

    echo render_template('login', $template_data);
}


function print_cfg()
{
    global $DB, $err_msg, $self;

    // Use print_header which now uses templates
    print_header();

    // Prepare template data
    $template_data = [
        'user' => $DB['user'] ?? '',
        'db' => $DB['db'] ?? '',
        'host' => $DB['host'] ?? '',
        'port' => $DB['port'] ?? '',
        'socket' => $DB['socket'] ?? '',
        'charset_options' => chset_select($DB['chset'] ?? ''),
        'self' => $self
    ];

    // Render config form using template
    echo render_template('config_form', $template_data);

    // Use print_footer
    print_footer();
}


// Pure validation functions for better security and maintainability
function validate_database_name($name)
{
    if (empty($name)) {
        return ['valid' => false, 'error' => 'Database name cannot be empty'];
    }

    if (strlen($name) > 64) {
        return ['valid' => false, 'error' => 'Database name too long (max 64 characters)'];
    }

    if (!preg_match('/^[a-zA-Z0-9_]+$/', $name)) {
        return ['valid' => false, 'error' => 'Database name contains invalid characters'];
    }

    return ['valid' => true, 'error' => null];
}

function validate_sql_query($sql)
{
    $sql = trim($sql);

    if (strlen($sql) > 1000) {
        return ['valid' => false, 'error' => 'SQL query too long (max 1000 characters)'];
    }

    $dangerous_patterns = [
        '/union\s+select/i',
        '/load_file\(/i',
        '/into\s+outfile/i',
        '/into\s+dumpfile/i'
    ];

    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $sql)) {
            return ['valid' => false, 'error' => 'SQL query contains potentially dangerous patterns'];
        }
    }

    return ['valid' => true, 'error' => null];
}

function create_safe_token($length = 32)
{
    if ($length < 16) {
        $length = 16;
    }
    if ($length > 128) {
        $length = 128;
    }

    return get_rand_str($length);
}

function validate_csrf_token($session_token, $request_token)
{
    if (empty($session_token) || empty($request_token)) {
        return false;
    }

    return hash_equals($session_token, $request_token);
}

function create_error_response($message, $log_context = [])
{
    if (!empty($log_context['ip'])) {
        error_log("Security event: {$message} from IP: {$log_context['ip']}");
    }

    return ['success' => false, 'error' => $message];
}

function create_success_response($data = [])
{
    return array_merge(['success' => true, 'error' => null], $data);
}

// Pure functions for login attempt management
function initialize_login_tracking()
{
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['last_attempt_time'] = time();
    }
}

function should_reset_login_attempts($last_attempt_time, $reset_window = 900)
{
    return (time() - $last_attempt_time) > $reset_window;
}

function is_rate_limited($attempts, $max_attempts = 5)
{
    return $attempts >= $max_attempts;
}

function calculate_remaining_lockout_time($last_attempt_time, $lockout_duration = 900)
{
    return $lockout_duration - (time() - $last_attempt_time);
}

function validate_login_password($provided_password, $expected_password)
{
    if (empty($expected_password) && empty($provided_password)) {
        return true;
    }

    if (empty($expected_password) || empty($provided_password)) {
        return false;
    }

    return hash_equals($expected_password, $provided_password);
}

function create_rate_limit_message($remaining_time)
{
    $minutes = ceil($remaining_time / 60);
    return "Too many failed login attempts. Please wait {$minutes} minutes before trying again.";
}

function create_failed_login_message($remaining_attempts)
{
    return "Invalid password. Try again. ({$remaining_attempts} attempts remaining)";
}

function reset_login_attempts()
{
    $_SESSION['login_attempts'] = 0;
}

function increment_login_attempts()
{
    $_SESSION['login_attempts']++;
    $_SESSION['last_attempt_time'] = time();
}

function process_login_attempt($provided_password, $expected_password)
{
    initialize_login_tracking();

    // Reset attempts if window has expired
    if (should_reset_login_attempts($_SESSION['last_attempt_time'])) {
        reset_login_attempts();
    }

    // Check rate limiting
    if (is_rate_limited($_SESSION['login_attempts'])) {
        $remaining_time = calculate_remaining_lockout_time($_SESSION['last_attempt_time']);
        return create_error_response(create_rate_limit_message($remaining_time));
    }

    // Validate password
    if (!validate_login_password($provided_password, $expected_password)) {
        increment_login_attempts();
        $remaining_attempts = 5 - $_SESSION['login_attempts'];
        return create_error_response(create_failed_login_message($remaining_attempts));
    }

    // Successful login
    reset_login_attempts();
    $_SESSION['is_logged'] = true;

    return create_success_response(['message' => 'Login successful']);
}

// Ultra-simple template system using ob_start() - all templates in same file
function render_template($template_name, $data = [])
{
    $function_name = "tpl_{$template_name}";

    if (!function_exists($function_name)) {
        return "<!-- Template '{$template_name}' not found -->";
    }

    return $function_name($data);
}

function tpl_layout($data)
{
    ob_start(); ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title><?= hs($data['title'] ?? 'phpMochiAdmin') ?></title>
        <meta charset="utf-8">
        <?= tpl_css_styles() ?>
        <?= tpl_javascript() ?>
    </head>
    <body onload="after_load()">
        <?= tpl_form_start($data) ?>
        <?= tpl_navigation($data) ?>
        <div class="container">
            <?= tpl_error_message($data) ?>
            <?= $data['content'] ?? '' ?>
        </div>
        <?= tpl_footer() ?>
        </form>
    </body>
    </html>
    <?php return ob_get_clean();
}

function tpl_layout_start($data)
{
    ob_start(); ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title><?= hs($data['title'] ?? 'phpMochiAdmin') ?></title>
        <meta charset="utf-8">
        <?= tpl_css_styles() ?>
        <?= tpl_javascript() ?>
    </head>
    <body onload="after_load()">
        <?= tpl_form_start($data) ?>
        <?= tpl_navigation($data) ?>
        <div class="container">
            <?= tpl_error_message($data) ?>
    <?php return ob_get_clean();
}

function tpl_login($data)
{
    ob_start(); ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>phpMochiAdmin Login</title>
        <meta charset="utf-8">
        <?= tpl_login_styles() ?>
    </head>
    <body>
        <form method="post" action="<?= hs($data['self']) ?>">
            <div class="login-card">
                <div class="login-header">
                    <h1 class="login-title">🍡 phpMochiAdmin</h1>
                    <p class="login-subtitle">Database access is protected by password</p>
                </div>

                <?= tpl_error_message($data) ?>

                <div class="form-group">
                    <label for="pwd" class="form-label">Password</label>
                    <input type="password" name="pwd" id="pwd" class="form-input"
                           placeholder="Enter your password" autofocus>
                    <input type="hidden" name="login" value="1">
                </div>

                <button type="submit" class="btn">
                    🔓 Login to Database
                </button>
            </div>
        </form>
    </body>
    </html>
    <?php return ob_get_clean();
}

function tpl_main_interface($data)
{
    ob_start(); ?>
    <?= tpl_query_form($data) ?>
    <?= tpl_results_section($data) ?>
    <?php return ob_get_clean();
}

function tpl_query_form($data)
{
    ob_start(); ?>
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">
                SQL Query
                <div style="float:right;display:flex;gap:0.5rem;align-items:center;">
                    <button type="button" class="btn btn-ghost btn-sm" onclick="q_prev()" title="Previous query">&lt;</button>
                    <button type="button" class="btn btn-ghost btn-sm" onclick="q_next()" title="Next query">&gt;</button>
                </div>
            </h2>
        </div>

        <div class="form-group">
            <label for="qraw" class="form-label">SQL query (or multiple queries separated by ";"):</label>
            <textarea id="qraw" class="form-textarea" rows="8"
                      placeholder="Enter your SQL query here..."><?= hs($data['sql_query'] ?? '') ?></textarea>
            <input type="hidden" name="q" id="q" value="<?= hs(base64_encode($data['sql_query'] ?? '')) ?>">
        </div>

        <div class="query-buttons">
            <button type="submit" name="GoSQL" class="btn btn-primary">
                <span>Execute Query</span>
            </button>
            <button type="button" class="btn btn-secondary" onclick="$('qraw').value='';">
                Clear
            </button>

            <?php if ($data['has_db'] ?? false): ?>
            <div style="margin-left:auto;display:flex;gap:0.5rem;flex-wrap:wrap;">
                <?php foreach ($data['template_buttons'] ?? [] as $name => $template): ?>
                <button type="button" class="btn btn-ghost btn-sm"
                        onclick="qtpl('<?= hs(addslashes($template)) ?>')"><?= hs(ucfirst($name)) ?></button>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php return ob_get_clean();
}

function tpl_results_section($data)
{
    if (!($data['has_results'] ?? false)) {
        return '';
    }

    ob_start(); ?>
    <div class="card">
        <div class="card-header">
            <h2 class="card-title">
                Query Results
                <div style="float:right;display:flex;gap:1rem;align-items:center;font-size:0.875rem;font-weight:normal;">
                    <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;">
                        <input type="checkbox" name="is_sm" value="1" id="is_sm" onclick="smview()"
                               <?= ($data['compact_view'] ?? false) ? 'checked' : '' ?>>
                        Compact view
                    </label>
                    <span class="text-muted">
                        Records: <strong><?= hs($data['record_count'] ?? 0) ?><?php
    if (!is_null($data['total_count'] ?? null) && ($data['record_count'] ?? 0) < $data['total_count']) {
        echo ' of ' . hs($data['total_count']);
    } ?></strong>
                        in <strong><?= hs($data['execution_time'] ?? '0') ?></strong> sec
                    </span>
                </div>
            </h2>
        </div>

        <?php if ($data['message'] ?? ''): ?>
        <div class="message message-success">
            <?= hs($data['message']) ?>
        </div>
        <?php endif; ?>

        <?php if ($data['content'] ?? ''): ?>
            <?= ($data['pagination_html'] ?? '') . $data['content'] . ($data['pagination_html'] ?? '') ?>
        <?php endif; ?>
    </div>
    <?php return ob_get_clean();
}

function tpl_navigation($data)
{
    ob_start(); ?>
    <nav class="nav">
        <div class="nav-content">
            <a href="https://github.com/phpMochiAdmin/phpMochiAdmin" target="_blank" class="nav-brand">
                🍡 <?= hs($data['version'] ?? 'phpMochiAdmin') ?>
            </a>
            <div class="nav-links">
                <?= tpl_database_navigation($data) ?>
                <?= tpl_utility_navigation($data) ?>
            </div>
        </div>
    </nav>
    <?php return ob_get_clean();
}

function tpl_database_navigation($data)
{
    if (!($data['is_logged'] ?? false) || !($data['has_connection'] ?? false)) {
        return '';
    }

    ob_start(); ?>
    <?php if ($data['servers'] ?? []): ?>
        <label>Servers:</label>
        <select name="srv" onChange="frefresh()" class="nav-select">
            <option value=''>- select/refresh -</option>
            <?= sel($data['servers'], 'iname', $data['current_server'] ?? '') ?>
        </select>
    <?php endif; ?>

    <a href="?<?= hs($data['xurl'] ?? '') ?>&db=<?= ue($data['db'] ?? '') ?>&srv=<?= ue($data['current_server'] ?? '') ?>&q=<?= b64u("show processlist") ?>">⚡ Processes</a>
    <a href="?<?= hs($data['xurl'] ?? '') ?>&q=<?= b64u("show databases") ?>">🗂️ Databases</a>

    <select name="db" onChange="frefresh()" class="nav-select">
        <option value='*'> - select/refresh -</option>
        <option value=''> - show all -</option>
        <?= $data['db_options'] ?? '' ?>
    </select>

    <?php if ($data['db'] ?? ''): ?>
        <?php $base_url = "href='" . hs($data['self'] ?? '') . "?" . hs($data['xurl'] ?? '') . "&db=" . ue($data['db']) . "&srv=" . ue($data['current_server'] ?? ''); ?>
        <a <?= $base_url ?>&q=<?= b64u($data['show_tables'] ?? '') ?>'">📋 Tables</a>
        <a <?= $base_url ?>&shex=1'">📊 Export</a>
        <a <?= $base_url ?>&shim=1'">📤 Import</a>
    <?php endif; ?>
    <?php return ob_get_clean();
}

function tpl_utility_navigation($data)
{
    ob_start(); ?>
    <a href="?showcfg=1">⚙️ Settings</a>
    <?php if ($data['is_logged'] ?? false): ?>
        <a href="?<?= hs($data['xurl'] ?? '') ?>&logoff=1" onclick="logoff()">🚪 Logoff</a>
    <?php endif; ?>
    <a href="?pi=1">ℹ️ PHP Info</a>
    <?php return ob_get_clean();
}

function tpl_error_message($data)
{
    $message = $data['error_message'] ?? '';
    if (!$message) {
        return '';
    }

    ob_start(); ?>
    <div class="message message-error" style="margin:1rem 0;">
        <?= hs($message) ?>
    </div>
    <?php return ob_get_clean();
}

function tpl_form_start($data)
{
    ob_start(); ?>
    <form method="post" name="DF" id="DF" action="<?= hs($data['self'] ?? '') ?>" enctype="multipart/form-data">
        <input type="hidden" name="XSS" value="<?= hs($data['xss_token'] ?? '') ?>">
        <input type="hidden" name="refresh" value="">
        <input type="hidden" name="p" value="">
    <?php return ob_get_clean();
}

function tpl_export_form($data)
{
    ob_start(); ?>
    <center>
    <h3>Export <?= hs($data['export_label']) ?></h3>
    <div class="frm">
    <input type="checkbox" name="s" value="1" checked> Structure<br>
    <input type="checkbox" name="d" value="1" checked> Data<br><br>
    <div><label><input type="radio" name="et" value="" checked> .sql</label>&nbsp;</div>
    <div>
    <?php if ($data['show_csv_option']): ?>
     <label><input type="radio" name="et" value="csv"> .csv (Excel style, data only and for one table only)</label>
    <?php else: ?>
    <label>&nbsp;( ) .csv</label> <small>(to export as csv - go to 'show tables' and export just ONE table)</small>
    <?php endif; ?>
    </div>
    <br>
    <div><label><input type="checkbox" name="sp" value="1"> import has super privileges</label></div>
    <div><label><input type="checkbox" name="gz" value="1"> compress as .gz</label></div>
    <div style="display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap;">
    <input type="hidden" name="doex" value="1">
    <input type="hidden" name="rt" value="<?= hs($data['table_name']) ?>">
    <button type="submit" class="btn btn-primary">⬇️ Download</button>
    <button type="submit" name="issrv" class="btn btn-secondary">💾 Dump on Server</button>
    <button type="button" class="btn btn-ghost" onclick="window.location='<?= hs($data['self_url'].'?'.$data['xurl'].'&db='.ue($data['database'])."&srv=".ue($data['server'])) ?>'">❌ Cancel</button>
    </div>
    <p><small>"Dump on Server" exports to file:<br><?= hs($data['dump_file']) ?></small></p>
    </div>
    </center>
    <?php return ob_get_clean();
}

function tpl_import_form($data)
{
    ob_start(); ?>
    <center>
    <h3>Import DB</h3>
    <div class="frm">
    <div><label><input type="radio" name="it" value="" checked> import by uploading <b>.sql</b> or <b>.gz</b> file:</label>
     <input type="file" name="file1" value="" size=40><br>
    </div>
    <div><label><input type="radio" name="it" value="sql"> import from file on server:<br>
     <?= hs($data['dump_file_sql']) ?></label></div>
    <div><label><input type="radio" name="it" value="gz"> import from file on server:<br>
     <?= hs($data['dump_file_gz']) ?></label></div>
    <input type="hidden" name="doim" value="1">
    <div style="display:flex;gap:0.5rem;margin-top:1rem;flex-wrap:wrap;">
    <button type="submit" class="btn btn-primary" onclick="return ays()">⬆️ Import</button>
    <button type="button" class="btn btn-secondary" onclick="window.location='<?= hs($data['self_url'].'?'.$data['xurl'].'&db='.ue($data['database'])."&srv=".ue($data['server'])) ?>'">❌ Cancel</button>
    </div>
    </div>
    </center>
    <?php return ob_get_clean();
}

function tpl_footer()
{
    ob_start(); ?>
    <footer style="background:#ffffff;border-top:1px solid #e2e8f0;padding:2rem;text-align:center;color:#64748b;font-size:0.875rem;margin-top:2rem;">
        🍡 phpMochiAdmin - Enhanced with functional programming<br>
        Based on phpMiniAdmin &copy; 2004-2024 <a href="http://osalabs.com" target="_blank" style="color:#3b82f6;text-decoration:none;">Oleg Savchuk</a>
    </footer>
    <?php return ob_get_clean();
}

function tpl_css_styles()
{
    ob_start(); ?>
    <style>
    /* Modern ShadCN-inspired CSS for phpMochiAdmin */
    :root{
      --bg:#f8fafc;--text:#0f172a;--muted:#64748b;--border:#e2e8f0;
      --card:#ffffff;--accent:#3b82f6;--accent-dark:#2563eb;--radius:6px;
      --shadow:0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      --shadow-sm:0 1px 2px 0 rgba(0, 0, 0, 0.05);
      --success:#10b981;--warning:#f59e0b;--error:#ef4444;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      line-height: 1.6;
      font-size: 14px;
      margin: 0;
      padding: 0;
      min-height: 100vh;
    }

    /* Layout */
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 1rem;
    }

    /* Navigation bar */
    .nav {
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 1rem 0;
      margin-bottom: 2rem;
      box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
      width: 100%;
      display: block;
    }

    .nav-content {
      display: flex;
      align-items: center;
      gap: 1rem;
      flex-wrap: wrap;
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 1rem;
      min-height: 60px;
    }

    .nav-brand {
      font-size: 1.125rem;
      font-weight: 600;
      color: #0f172a;
      text-decoration: none;
      margin-right: 2rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .nav-links {
      display: flex;
      gap: 0.75rem;
      align-items: center;
      flex-wrap: wrap;
      margin-left: auto;
    }

    .nav a {
      color: #64748b;
      text-decoration: none;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      transition: all 0.2s;
      font-size: 0.875rem;
      font-weight: 500;
    }

    .nav a:hover {
      color: #0f172a;
      background: #f1f5f9;
    }

    .nav-select {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      color: #0f172a;
      font-size: 0.875rem;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      margin: 0 0.25rem;
      min-width: 180px;
      max-width: 220px;
    }

    .nav-select:focus {
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
      outline: none;
    }

    /* Cards */
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: var(--shadow);
    }

    .card-header {
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid var(--border);
    }

    .card-title {
      font-size: 1.125rem;
      font-weight: 600;
      color: var(--text);
      margin: 0;
    }

    /* Forms */
    .form-group {
      margin-bottom: 1rem;
    }

    .form-label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: var(--text);
      margin-bottom: 0.5rem;
    }

    .form-input, .form-select, .form-textarea {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      font-size: 0.875rem;
      background: var(--card);
      color: var(--text);
      transition: all 0.2s;
    }

    .form-input:focus, .form-select:focus, .form-textarea:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
    }

    .form-textarea {
      resize: vertical;
      min-height: 120px;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      font-weight: 500;
      font-size: 0.875rem;
      padding: 0.75rem 1rem;
      border: 1px solid transparent;
      border-radius: var(--radius);
      cursor: pointer;
      transition: all 0.2s;
      text-decoration: none;
      white-space: nowrap;
    }

    .btn-primary {
      background: var(--accent);
      color: white;
    }

    .btn-primary:hover {
      background: var(--accent-dark);
    }

    .btn-secondary {
      background: #f3f4f6;
      color: var(--text);
      border-color: var(--border);
    }

    .btn-secondary:hover {
      background: #e5e7eb;
    }

    .btn-ghost {
      background: transparent;
      color: var(--text);
    }

    .btn-ghost:hover {
      background: #f3f4f6;
    }

    .btn-sm {
      padding: 0.5rem 0.75rem;
      font-size: 0.75rem;
    }

    .btn-success {
      background: var(--success);
      color: white;
    }

    .btn-warning {
      background: var(--warning);
      color: white;
    }

    .btn-error {
      background: var(--error);
      color: white;
    }

    /* Messages */
    .message {
      padding: 1rem;
      border-radius: var(--radius);
      margin-bottom: 1rem;
      border: 1px solid;
    }

    .message-error {
      background: #fef2f2;
      border-color: #fecaca;
      color: #991b1b;
    }

    .message-success {
      background: #f0fdf4;
      border-color: #bbf7d0;
      color: #166534;
    }

    /* Query buttons */
    .query-buttons {
      display: flex;
      gap: 0.5rem;
      margin-top: 1rem;
      flex-wrap: wrap;
    }

    /* Tables */
    .table-container {
      border-radius: var(--radius);
      border: 1px solid var(--border);
      background: var(--card);
      margin: 1rem 0;
      box-shadow: var(--shadow);
    }

    .table-container-inner {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
      margin: 0;
    }

    table.res {
      width: 100%;
    }

    table.sm {
      font-size: 0.75rem;
    }

    table.sm th, table.sm td {
      padding: 0.5rem;
    }

    table.wa {
      width: auto;
    }

    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      word-wrap: break-word;
    }

    td:first-child {
      border-left: none;
    }

    td:last-child {
      border-right: none;
    }

    th {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      background: #f9fafb;
    }

    tbody tr:hover {
      background: #f9fafb;
    }

    /* Legacy classes for compatibility */
    tr.e {
      background-color: #f9fafb;
    }

    tr.o {
      background-color: white;
    }

    tr.e:hover, tr.o:hover {
      background-color: #eff6ff;
    }

    tr.h {
      background-color: #dbeafe;
    }

    tr.s {
      background-color: #fef3c7;
    }

    /* Table actions specific styling */
    .table-actions {
      background: var(--card);
      border: 1px solid var(--border);
      border-top: none;
      border-radius: 0 0 var(--radius) var(--radius);
    }

    .table-actions-content {
      padding: 1rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .table-actions-buttons {
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }

    .table-actions-label {
      color: var(--muted);
      font-size: 0.875rem;
      white-space: nowrap;
    }

    .table-actions .btn {
      box-shadow: var(--shadow-sm);
    }

    .table-container-inner {
      border-radius: var(--radius) var(--radius) 0 0;
      overflow: hidden;
    }

    /* Database/table link styling */
    td a {
      color: var(--accent);
      text-decoration: none;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      transition: background-color 0.2s;
      display: inline-block;
      font-size: 0.75rem;
      margin: 0.125rem;
    }

    td a:hover {
      background-color: #eff6ff;
      text-decoration: none;
    }

    /* Table cell special formatting */
    td i {
      color: var(--muted);
      font-style: italic;
    }

    /* Binary/long text indicator */
    td .binary {
      background: #f3f4f6;
      color: #6b7280;
      padding: 0.25rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-family: monospace;
    }

    /* Responsive */
    @media (max-width: 768px) {
      .nav-content {
        flex-direction: column;
        gap: 1rem;
      }

      .nav-links {
        justify-content: center;
        flex-wrap: wrap;
      }

      .nav-brand {
        margin-right: 0;
        margin-bottom: 0.5rem;
      }

      .container {
        padding: 0.5rem;
      }

      .card {
        padding: 1rem;
      }

      .query-buttons {
        flex-direction: column;
      }
    }
    </style>
    <?php return ob_get_clean();
}

function tpl_login_styles()
{
    ob_start(); ?>
    <style>
    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      margin: 0;
      padding: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .login-card {
      background: white;
      border: 1px solid #e2e8f0;
      border-radius: 12px;
      padding: 2rem;
      width: 400px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .login-header {
      text-align: center;
      margin-bottom: 2rem;
    }
    .login-title {
      font-size: 1.5rem;
      font-weight: 600;
      color: #0f172a;
      margin: 0 0 0.5rem;
    }
    .login-subtitle {
      color: #64748b;
      font-size: 0.875rem;
      margin: 0;
    }
    .form-group {
      margin-bottom: 1.5rem;
    }
    .form-label {
      display: block;
      font-size: 0.875rem;
      font-weight: 500;
      color: #0f172a;
      margin-bottom: 0.5rem;
    }
    .form-input {
      width: 100%;
      padding: 0.75rem;
      border: 1px solid #e2e8f0;
      border-radius: 6px;
      font-size: 0.875rem;
      background: white;
      color: #0f172a;
      box-sizing: border-box;
    }
    .form-input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-weight: 500;
      font-size: 0.875rem;
      padding: 0.75rem 1rem;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s;
      width: 100%;
      background: #3b82f6;
      color: white;
    }
    .btn:hover {
      background: #2563eb;
    }
    .message {
      padding: 1rem;
      border-radius: 6px;
      margin-bottom: 1.5rem;
      border: 1px solid;
    }
    .message-error {
      background: #fef2f2;
      border-color: #fecaca;
      color: #991b1b;
      font-size: 0.875rem;
    }
    </style>
    <?php return ob_get_clean();
}

function tpl_javascript()
{
    ob_start(); ?>
    <script type="text/javascript">
    var LSK='pma_',LSKX=LSK+'max',LSKM=LSK+'min',qcur=0,LSMAX=32;

    function $(i){return document.getElementById(i)}
    function frefresh(){
     var F=document.DF;
     F.method='get';
     F.refresh.value="1";
     F.GoSQL.click();
    }
    function go(p,sql){
     var F=document.DF;
     F.p.value=p;
     if (sql)F.q.value=sql;
     F.GoSQL.click();
    }
    function ays(){
     return confirm('Are you sure to continue?');
    }
    function chksql(){
     var F=document.DF,v=F.qraw.value;
     if (/^\s*(?:delete|drop|truncate|alter)/.test(v)) if (!ays())return false;
     if (lschk(1)){
      var lsm=lsmax()+1,ls=localStorage;
      ls[LSK+lsm]=v;
      ls[LSKX]=lsm;
      if (!ls[LSKM])ls[LSKM]=1;
      var lsmin=parseInt(ls[LSKM]);
      if ((lsm-lsmin+1)>LSMAX){
       lsclean(lsmin,lsm-LSMAX);
      }
     }
     return true;
    }
    function lschk(skip){
     if (!localStorage || !skip && !localStorage[LSKX]) return false;
     return true;
    }
    function lsmax(){
     var ls=localStorage;
     if (!lschk() || !ls[LSKX])return 0;
     return parseInt(ls[LSKX]);
    }
    function lsclean(from,to){
     ls=localStorage;
     for (var i=from;i<=to;i++){
      delete ls[LSK+i];ls[LSKM]=i+1;
     }
    }
    function q_prev(){
     var ls=localStorage;
     if (!lschk())return;
     qcur--;
     var x=parseInt(ls[LSKM]);
     if (qcur<x)qcur=x;
     $('qraw').value=ls[LSK+qcur];
    }
    function q_next(){
     var ls=localStorage;
     if (!lschk())return;
     qcur++;
     var x=parseInt(ls[LSKX]);
     if (qcur>x)qcur=x;
     $('qraw').value=ls[LSK+qcur];
    }
    function after_load(){
     var F=document.DF;
     var p=F['v[pwd]'];
     if (p) p.focus();
     qcur=lsmax();

     F.addEventListener('submit',function(e){
      if (!F.qraw)return;
      if (!chksql()){e.preventDefault();return}
      $('q').value=btoa(encodeURIComponent($('qraw').value).replace(/%([0-9A-F]{2})/g,function(m,p){return String.fromCharCode('0x'+p)}));
     });
     var res=$('res');
     if (res)res.addEventListener('dblclick',function(e){
      if (!$('is_sm').checked)return;
      var el=e.target;
      if (el.tagName!='TD')el=el.parentNode;
      if (el.tagName!='TD')return;
      if (el.className.match(/\b\lg\b/))el.className=el.className.replace(/\blg\b/,' ');
      else el.className+=' lg';
     });
    }
    function logoff(){
     if (lschk()){
      var ls=localStorage;
      var from=parseInt(ls[LSKM]),to=parseInt(ls[LSKX]);
      for (var i=from;i<=to;i++){
       delete ls[LSK+i];
      }
      delete ls[LSKM];delete ls[LSKX];
     }
    }
    function cfg_toggle(){
     var e=$('cfg-adv');
     e.style.display=e.style.display=='none'?'':'none';
    }
    function qtpl(s){
     $('qraw').value=s.replace(/%T/g,"`<?php eo(($_REQUEST['t'] ?? 0) ? b64d($_REQUEST['t']) : 'tablename')?>`");
    }
    function smview(){
     if ($('is_sm').checked){$('res').className+=' sm'} else {$('res').className = $('res').className.replace(/\bsm\b/,' ')}
    }
    </script>
    <?php return ob_get_clean();
}

// Templates for table rendering components
function tpl_table_row($data)
{
    ob_start(); ?>
    <tr class="<?= hs($data['row_class']) ?>" onclick="tc(this)">
        <?= $data['content'] ?>
    </tr>
    <?php return ob_get_clean();
}

function tpl_show_tables_row($data)
{
    ob_start(); ?>
    <td><input type='checkbox' name='cb[]' value="<?= hs($data['table_quoted']) ?>"></td>
    <td><a href="<?= hs($data['table_url']) ?>"><?= hs($data['table_name']) ?></a></td>
    <td><?= hs($data['engine']) ?></td>
    <td align='right'><?= hs($data['rows']) ?></td>
    <td align='right'><?= hs($data['data_size']) ?></td>
    <td align='right'><?= hs($data['index_size']) ?></td>
    <td><?= $data['actions'] ?></td>
    <td><?= hs($data['comment']) ?></td>
    <?php return ob_get_clean();
}

function tpl_show_databases_row($data)
{
    ob_start(); ?>
    <td><a href="<?= hs($data['db_url']) ?>"><?= hs($data['db_name']) ?></a></td>
    <?php foreach ($data['actions'] as $action): ?>
    <td><?= $action ?></td>
    <?php endforeach; ?>
    <?php return ob_get_clean();
}

function tpl_regular_row($data)
{
    ob_start(); ?>
    <?php foreach ($data['cells'] as $cell): ?>
    <td><div><?= $cell ?><?= empty($cell) ? "<br>" : '' ?></div></td>
    <?php endforeach; ?>
    <?php return ob_get_clean();
}

function tpl_table_action_link($data)
{
    ob_start(); ?>
    &#183;<a href="<?= hs($data['url']) ?>&q=<?= hs($data['encoded_query']) ?>"<?= $data['onclick'] ?>><?= hs($data['text']) ?></a>
    <?php return ob_get_clean();
}

function tpl_export_link($data)
{
    ob_start(); ?>
    &#183;<a href="<?= hs($data['url']) ?>&shex=1&rt=<?= hs($data['table_name_encoded']) ?>">export</a>
    <?php return ob_get_clean();
}

function tpl_table_headers($data)
{
    ob_start(); ?>
    <tr class="h">
        <?php if ($data['show_checkbox']): ?>
        <th><input type="checkbox" onclick="chkall(this)"></th>
        <?php endif; ?>
        <?php foreach ($data['headers'] as $header): ?>
        <th><?= hs($header) ?></th>
        <?php endforeach; ?>
        <?php if ($data['show_actions']): ?>
        <th>Actions</th>
        <?php endif; ?>
    </tr>
    <?php return ob_get_clean();
}

function tpl_info_card($data)
{
    ob_start(); ?>
    <div class="server-info-card">
        <div class="server-info-title">
            <?= $data['icon'] ?> <?= hs($data['title']) ?>
        </div>
        <div class="server-info-links">
            <?php foreach ($data['links'] as $link): ?>
            <a href="<?= hs($link['url']) ?>" class="server-link">
                <?= $link['icon'] ?> <?= hs($link['text']) ?>
            </a>
            <?php endforeach; ?>
        </div>
        <?php if ($data['database_info']): ?>
        <div class="database-info">
            <span class="database-label">Current Database:</span>
            <?= hs($data['database_info']) ?>
        </div>
        <?php endif; ?>
    </div>
    <?php return ob_get_clean();
}

function tpl_table_actions_section($data)
{
    ob_start(); ?>
    </div><div class="table-actions">
        <div class="table-actions-content">
            <div class="table-actions-buttons">
                <?php foreach ($data['actions'] as $action): ?>
                <button type="submit" class="btn btn-sm <?= hs($action['class']) ?>"
                        onclick="<?php if ($action['confirm'] ?? false): ?>if (ays()){sht('<?= hs($action['action']) ?>')} else {return false}<?php else: ?>sht('<?= hs($action['action']) ?>')<?php endif; ?>">
                    <?= hs($action['text']) ?>
                </button>
                <?php endforeach; ?>
            </div>
            <span class="table-actions-label"><strong>selected tables</strong></span>
        </div>
        <div class='table-container-inner'>
        <input type='hidden' name='dosht' value=''>
    <?php return ob_get_clean();
}

// Pure functions for table rendering - much cleaner than the horrible display_select!
function detect_query_type($query)
{
    return [
        'is_show_databases' => preg_match('/^show\s+databases/i', $query),
        'is_show_tables' => preg_match('/^show\s+tables|^SHOW\s+TABLE\s+STATUS/', $query),
        'is_show_create' => preg_match('/^show\s+create\s+table/i', $query)
    ];
}

function format_cell_value($value, $is_show_create = false)
{
    if (is_null($value)) {
        return "<i>NULL</i>";
    }

    // Check for binary data
    if (preg_match('/[\x00-\x09\x0B\x0C\x0E-\x1F]+/', $value)) {
        $length = strlen($value);
        $prefix = '';

        if ($length > 16) {
            $value = substr($value, 0, 16);
            $prefix = '...';
        }

        return 'BINARY: ' . chunk_split(strtoupper(bin2hex($value)), 2, ' ') . $prefix;
    }

    $escaped_value = hs($value);

    if ($is_show_create) {
        return "<pre>{$escaped_value}</pre>";
    }

    return $escaped_value;
}

function create_table_action_link($url, $query, $text, $confirm = false)
{
    $template_data = [
        'url' => $url,
        'encoded_query' => b64u($query),
        'text' => $text,
        'onclick' => $confirm ? " onclick='return ays()'" : ""
    ];

    return render_template('table_action_link', $template_data);
}

function create_export_link($url, $table_name)
{
    $template_data = [
        'url' => $url,
        'table_name_encoded' => ue($table_name)
    ];

    return render_template('export_link', $template_data);
}

function render_table_row_actions($url, $table_name, $table_quoted)
{
    $actions = [
        create_table_action_link($url, "show create table {$table_quoted}", "sct"),
        create_table_action_link($url, "explain {$table_quoted}", "exp"),
        create_table_action_link($url, "show index from {$table_quoted}", "ind"),
        create_export_link($url, $table_quoted),
        create_table_action_link($url, "drop table {$table_quoted}", "dr", true),
        create_table_action_link($url, "truncate table {$table_quoted}", "tr", true),
        create_table_action_link($url, "optimize table {$table_quoted}", "opt", true),
        create_table_action_link($url, "repair table {$table_quoted}", "rpr", true)
    ];

    return implode("</td><td>", $actions);
}

function render_database_row_actions($url, $db_name, $db_quoted)
{
    return [
        "<a href=\"{$url}&q=" . b64u("show create database {$db_quoted}") . "\">scd</a>",
        "<a href=\"{$url}&q=" . b64u("show table status") . "\">status</a>",
        "<a href=\"{$url}&q=" . b64u("show triggers") . "\">trig</a>"
    ];
}

function create_table_headers($query_type, $field_names)
{
    $show_checkbox = $query_type['is_show_tables'];
    $headers = [];

    // Add main field headers
    foreach ($field_names as $name) {
        if ($query_type['is_show_tables'] && array_search($name, $field_names) > 0) {
            break; // Only show first field for show tables
        }
        $headers[] = $name;
    }

    // Add action headers based on query type
    if ($query_type['is_show_databases']) {
        $headers = array_merge($headers, ['show create database', 'show table status', 'show triggers']);
        $show_actions = false;
    } elseif ($query_type['is_show_tables']) {
        $headers = array_merge($headers, ['engine', '~rows', 'data size', 'index size', 'show create table', 'explain', 'indexes', 'export', 'drop', 'truncate', 'optimize', 'repair', 'comment']);
        $show_actions = false;
    } else {
        $show_actions = false;
    }

    $template_data = [
        'show_checkbox' => $show_checkbox,
        'headers' => $headers,
        'show_actions' => $show_actions
    ];

    return render_template('table_headers', $template_data);
}

function create_info_card($query_type, $config)
{
    if (!($query_type['is_show_tables'] || $query_type['is_show_databases'])) {
        return '';
    }

    $base_url = "?{$config['xurl']}&db={$config['db']}&srv={$config['srv']}";

    $links = [
        ['url' => $base_url . "&q=" . b64u("show variables"), 'icon' => '⚙️', 'text' => 'Configuration Variables'],
        ['url' => $base_url . "&q=" . b64u("show status"), 'icon' => '📊', 'text' => 'Statistics'],
        ['url' => $base_url . "&q=" . b64u("show processlist"), 'icon' => '⚡', 'text' => 'Process List']
    ];

    $database_info = null;
    if ($query_type['is_show_tables']) {
        $database_info = $config['db'];
    }

    $template_data = [
        'icon' => '🖥️',
        'title' => 'MySQL Server',
        'links' => $links,
        'database_info' => $database_info
    ];

    return render_template('info_card', $template_data);
}

function create_table_actions_section($query_type)
{
    if (!$query_type['is_show_tables']) {
        return '';
    }

    $template_data = [
        'actions' => [
            ['action' => 'exp', 'text' => '📊 Export', 'class' => 'btn-primary'],
            ['action' => 'drop', 'text' => '🗑️ Drop', 'class' => 'btn-error', 'confirm' => true],
            ['action' => 'trunc', 'text' => '✂️ Truncate', 'class' => 'btn-warning', 'confirm' => true],
            ['action' => 'opt', 'text' => '⚡ Optimize', 'class' => 'btn-success']
        ]
    ];

    return render_template('table_actions_section', $template_data);
}

function tpl_config_form($data)
{
    ob_start(); ?>
    <center>
    <h3>DB Connection Settings</h3>
    <div class="frm">
        <label><div class="l">DB user name:</div><input type="text" name="v[user]" value="<?= hs($data['user']) ?>"></label><br>
        <label><div class="l">Password:</div><input type="password" name="v[pwd]" value=""></label><br>
        <div style="text-align:right"><a href="#" class="ajax" onclick="cfg_toggle()">advanced settings</a></div>
        <div id="cfg-adv" style="display:none;">
            <label><div class="l">DB name:</div><input type="text" name="v[db]" value="<?= hs($data['db']) ?>"></label><br>
            <label><div class="l">MySQL host:</div><input type="text" name="v[host]" value="<?= hs($data['host']) ?>"></label>
            <label>port: <input type="text" name="v[port]" value="<?= hs($data['port']) ?>" size="4"></label>
            <label>socket: <input type="text" name="v[socket]" value="<?= hs($data['socket']) ?>" size="4"></label><br>
            <label><div class="l">Charset:</div><select name="v[chset]"><option value="">- default -</option><?= $data['charset_options'] ?></select></label><br>
            <br><label for="rmb"><input type="checkbox" name="rmb" id="rmb" value="1" checked> Remember in cookies for 30 days or until Logoff</label>
        </div>
        <div style="display:flex;gap:0.5rem;justify-content:center;margin-top:1.5rem;">
            <input type="hidden" name="savecfg" value="1">
            <button type="submit" class="btn btn-primary">💾 Apply Settings</button>
            <button type="button" class="btn btn-secondary" onclick="window.location='<?= hs($data['self']) ?>'">❌ Cancel</button>
        </div>
    </div>
    </center>
    <?php return ob_get_clean();
}

// Database operation helpers - functional approach
function safe_db_query($sql, $validation_func = null)
{
    if ($validation_func && is_callable($validation_func)) {
        $validation = $validation_func($sql);
        if (!$validation['valid']) {
            return create_error_response($validation['error']);
        }
    }

    try {
        $result = db_query($sql);
        return create_success_response(['result' => $result]);
    } catch (Exception $e) {
        return create_error_response("Database query failed: " . $e->getMessage());
    }
}

function create_safe_url($base_url, $params = [])
{
    $url = $base_url;
    $query_parts = [];

    foreach ($params as $key => $value) {
        $query_parts[] = urlencode($key) . '=' . urlencode($value);
    }

    if (!empty($query_parts)) {
        $url .= (strpos($url, '?') === false ? '?' : '&') . implode('&', $query_parts);
    }

    return $url;
}

// HTML generation helpers - pure functions
function render_option($value, $text, $selected = false)
{
    $selected_attr = $selected ? ' selected' : '';
    return "<option value=\"" . hs($value) . "\"{$selected_attr}>" . hs($text) . "</option>";
}

function render_link($url, $text, $attributes = [])
{
    $attr_string = '';
    foreach ($attributes as $key => $value) {
        $attr_string .= " {$key}=\"" . hs($value) . "\"";
    }

    return "<a href=\"" . hs($url) . "\"{$attr_string}>" . hs($text) . "</a>";
}

function render_button($text, $type = 'button', $attributes = [])
{
    $default_class = 'btn btn-primary';
    $attributes['class'] = $attributes['class'] ?? $default_class;
    $attributes['type'] = $type;

    $attr_string = '';
    foreach ($attributes as $key => $value) {
        $attr_string .= " {$key}=\"" . hs($value) . "\"";
    }

    return "<button{$attr_string}>" . hs($text) . "</button>";
}

//* utilities
function db_connect($nodie = 0)
{
    global $dbh,$DB,$err_msg,$IS_LOCAL_INFILE;

    mysqli_report(MYSQLI_REPORT_OFF);
    $po = $DB['port'];
    if (!$po) {
        $po = ini_get("mysqli.default_port");
    }
    $so = $DB['socket'];
    if (!$so) {
        $so = ini_get("mysqli.default_socket");
    }
    if ($DB['ssl_ca']) {#ssl connection
        $dbh = mysqli_init();
        mysqli_options($dbh, MYSQLI_OPT_SSL_VERIFY_SERVER_CERT, true);
        mysqli_ssl_set($dbh, $DB['ssl_key'], $DB['ssl_cert'], $DB['ssl_ca'], null, null);
        if (!mysqli_real_connect($dbh, $DB['host'], $DB['user'], $DB['pwd'], $DB['db'], $po, $so, MYSQLI_CLIENT_SSL_DONT_VERIFY_SERVER_CERT)) {
            $dbh = null;
        }
    } else {#non-ssl
        $dbh = mysqli_connect($DB['host'], $DB['user'], $DB['pwd'], $DB['db'], $po, $so);
    }
    if (!$dbh) {
        $err_msg = 'Cannot connect to the database because: '.mysqli_connect_error();
        if (!$nodie) {
            die($err_msg);
        }
    } else {
        if ($DB['chset']) {
            db_query("SET NAMES ".$DB['chset']);
        }
        db_query("SET GLOBAL local_infile=".intval($IS_LOCAL_INFILE), null, 1);
    }

    return $dbh;
}

function db_checkconnect($dbh1 = null, $skiperr = 0)
{
    global $dbh;
    if (!$dbh1) {
        $dbh1 = &$dbh;
    }
    if (!$dbh1 or !mysqli_ping($dbh1)) {
        db_connect($skiperr);
        $dbh1 = &$dbh;
    }
    return $dbh1;
}

function db_disconnect()
{
    global $dbh;
    mysqli_close($dbh);
}

function dbq($s)
{
    global $dbh;
    if (is_null($s)) {
        return "NULL";
    }
    return "'".mysqli_real_escape_string($dbh, $s)."'";
}

/**
 * Safely quotes database identifiers (table names, column names, etc.)
 * Security fix: Prevents SQL injection by validating identifier format
 *
 * @param string $s The identifier to quote
 * @return string The safely quoted identifier
 * @throws Exception If identifier contains invalid characters
 */
function dbqid($s)
{
    // Remove any existing backticks to prevent double-quoting
    $s = str_replace('`', '', $s);

    // Security validation: Only allow alphanumeric characters, underscores, and dots
    // This prevents SQL injection through malicious identifiers
    if (!preg_match('/^[a-zA-Z0-9_\.]+$/', $s)) {
        throw new Exception("Invalid database identifier: " . htmlspecialchars($s));
    }

    // Additional length check to prevent extremely long identifiers
    if (strlen($s) > 64) {
        throw new Exception("Database identifier too long (max 64 characters)");
    }

    return "`$s`";
}

function db_query($sql, $dbh1 = null, $skiperr = 0, $resmod = MYSQLI_STORE_RESULT)
{
    $dbh1 = db_checkconnect($dbh1, $skiperr);
    if ($dbh1) {
        $sth = mysqli_query($dbh1, $sql, $resmod);
    }
    if (!$sth && $skiperr) {
        return;
    }
    if (!$sth) {
        die("Error in DB operation:<br>\n".mysqli_error($dbh1)."<br>\n$sql");
    }
    return $sth;
}

function db_array($sql, $dbh1 = null, $skiperr = 0, $isnum = 0) #array of rows
{$sth = db_query($sql, $dbh1, $skiperr, MYSQLI_USE_RESULT);
    if (!$sth) {
        return;
    }
    $res = [];
    if ($isnum) {
        while ($row = mysqli_fetch_row($sth)) {
            $res[] = $row;
        }
    } else {
        while ($row = mysqli_fetch_assoc($sth)) {
            $res[] = $row;
        }
    }
    mysqli_free_result($sth);
    return $res;
}

function db_row($sql)
{
    $sth = db_query($sql);
    return mysqli_fetch_assoc($sth);
}

function db_value($sql, $dbh1 = null, $skiperr = 0)
{
    $sth = db_query($sql, $dbh1, $skiperr);
    if (!$sth) {
        return;
    }
    $row = mysqli_fetch_row($sth);
    return $row[0];
}

function get_identity($dbh1 = null)
{
    $dbh1 = db_checkconnect($dbh1);
    return mysqli_insert_id($dbh1);
}

function get_db_select($sel = '')
{
    global $DB,$SHOW_D;
    if (is_array($_SESSION['sql_sd'] ?? 0) && ($_REQUEST['db'] ?? '') != '*') {//check cache
        $arr = $_SESSION['sql_sd'];
    } else {
        $arr = db_array($SHOW_D, null, 1);
        if (!is_array($arr)) {
            $arr = [0 => array('Database' => $DB['db'])];
        }
        $_SESSION['sql_sd'] = $arr;
    }
    return @sel($arr, 'Database', $sel);
}

function chset_select($sel = '')
{
    global $DBDEF;
    if (isset($_SESSION['sql_chset'])) {
        $arr = $_SESSION['sql_chset'];
    } else {
        $arr = db_array("show character set", null, 1);
        if (!is_array($arr)) {
            $arr = [['Charset' => $DBDEF['chset']]];
        }
        $_SESSION['sql_chset'] = $arr;
    }

    return @sel($arr, 'Charset', $sel);
}

function sel($arr, $n, $sel = '')
{
    if (!is_array($arr)) {
        return '';
    }

    return array_reduce($arr, function ($result, $item) use ($n, $sel) {
        $value = $item[$n] ?? '';
        $is_selected = $sel && $sel === $value;
        return $result . render_option($value, $value, $is_selected);
    }, '');
}

function microtime_float()
{
    list($usec, $sec) = explode(" ", microtime());
    return ((float)$usec + (float)$sec);
}

/* page nav
 $pg=int($_[0]);     #current page
 $all=int($_[1]);     #total number of items
 $PP=$_[2];      #number if items Per Page
 $ptpl=$_[3];      #page url /ukr/dollar/notes.php?page=    for notes.php
 $show_all=$_[5];           #print Totals?
*/
function get_nav($pg, $all, $PP, $ptpl, $show_all = '')
{
    $n = '&nbsp;';
    $sep = " $n|$n\n";
    if (!$PP) {
        $PP = 10;
    }
    $allp = floor($all / $PP + 0.999999);

    $pname = '';
    $res = '';
    $w = ['Less','More','Back','Next','First','Total'];

    $sp = $pg - 2;
    if ($sp < 0) {
        $sp = 0;
    }
    if ($allp - $sp < 5 && $allp >= 5) {
        $sp = $allp - 5;
    }

    $res = "";

    if ($sp > 0) {
        $pname = pen($sp - 1, $ptpl);
        $res .= "<a href='$pname'>$w[0]</a>";
        $res .= $sep;
    }
    for ($p_p = $sp;$p_p < $allp && $p_p < $sp + 5;$p_p++) {
        $first_s = $p_p * $PP + 1;
        $last_s = ($p_p + 1) * $PP;
        $pname = pen($p_p, $ptpl);
        if ($last_s > $all) {
            $last_s = $all;
        }
        if ($p_p == $pg) {
            $res .= "<b>$first_s..$last_s</b>";
        } else {
            $res .= "<a href='$pname'>$first_s..$last_s</a>";
        }
        if ($p_p + 1 < $allp) {
            $res .= $sep;
        }
    }
    if ($sp + 5 < $allp) {
        $pname = pen($sp + 5, $ptpl);
        $res .= "<a href='$pname'>$w[1]</a>";
    }
    $res .= " <br>\n";

    if ($pg > 0) {
        $pname = pen($pg - 1, $ptpl);
        $res .= "<a href='$pname'>$w[2]</a> $n|$n ";
        $pname = pen(0, $ptpl);
        $res .= "<a href='$pname'>$w[4]</a>";
    }
    if ($pg > 0 && $pg + 1 < $allp) {
        $res .= $sep;
    }
    if ($pg + 1 < $allp) {
        $pname = pen($pg + 1, $ptpl);
        $res .= "<a href='$pname'>$w[3]</a>";
    }
    if ($show_all) {
        $res .= " <b>($w[5] - $all)</b> ";
    }

    return $res;
}

function pen($p, $np = '')
{
    return str_replace('%p%', $p, $np);
}

function savecfg()
{
    global $DBDEF;
    $v = $_REQUEST['v'] ?? [];
    if (!is_array($v)) {
        $v = [];
    }
    unset($v['ssl_ca']);
    unset($v['ssl_key']);
    unset($v['ssl_cert']);#don't allow override ssl paths from web
    $_SESSION['DB'] = array_merge($DBDEF, $v);
    unset($_SESSION['sql_sd']);

    if ($_REQUEST['rmb'] ?? 0) {
        $tm = time() + 60 * 60 * 24 * 30;
        newcookie("conn[db]", $v['db'], $tm);
        newcookie("conn[user]", $v['user'], $tm);
        newcookie("conn[pwd]", $v['pwd'], $tm);
        newcookie("conn[host]", $v['host'], $tm);
        newcookie("conn[port]", $v['port'], $tm);
        newcookie("conn[socket]", $v['socket'], $tm);
        newcookie("conn[chset]", $v['chset'], $tm);
    } else {
        newcookie("conn[db]", false, -1);
        newcookie("conn[user]", false, -1);
        newcookie("conn[pwd]", false, -1);
        newcookie("conn[host]", false, -1);
        newcookie("conn[port]", false, -1);
        newcookie("conn[socket]", false, -1);
        newcookie("conn[chset]", false, -1);
    }
}

// Allow httponly cookies, or the password is stored plain text in a cookie
function newcookie($n, $v, $e)
{
    $x = '';
    return setcookie($n, $v, $e, $x, $x, !!$x, !$x);
}

//during login only - from cookies or use defaults;
function loadcfg()
{
    global $DBDEF;

    if (isset($_COOKIE['conn'])) {
        $_SESSION['DB'] = array_merge($DBDEF, $_COOKIE['conn']);
    } else {
        $_SESSION['DB'] = $DBDEF;
    }
    if (!strlen($_SESSION['DB']['chset'])) {
        $_SESSION['DB']['chset'] = $DBDEF['chset'];
    }#don't allow empty charset
}

//each time - from session to $DB_*
function loadsess()
{
    global $SRV,$DBSERVERS,$DB,$is_sm;

    $DB = $_SESSION['DB'];
    $rdb = $_REQUEST['db'] ?? '';
    if ($rdb == '*') {
        $rdb = '';
    }

    #if server passed - use that srv config
    $SRV = $_REQUEST['srv'] ?? '';
    if ($SRV) {
        foreach ($DBSERVERS as $v) {
            if ($v['iname'] == $SRV) {
                if ($DB['user'] . '|' . $DB['host'] != $v['config']['user'] . '|' . $v['config']['host']) {
                    $rdb = '';
                }#reset db if host changed
                $DB = $v['config'];
                break;
            }
        }
    }

    if ($rdb) {
        $DB['db'] = $rdb;
    }
    if ($_REQUEST['GoSQL'] ?? '') {
        $_SESSION['is_sm'] = intval($_REQUEST['is_sm'] ?? 0);
    }
    $is_sm = intval($_SESSION['is_sm'] ?? 0);
}

function print_export()
{
    global $self,$xurl,$SRV,$DB,$DUMP_FILE;
    $t = $_REQUEST['rt'];

    print_header();

    $template_data = [
        'export_label' => ($t) ? "Table $t" : "whole DB",
        'table_name' => $t,
        'self_url' => $self,
        'xurl' => $xurl,
        'database' => $DB['db'],
        'server' => $SRV,
        'dump_file' => export_fname($DUMP_FILE).'.sql',
        'show_csv_option' => $t && !strpos($t, ',')
    ];

    echo render_template('export_form', $template_data);
    print_footer();
    exit;
}

function export_fname($f, $ist = false)
{
    $t = $ist ? date('Y-m-d-His') : 'YYYY-MM-DD-HHMMSS';
    return $f.$t;
}

function do_export()
{
    global $DB,$VERSION,$D,$BOM,$ex_isgz,$ex_issrv,$dbh,$out_message;
    $rt = str_replace('`', '', $_REQUEST['rt'] ?? '');
    $t = explode(",", $rt);
    $th = array_flip($t);
    $ct = count($t);
    $z = db_row("show variables like 'max_allowed_packet'");
    $MAXI = floor($z['Value'] * 0.8);
    if (!$MAXI) {
        $MAXI = 838860;
    }
    $MAXI = min($MAXI, 16777216);
    $aext = '';
    $ctp = '';

    $ex_super = ($_REQUEST['sp'] ?? 0) ? 1 : 0;
    $ex_isgz = ($_REQUEST['gz'] ?? 0) ? 1 : 0;
    if ($ex_isgz) {
        $aext = '.gz';
        $ctp = 'application/x-gzip';
    }
    $ex_issrv = ($_REQUEST['issrv'] ?? 0) ? 1 : 0;

    if ($ct == 1 && ($_REQUEST['et'] ?? '') == 'csv') {
        ex_start('.csv');
        ex_hdr($ctp ?: 'text/csv', "$t[0].csv$aext");
        if (str_starts_with($DB['chset'], 'utf8')) {
            ex_w($BOM);
        }

        $sth = db_query("select * from ".dbqid($t[0]), null, 0, MYSQLI_USE_RESULT);
        $fn = mysqli_field_count($dbh);
        for ($i = 0;$i < $fn;$i++) {
            $m = mysqli_fetch_field($sth);
            ex_w(qstr($m->name).(($i < $fn - 1) ? "," : ""));
        }
        ex_w($D);
        while ($row = mysqli_fetch_row($sth)) {
            ex_w(to_csv_row($row));
        }
        mysqli_free_result($sth);
    } else {
        ex_start('.sql');
        ex_hdr($ctp ? $ctp : 'text/plain', $DB['db'].(($ct == 1 && $t[0]) ? ".$t[0]" : (($ct > 1) ? '.'.$ct.'tables' : '')).".sql$aext");
        ex_w("-- phpMochiAdmin dump $VERSION$D-- Datetime: ".date('Y-m-d H:i:s')."$D-- Host: {$DB['host']}$D-- Database: {$DB['db']}$D$D");
        if ($DB['chset']) {
            ex_w("/*!40030 SET NAMES {$DB['chset']} */;$D");
        }
        $ex_super && ex_w("/*!40030 SET GLOBAL max_allowed_packet=16777216 */;$D$D");
        ex_w("/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;$D$D");

        $sth = db_query("show full tables from ".dbqid($DB['db']));
        while ($row = mysqli_fetch_row($sth)) {
            if (!$rt || array_key_exists($row[0], $th)) {
                do_export_table($row[0], $row[1], $MAXI);
            }
        }

        ex_w("/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;$D$D");
        ex_w("$D-- phpMochiAdmin dump end$D");
    }
    ex_end();
    if (!$ex_issrv) {
        exit;
    }
    $out_message = 'Export done successfully';
}

function do_export_table($t = '', $tt = '', $MAXI = 838860)
{
    global $D,$ex_issrv;
    @set_time_limit(600);
    $qt = dbqid($t);

    if ($_REQUEST['s'] ?? 0) {
        $sth = db_query("show create table $qt");
        $row = mysqli_fetch_row($sth);
        $ct = preg_replace("/\n\r|\r\n|\n|\r/", $D, $row[1]);
        ex_w("DROP TABLE IF EXISTS $qt;$D$ct;$D$D");
    }

    if ($_REQUEST['d'] && $tt != 'VIEW') {//no dump for views
        $exsql = '';
        ex_w("/*!40000 ALTER TABLE $qt DISABLE KEYS */;$D");
        $sth = db_query("select * from $qt", null, 0, MYSQLI_USE_RESULT);
        while ($row = mysqli_fetch_row($sth)) {
            $values = '';
            foreach ($row as $v) {
                $values .= (($values) ? ',' : '').dbq($v);
            }
            $exsql .= (($exsql) ? ',' : '')."(".$values.")";
            if (strlen($exsql) > $MAXI) {
                ex_w("INSERT INTO $qt VALUES $exsql;$D");
                $exsql = '';
            }
        }
        mysqli_free_result($sth);
        if ($exsql) {
            ex_w("INSERT INTO $qt VALUES $exsql;$D");
        }
        ex_w("/*!40000 ALTER TABLE $qt ENABLE KEYS */;$D$D");
    }
    if (!$ex_issrv) {
        flush();
    }
}

function ex_hdr($ct, $fn)
{
    global $ex_issrv;
    if ($ex_issrv) {
        return;
    }
    header("Content-type: $ct");
    header("Content-Disposition: attachment; filename=\"$fn\"");
}
function ex_start($ext)
{
    global $ex_isgz,$ex_gz,$ex_tmpf,$ex_issrv,$ex_f,$DUMP_FILE;
    if ($ex_isgz) {
        $ex_tmpf = ($ex_issrv ? export_fname($DUMP_FILE, true).$ext : tmp_name()).'.gz';
        if (!($ex_gz = gzopen($ex_tmpf, 'wb9'))) {
            die("Error trying to create gz tmp file");
        }
    } else {
        if ($ex_issrv) {
            if (!($ex_f = fopen(export_fname($DUMP_FILE, true).$ext, 'wb'))) {
                die("Error trying to create dump file");
            }
        }
    }
}
function ex_w($s)
{
    global $ex_isgz,$ex_gz,$ex_issrv,$ex_f;
    if ($ex_isgz) {
        gzwrite($ex_gz, $s, strlen($s));
    } else {
        if ($ex_issrv) {
            fwrite($ex_f, $s);
        } else {
            echo $s;
        }
    }
}
function ex_end()
{
    global $ex_isgz,$ex_gz,$ex_tmpf,$ex_issrv,$ex_f;
    if ($ex_isgz) {
        gzclose($ex_gz);
        if (!$ex_issrv) {
            readfile($ex_tmpf);
            unlink($ex_tmpf);
        }
    } else {
        if ($ex_issrv) {
            fclose($ex_f);
        }
    }
}

function print_import()
{
    global $self,$xurl,$SRV,$DB,$DUMP_FILE;

    print_header();

    $template_data = [
        'self_url' => $self,
        'xurl' => $xurl,
        'database' => $DB['db'],
        'server' => $SRV,
        'dump_file_sql' => $DUMP_FILE.'.sql',
        'dump_file_gz' => $DUMP_FILE.'.sql.gz'
    ];

    echo render_template('import_form', $template_data);
    print_footer();
    exit;
}

function do_import()
{
    global $err_msg,$out_message,$dbh,$SHOW_T,$DUMP_FILE;
    $err_msg = '';
    $it = $_REQUEST['it'] ?? '';

    if (!$it) {
        $F = $_FILES['file1'];
        if ($F && $F['name']) {
            $filename = $F['tmp_name'];
            $pi = pathinfo($F['name']);
            $ext = $pi['extension'];
        }
    } else {
        $ext = ($it == 'gz' ? 'sql.gz' : 'sql');
        $filename = $DUMP_FILE.'.'.$ext;
    }

    if ($filename && file_exists($filename)) {
        if ($ext != 'sql') {//if not sql - assume .gz and extract
            $tmpf = tmp_name();
            if (($gz = gzopen($filename, 'rb')) && ($tf = fopen($tmpf, 'wb'))) {
                while (!gzeof($gz)) {
                    if (fwrite($tf, gzread($gz, 8192), 8192) === false) {
                        $err_msg = 'Error during gz file extraction to tmp file';
                        break;
                    }
                }//extract to tmp file
                gzclose($gz);
                fclose($tf);
                $filename = $tmpf;
            } else {
                $err_msg = 'Error opening gz file';
            }
        }
        if (!$err_msg) {
            if (!do_multi_sql('', $filename)) {
                $err_msg = 'Import Error: '.mysqli_error($dbh);
            } else {
                $out_message = 'Import done successfully';
                do_sql($SHOW_T);
                return;
            }
        }

    } else {
        $err_msg = "Error: Please select file first";
    }
    print_import();
    exit;
}

// Pure function helpers for SQL parsing
function parse_sql_state($str, $pos, $ochar)
{
    $patterns = [
        'comment_start' => '/(\/\*|^--|(?<=\s)--|#|\'|\"|;)/',
        'comment_end' => [
            '\'' => '(?<!\\\\)\'|(\\\\+)\'',
            '"' => '(?<!\\\\)"',
            '/*' => '\*\/',
            '#' => '[\r\n]+',
            '--' => '[\r\n]+'
        ]
    ];

    return [
        'open_char' => $ochar,
        'position' => $pos,
        'patterns' => $patterns
    ];
}

function split_sql_statements($sql_content)
{
    $statements = [];
    $current_statement = '';
    $in_string = false;
    $string_char = '';
    $in_comment = false;

    $lines = preg_split('/\r\n|\r|\n/', $sql_content);

    foreach ($lines as $line) {
        $line = trim($line);

        // Skip empty lines and comments
        if (empty($line) || strpos($line, '--') === 0 || strpos($line, '#') === 0) {
            continue;
        }

        $current_statement .= $line . ' ';

        // Simple statement termination detection
        if (substr(trim($line), -1) === ';' && !$in_string && !$in_comment) {
            $statements[] = trim(rtrim($current_statement, ';'));
            $current_statement = '';
        }
    }

    // Add remaining statement if exists
    if (!empty(trim($current_statement))) {
        $statements[] = trim($current_statement);
    }

    return array_filter($statements);
}

// multiple SQL statements splitter - improved functional approach
function do_multi_sql($insql, $fname = '')
{
    @set_time_limit(600);

    $content = '';

    // Read content from file or use provided SQL
    if ($fname && file_exists($fname)) {
        $content = file_get_contents($fname);
    } else {
        $content = $insql;
    }

    if (empty($content)) {
        return true;
    }

    // Split into individual statements
    $statements = split_sql_statements($content);

    // Execute each statement
    foreach ($statements as $sql) {
        if (!do_one_sql($sql)) {
            return false;
        }
    }

    return true;
}

//read from insql var or file
function get_next_chunk($insql, $fname)
{
    global $LFILE, $insql_done;
    if ($insql) {
        if ($insql_done) {
            return '';
        } else {
            $insql_done = 1;
            return $insql;
        }
    }
    if (!$fname) {
        return '';
    }
    if (!$LFILE) {
        $LFILE = fopen($fname, "r+b") or die("Can't open [$fname] file $!");
    }
    return fread($LFILE, 64 * 1024);
}

function get_open_char($str, $pos)
{
    $ochar = '';
    $opos = '';
    if (preg_match("/(\/\*|^--|(?<=\s)--|#|'|\"|;)/", $str, $m, PREG_OFFSET_CAPTURE, $pos)) {
        $ochar = $m[1][0];
        $opos = $m[1][1];
    }
    return [$ochar, $opos];
}

#RECURSIVE!
function get_close_char($str, $pos, $ochar)
{
    $aCLOSE = [
      '\'' => '(?<!\\\\)\'|(\\\\+)\'',
      '"' => '(?<!\\\\)"',
      '/*' => '\*\/',
      '#' => '[\r\n]+',
      '--' => '[\r\n]+',
    ];
    if ($aCLOSE[$ochar] && preg_match("/(".$aCLOSE[$ochar].")/", $str, $m, PREG_OFFSET_CAPTURE, $pos)) {
        $clchar = $m[1][0];
        $clpos = $m[1][1];
        $sl = strlen($m[2][0] ?? '');
        if ($ochar == "'" && $sl) {
            if ($sl % 2) { #don't count as CLOSE char if number of slashes before ' ODD
                list($clchar, $clpos) = get_close_char($str, $clpos + strlen($clchar), $ochar);
            } else {
                $clpos += strlen($clchar) - 1;
                $clchar = "'";#correction
            }
        }
    }
    return [$clchar, $clpos];
}

function do_one_sql($sql)
{
    global $last_sth,$last_sql,$MAX_ROWS_PER_PAGE,$page,$is_limited_sql,$last_count,$IS_COUNT;
    $sql = trim($sql);
    $sql = preg_replace("/;$/", "", $sql);
    if ($sql) {
        $last_sql = $sql;
        $is_limited_sql = 0;
        $last_count = null;
        if (preg_match("/^select/i", $sql) && !preg_match("/limit +\d+/i", $sql)) {
            if ($IS_COUNT) {
                #get total count
                $sql1 = 'select count(*) from ('.$sql.') ___count_table';
                $last_count = db_value($sql1, null, 'noerr');
            }
            $offset = $page * $MAX_ROWS_PER_PAGE;
            $sql .= " LIMIT $offset,$MAX_ROWS_PER_PAGE";
            $is_limited_sql = 1;
        }
        $last_sth = db_query($sql, 0, 'noerr');
        return $last_sth;
    }
    return 1;
}

function do_sht()
{
    global $SHOW_T;
    $cb = $_REQUEST['cb'] ?? [];
    if (!is_array($cb)) {
        $cb = [];
    }
    $sql = '';
    switch ($_REQUEST['dosht'] ?? '') {
        case 'exp':$_REQUEST['rt'] = join(",", $cb);
            print_export();
            exit;
        case 'drop':$sq = 'DROP TABLE';
            break;
        case 'trunc':$sq = 'TRUNCATE TABLE';
            break;
        case 'opt':$sq = 'OPTIMIZE TABLE';
            break;
    }
    if ($sq) {
        foreach ($cb as $v) {
            $sql .= $sq." $v;\n";
        }
    }
    if ($sql) {
        do_sql($sql);
    }
    do_sql($SHOW_T);
}

function to_csv_row($adata)
{
    global $D;
    $r = '';
    foreach ($adata as $a) {
        $r .= (($r) ? "," : "").qstr($a);
    }
    return $r.$D;
}
function qstr($s)
{
    $s = nl2br($s ?? '');
    $s = str_replace('"', '""', $s);
    return '"'.$s.'"';
}

function get_rand_str($len)
{
    $result = '';
    $chars = preg_split('//', 'ABCDEFabcdef0123456789');
    for ($i = 0;$i < $len;$i++) {
        $result .= $chars[rand(0, count($chars) - 1)];
    }
    return $result;
}

/**
 * Security improvement: Enhanced CSRF token validation using functional approach
 * Protects against Cross-Site Request Forgery attacks
 */
function check_xss()
{
    global $self;

    $session_token = $_SESSION['XSS'] ?? '';
    $request_token = trim($_REQUEST['XSS'] ?? '');

    // Use the functional validation approach
    if (!validate_csrf_token($session_token, $request_token)) {
        // Log security event with context
        $error_response = create_error_response(
            'CSRF token validation failed',
            ['ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown']
        );

        // Regenerate token to prevent fixation attacks
        $_SESSION['XSS'] = create_safe_token(32);

        header("location: $self");
        exit;
    }
}

function rw($s) #for debug
{echo hs(var_dump($s))."<br>\n";
}

function tmp_name()
{
    if (function_exists('sys_get_temp_dir')) {
        return tempnam(sys_get_temp_dir(), 'pma');
    }

    if (!($temp = getenv('TMP'))) {
        if (!($temp = getenv('TEMP'))) {
            if (!($temp = getenv('TMPDIR'))) {
                $temp = tempnam(__FILE__, '');
                if (file_exists($temp)) {
                    unlink($temp);
                    $temp = dirname($temp);
                }
            }
        }
    }
    return $temp ? tempnam($temp, 'pma') : null;
}

function hs($s)
{
    return htmlspecialchars(is_null($s) ? '' : $s, ENT_QUOTES, 'UTF-8');
}
function eo($s) //echo+escape
{echo hs($s);
}
function ue($s)
{
    return urlencode($s);
}

function b64e($s)
{
    return base64_encode($s);
}
function b64u($s)
{
    return ue(base64_encode($s));
}
function b64d($s)
{
    return base64_decode($s ?? '');
}

function isTrusted()
{
    $trstd = ['127.0.0.1','::1']; #do not require ACCESS_PWD for local
    if (in_array($_SERVER['REMOTE_ADDR'], $trstd)) {
        return true;
    }
    return false;
}
?>
