<?php
/**
 * Plugin Name: WP GA LINE Reporter
 * Description: Fetch Google Analytics data and send reports via LINE Messaging API.
 * Version: 0.1.0
 * Author: Your Name
 * Author URI: Your Website
 * License: GPL-2.0-or-later
 * Text Domain: wpgalr
 * Domain Path: /languages
 */

defined( 'ABSPATH' ) || exit; // 防止直接訪問

// 引入 Composer Autoloader
// 請確保您已在此外掛目錄或 WordPress 根目錄使用 Composer 安裝 Google Client Library
// composer require google/apiclient:^2.12
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else if (file_exists(ABSPATH . 'vendor/autoload.php')) {
    require_once ABSPATH . 'vendor/autoload.php';
} else {
    add_action('admin_notices', function() {
        echo '<div class="notice notice-error"><p>WP GA LINE Reporter 外掛需要 Google Client Library。請使用 Composer 在此外掛目錄 (' . esc_html(__DIR__) . ') 或網站根目錄安裝。</p></div>';
    });
    return; // 停止載入外掛功能
}

use Google\Client;
use Google\Service\AnalyticsAdmin;

/**
 * @var string 資料表名稱，使用 WordPress 前綴確保唯一性。
 */
global $wpgalr_db_version;
$wpgalr_db_version = '1.0';

/**
 * 在外掛啟動時執行，建立資料表。
 */
function wpgalr_install() {
    global $wpdb;
    global $wpgalr_db_version;

    $table_name = $wpdb->prefix . 'wpgalr_user_configs';

    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE $table_name (
        id mediumint(9) NOT NULL AUTO_INCREMENT,
        wp_user_id bigint(20) UNSIGNED NOT NULL,
        google_email varchar(255) DEFAULT '' NOT NULL,
        google_refresh_token_encrypted text NOT NULL,
        ga_property_id varchar(50),
        ga_account_name varchar(255),
        ga_property_name varchar(255),
        timezone varchar(50) DEFAULT 'Asia/Taipei' NOT NULL,
        is_active tinyint(1) DEFAULT 1 NOT NULL,
        is_admin tinyint(1) DEFAULT 0 NOT NULL,
        updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY google_email (google_email),
        FOREIGN KEY (wp_user_id) REFERENCES {$wpdb->users}(ID) ON DELETE CASCADE
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);

    // 儲存資料庫版本
    add_option( 'wpgalr_db_version', $wpgalr_db_version );
}

register_activation_hook(__FILE__, 'wpgalr_install');

/**
 * 加密 Refresh Token。
 * 請在 wp-config.php 中定義一個強密碼作為 MY_PLUGIN_ENCRYPTION_KEY。
 * 範例: define('MY_PLUGIN_ENCRYPTION_KEY', '你的安全加密金鑰');
 *
 * @param string $token 要加密的 Refresh Token。
 * @return string|false 加密後的字串，或失敗時返回 false。
 */
function wpgalr_encrypt_token($token) {
    $encryption_key = defined('WPGA_LINE_REPORTER_ENCRYPTION_KEY') ? WPGA_LINE_REPORTER_ENCRYPTION_KEY : null;

    if (!$encryption_key) {
        error_log('WPGA_LINE_REPORTER: 加密金鑰 (WPGA_LINE_REPORTER_ENCRYPTION_KEY) 未定義。');
        return false;
    }

    // 使用 AES-256-CBC 加密
    $ivlen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = openssl_random_pseudo_bytes($ivlen);
    $ciphertext_raw = openssl_encrypt($token, 'aes-256-cbc', $encryption_key, $options=0, $iv);
    $hmac = hash_hmac('sha256', $ciphertext_raw, $encryption_key, $binary=true);

    // 將 IV, HMAC 和密文組合成一個字串儲存 (Base64 編碼方便儲存)
    return base64_encode($iv . $hmac . $ciphertext_raw);
}

/**
 * 解密 Refresh Token。
 *
 * @param string $encrypted_token 加密後的字串。
 * @return string|false 解密後的 Refresh Token，或失敗時返回 false。
 */
function wpgalr_decrypt_token($encrypted_token) {
    $encryption_key = defined('WPGA_LINE_REPORTER_ENCRYPTION_KEY') ? WPGA_LINE_REPORTER_ENCRYPTION_KEY : null;

     if (!$encryption_key) {
        error_log('WPGA_LINE_REPORTER: 加密金鑰 (WPGA_LINE_REPORTER_ENCRYPTION_KEY) 未定義。');
        return false;
    }

    $c = base64_decode($encrypted_token);
    $ivlen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($c, 0, $ivlen);
    $hmac = substr($c, $ivlen, $sha256len=32);
    $ciphertext_raw = substr($c, $ivlen + $sha256len);

    $original_plaintext = openssl_decrypt($ciphertext_raw, 'aes-256-cbc', $encryption_key, $options=0, $iv);
    $calcmac = hash_hmac('sha256', $ciphertext_raw, $encryption_key, $binary=true);

    // 防止時序攻擊 (timing attacks)
    if (function_exists('hash_equals')) {
        if (hash_equals($hmac, $calcmac)) { // 驗證 HMAC
            return $original_plaintext;
        }
    } else {
        // Fallback for older PHP versions
        if ($hmac === $calcmac) {
             return $original_plaintext;
        }
    }

    error_log('WPGA_LINE_REPORTER: 解密失敗，HMAC 不匹配或金鑰錯誤。');
    return false;
}

/**
 * 儲存或更新使用者的設定。
 * 除了 Google Token 外，也處理 GA Property ID 和名稱的儲存。
 *
 * @param int    $wp_user_id WordPress 使用者 ID。
 * @param array  $data 要儲存的資料陣列 (鍵值對應資料表欄位)。
 *                     接受鍵: google_email, google_refresh_token_encrypted, ga_property_id, ga_account_name, ga_property_name, line_user_id, timezone, is_active, is_admin。
 *                     其中 google_refresh_token 需要傳入未加密的字串。
 * @return int|false 插入或更新的列 ID，或失敗時返回 false。
 */
function wpgalr_update_user_config($wp_user_id, $data) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wpgalr_user_configs';

    // 檢查使用者是否已存在設定記錄
    $existing_config = $wpdb->get_row($wpdb->prepare(
        "SELECT * FROM $table_name WHERE wp_user_id = %d",
        $wp_user_id
    ));

    $data_to_save = array();

    // 處理 refresh token 加密 (如果存在且不是空字串)
    if (isset($data['google_refresh_token']) && $data['google_refresh_token'] !== '') {
         $encrypted_token = wpgalr_encrypt_token($data['google_refresh_token']);
         if ($encrypted_token === false) {
             error_log('WPGA_LINE_REPORTER: 無法加密 Refresh Token (使用者ID: ' . $wp_user_id . ')');
             // 如果加密失敗，不儲存 token，但可能需要記錄錯誤或通知使用者
             // 這裡選擇直接返回 false，表示更新失敗
             return false;
         }
         $data_to_save['google_refresh_token_encrypted'] = $encrypted_token;
         unset($data['google_refresh_token']); // 避免儲存未加密的 token
    }

    // 清理和複製其他要儲存的數據
    $allowed_fields = ['google_email', 'ga_property_id', 'ga_account_name', 'ga_property_name', 'line_user_id', 'timezone', 'is_active', 'is_admin'];
    foreach ($allowed_fields as $field) {
        if (isset($data[$field])) {
             // 針對 email 進行 sanitization
            if ($field === 'google_email') {
                 $data_to_save[$field] = sanitize_email($data[$field]);
            } else if ($field === 'is_active' || $field === 'is_admin') {
                 $data_to_save[$field] = (int) filter_var($data[$field], FILTER_VALIDATE_BOOLEAN); // 確保是 0 或 1
            } else {
                 $data_to_save[$field] = sanitize_text_field($data[$field]);
            }
        }
    }

    // 總是更新 updated_at
    $data_to_save['updated_at'] = current_time('mysql');

    if ($existing_config) {
        // 更新現有記錄
        $updated = $wpdb->update(
            $table_name,
            $data_to_save,
            array('wp_user_id' => $wp_user_id)
        );
         // 返回更新的列 ID 或 false
        return $updated ? $existing_config->id : false;
    } else {
        // 插入新記錄 (需要確保 wp_user_id 存在)
        if (!$wp_user_id) {
             error_log('WPGA_LINE_REPORTER: 無法為無效的使用者 ID 插入設定。');
             return false;
        }
        $data_to_save['wp_user_id'] = $wp_user_id;
        $inserted = $wpdb->insert(
            $table_name,
            $data_to_save
        );
        // 返回插入的列 ID 或 false
        return $inserted ? $wpdb->insert_id : false;
    }
}

/**
 * 使用儲存的 Refresh Token 獲取新的 Google Access Token。
 *
 * @param int $wp_user_id WordPress 使用者 ID。
 * @return string|WP_Error 成功時返回 Access Token 字串，失敗時返回 WP_Error 物件。
 */
function wpgalr_get_google_access_token($wp_user_id) {
    global $wpdb;
    $config_table = $wpdb->prefix . 'wpgalr_user_configs';

    // 1. 從資料庫讀取加密的 Refresh Token
    $user_config = $wpdb->get_row($wpdb->prepare(
        "SELECT google_refresh_token_encrypted FROM $config_table WHERE wp_user_id = %d",
        $wp_user_id
    ));

    if (!$user_config || empty($user_config->google_refresh_token_encrypted)) {
        // 找不到 Refresh Token
        return new WP_Error('wpgalr_no_refresh_token', '找不到使用者的 Google Refresh Token，請在設定頁面重新連結 Google 帳號。');
    }

    // 2. 解密 Refresh Token
    $refresh_token = wpgalr_decrypt_token($user_config->google_refresh_token_encrypted);

    if (!$refresh_token) {
         // 解密失敗 (可能金鑰錯誤或資料損壞)
         // 考慮在這裡清除無效的 token 或提示使用者
         return new WP_Error('wpgalr_token_decryption_failed', '無法解密 Refresh Token，請檢查加密金鑰或重新連結 Google 帳號。');
    }

    // 3. 向 Google Token 端點請求新的 Access Token
    $token_url = 'https://oauth2.googleapis.com/token';
    $client_id = get_option('wpgalr_google_client_id');
    $client_secret = get_option('wpgalr_google_client_secret');

    if (!$client_id || !$client_secret) {
         return new WP_Error('wpgalr_missing_api_keys', 'Google API Client ID 或 Client Secret 未在設定頁面中設定。');
    }

    $token_payload = array(
        'client_id'     => $client_id,
        'client_secret' => $client_secret,
        'refresh_token' => $refresh_token,
        'grant_type'    => 'refresh_token',
    );

    // 使用 WordPress HTTP API 發送 POST 請求
    $response = wp_remote_post($token_url, array(
        'body'    => $token_payload,
        'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
        'timeout' => 15, // 設定超時時間
    ));

    // 4. 處理回應
    if (is_wp_error($response)) {
        return new WP_Error('wpgalr_token_refresh_http_error', '請求 Google 更新 Access Token 失敗：' . $response->get_error_message());
    } else {
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body);
        $status_code = wp_remote_retrieve_response_code($response);

        if ($status_code === 200 && isset($data->access_token)) {
            // 成功取得新的 Access Token
            return $data->access_token;
        } elseif (isset($data->error)) {
             // Google 返回錯誤
             $error_message = isset($data->error_description) ? $data->error_description : $data->error;
             error_log("WPGA_LINE_REPORTER: Google Token Refresh Error (User ID: {$wp_user_id}): {$status_code} - {$error_message}");

             // 判斷是否為 Refresh Token 失效的錯誤
             if ($status_code === 400 && ($data->error === 'invalid_grant' || $data->error === 'invalid_request')) {
                 // Refresh Token 失效，清除資料庫中的 Token 並提示使用者
                 $table = $wpdb->prefix . 'wpgalr_user_configs';
                 $wpdb->update(
                     $table,
                     array('google_refresh_token_encrypted' => null, 'ga_property_id' => null), // 清除 token 和相關設定
                     array('wp_user_id' => $wp_user_id)
                 );
                 return new WP_Error('wpgalr_refresh_token_expired', 'Google 憑證已失效，請在設定頁面重新連結 Google 帳號。');
             } else {
                 return new WP_Error('wpgalr_google_api_error', 'Google API 返回錯誤：' . $error_message . ' (狀態碼: ' . $status_code . ')');
             }

        } else {
            // 未知的回應格式或錯誤
            error_log("WPGA_LINE_REPORTER: Google Token Refresh Unknown Response (User ID: {$wp_user_id}): {$status_code} - " . $body);
            return new WP_Error('wpgalr_token_refresh_unknown_response', '獲取 Google Access Token 時發生未知錯誤。');
        }
    }
}

/**
 * 呼叫 Google Analytics Admin API 獲取使用者有權限存取的 GA4 資源列表。
 *
 * @param int $wp_user_id WordPress 使用者 ID。
 * @return array|WP_Error 成功時返回 GA Property 列表 (ID, name, account_name)，失敗時返回 WP_Error。
 */
function wpgalr_get_user_ga_properties($wp_user_id) {
    $access_token = wpgalr_get_google_access_token($wp_user_id);

    if (is_wp_error($access_token)) {
        return $access_token; // 返回獲取 Access Token 的錯誤
    }

    try {
        $client = new Client();
        $client->setAccessToken($access_token);

        $analytics_admin_service = new AnalyticsAdmin($client);

        // 呼叫 listAccountSummaries 方法獲取帳戶和資源摘要
        $account_summaries_response = $analytics_admin_service->accountSummaries->listAccountSummaries();

        $properties_list = [];

        if ($account_summaries_response->getAccountSummaries()) {
            foreach ($account_summaries_response->getAccountSummaries() as $account_summary) {
                $account_name = $account_summary->getDisplayName();
                if ($account_summary->getPropertySummaries()) {
                    foreach ($account_summary->getPropertySummaries() as $property_summary) {
                        // 檢查是否為 GA4 Property (GA4 Property ID 是數字)
                        // GA3 Property ID 是 UA- 開頭
                        // 檢查 Property 格式是否符合 properties/{propertyId} 且 propertyId 是數字
                        $property_resource_name = $property_summary->getProperty();
                        $property_id = basename($property_resource_name); // 從 properties/12345 提取 12345

                         if (is_numeric($property_id)) { // 簡易判斷是否為 GA4 Property ID
                             $properties_list[] = array(
                                 'id' => $property_id,
                                 'name' => $property_summary->getDisplayName(),
                                 'account_name' => $account_name,
                             );
                         }
                    }
                }
            }
        }

        if (empty($properties_list)) {
            return new WP_Error('wpgalr_no_ga_properties', '找不到任何 Google Analytics 4 資源，請確認您的 Google 帳號擁有 GA4 資源的讀取權限。');
        }

        return $properties_list;

    } catch (Google\Service\Exception $e) {
        error_log('WPGA_LINE_REPORTER: Google Admin API Error: ' . $e->getMessage());
        return new WP_Error('wpgalr_google_admin_api_error', '呼叫 Google Analytics Admin API 失敗：' . $e->getMessage());
    } catch (Exception $e) {
        error_log('WPGA_LINE_REPORTER: Exception fetching GA properties: ' . $e->getMessage());
        return new WP_Error('wpgalr_fetch_ga_properties_exception', '獲取 Google Analytics 資源時發生未知錯誤：' . $e->getMessage());
    }
}

/**
 * 處理 Google OAuth 回呼。
 */
function wpgalr_google_callback_handler() {
    // 檢查是否是我們的回呼請求 (通過特定的查詢參數)
    if (isset($_GET['wpgalr_google_callback']) && $_GET['wpgalr_google_callback'] == '1' && isset($_GET['code'])) {

        $auth_code = sanitize_text_field($_GET['code']); // 獲取授權碼

        // 獲取儲存的 API 憑證和重定向 URI
        $client_id = get_option('wpgalr_google_client_id');
        $client_secret = get_option('wpgalr_google_client_secret');
        // 重定向 URI 應該是您在 Google Cloud Console 中設定的，指向這個回呼處理函式
        // 例如: 您網站的 URL?wpgalr_google_callback=1
        // 我們將這個 URL 儲存在選項中，方便管理
        $redirect_uri = get_option('wpgalr_google_redirect_uri');

        // 檢查是否取得所有必要資訊
        if (empty($client_id) || empty($client_secret) || empty($redirect_uri) || empty($auth_code)) {
             // 處理錯誤，重定向回設定頁面並顯示錯誤訊息
             $error_message = '設定不完整，請檢查 Google API 憑證和重定向 URI。';
             wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=setup_incomplete&error_message=' . urlencode($error_message)));
             exit;
        }

        // 準備 POST 請求到 Google Token 端點
        $token_url = 'https://oauth2.googleapis.com/token';
        $token_payload = array(
            'code'          => $auth_code,
            'client_id'     => $client_id,
            'client_secret' => $client_secret,
            'redirect_uri'  => $redirect_uri,
            'grant_type'    => 'authorization_code',
        );

        // 使用 WordPress HTTP API 發送 POST 請求
        $response = wp_remote_post($token_url, array(
            'body'    => $token_payload,
            'headers' => array('Content-Type' => 'application/x-www-form-urlencoded'),
            'timeout' => 15, // 設定超時時間
        ));

        // 處理回應
        if (is_wp_error($response)) {
            $error_message = '交換 Google Token 失敗：' . $response->get_error_message();
             wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=token_exchange_failed&error_message=' . urlencode($error_message)));
             exit;
        } else {
            $body = wp_remote_retrieve_body($response);
            $data = json_decode($body, true); // 解碼為陣列
            $status_code = wp_remote_retrieve_response_code($response);

            if ($status_code === 200 && isset($data['access_token']) && isset($data['refresh_token'])) {
                $access_token = $data['access_token'];
                $refresh_token = $data['refresh_token'];

                // 獲取使用者 Google Email
                $userinfo_url = 'https://www.googleapis.com/oauth2/v3/userinfo';
                $userinfo_response = wp_remote_get($userinfo_url, array(
                    'headers' => array('Authorization' => 'Bearer ' . $access_token),
                     'timeout' => 15,
                ));

                if (!is_wp_error($userinfo_response) && wp_remote_retrieve_response_code($userinfo_response) === 200) {
                    $userinfo_body = wp_remote_retrieve_body($userinfo_response);
                    $userinfo_data = json_decode($userinfo_body, true);
                    $google_email = isset($userinfo_data['email']) ? $userinfo_data['email'] : null;

                    // 儲存 Refresh Token 和 Google Email，並與當前登入的 WordPress 使用者關聯
                    $current_wp_user_id = get_current_user_id();
                    if ($current_wp_user_id && $google_email) {
                         // 儲存或更新使用者設定
                         // 在回呼成功時，我們只儲存 token 和 email，GA Property 選擇在後續頁面操作
                         $update_success = wpgalr_update_user_config($current_wp_user_id, [
                             'google_email' => $google_email,
                             'google_refresh_token' => $refresh_token,
                             // 不在此處設定 ga_property_id 等
                         ]);

                         if ($update_success === false) {
                             $error_message = '儲存使用者設定失敗。'; // wpgalr_update_user_config 已記錄詳細錯誤
                             wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=save_config_failed&error_message=' . urlencode($error_message)));
                             exit;
                         } else {
                            // 成功連結，重定向回設定頁面並顯示成功訊息
                            wp_redirect(admin_url('admin.php?page=wpgalr-settings&status=google_linked'));
                            exit;
                         }

                    } else {
                        // 如果回呼時沒有 WordPress 使用者登入，或者無法獲取 Google Email
                        $error_message = '無法關聯到 WordPress 使用者或取得 Google Email，請確認已登入 WordPress。';
                         wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=user_association_failed&error_message=' . urlencode($error_message)));
                         exit;
                    }

                } else {
                     // 獲取使用者資訊失敗
                     $error_message = '無法獲取 Google 帳號資訊。';
                     if (is_wp_error($userinfo_response)) {
                         $error_message .= ' HTTP 錯誤：' . $userinfo_response->get_error_message();
                     } else {
                         $error_message .= ' 狀態碼：' . wp_remote_retrieve_response_code($userinfo_response);
                     }
                      wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=get_userinfo_failed&error_message=' . urlencode($error_message)));
                      exit;
                }


            } else {
                // Token 交換失敗，Google 返回錯誤
                 $error_message = isset($data['error_description']) ? $data['error_description'] : (isset($data['error']) ? $data['error'] : '未知 Token 交換錯誤');
                 error_log("WPGA_LINE_REPORTER: Google Token Exchange Error: {$status_code} - {$error_message}");
                 wp_redirect(admin_url('admin.php?page=wpgalr-settings&error_code=token_exchange_error_response&error_message=' . urlencode($error_message)));
                 exit;
            }
        }
    }
    // 如果不是我們的回呼請求，讓 WordPress 正常處理
}

add_action('init', 'wpgalr_google_callback_handler');

/**
 * 添加外掛設定頁面到 WordPress 管理選單。
 */
function wpgalr_add_admin_menu() {
    add_menu_page(
        __('WP GA LINE Reporter 設定', 'wpgalr'), // Page title
        __('GA LINE Reporter', 'wpgalr'),      // Menu title
        'manage_options',                       // Capability required
        'wpgalr-settings',                      // Menu slug
        'wpgalr_settings_page_content',         // Function to display the page content
        'dashicons-chart-bar',                  // Icon URL or Dashicon
        80                                      // Position
    );
}

add_action('admin_menu', 'wpgalr_add_admin_menu');

/**
 * 渲染外掛設定頁面內容。
 */
function wpgalr_settings_page_content() {
    // 檢查使用者權限
    if (!current_user_can('manage_options')) {
        wp_die(__('您沒有足夠的權限來訪問此頁面。', 'wpgalr'));
    }

    $current_wp_user_id = get_current_user_id();
    $user_config = null;
    if ($current_wp_user_id) {
         global $wpdb;
         $config_table = $wpdb->prefix . 'wpgalr_user_configs';
         $user_config = $wpdb->get_row($wpdb->prepare(
             "SELECT * FROM $config_table WHERE wp_user_id = %d", // 獲取所有欄位以便檢查 GA Property
             $current_wp_user_id
         ));
    }

    // 處理表單提交 (儲存 API 憑證 或 GA Property)
    if (isset($_POST['wpgalr_settings_submit'])) {
        // 驗證 Nonce
        if (!isset($_POST['wpgalr_settings_nonce']) || !wp_verify_nonce($_POST['wpgalr_settings_nonce'], 'wpgalr_save_settings')) {
            wp_die(__('安全性檢查失敗，請重試。', 'wpgalr'));
        }

        // 處理 Google API 憑證儲存
        if (isset($_POST['wpgalr_google_client_id'])) {
             $client_id = sanitize_text_field($_POST['wpgalr_google_client_id']);
             $client_secret = sanitize_text_field($_POST['wpgalr_google_client_secret']);
             // 自動生成並儲存重定向 URI
             $redirect_uri = site_url('/?wpgalr_google_callback=1'); // 使用查詢參數作為回呼 URL

             update_option('wpgalr_google_client_id', $client_id);
             update_option('wpgalr_google_client_secret', $client_secret);
             update_option('wpgalr_google_redirect_uri', $redirect_uri);

             add_settings_error('wpgalr_settings_messages', 'wpgalr_settings_saved', __('Google API 設定已儲存。', 'wpgalr'), 'success');
        }

        // 處理 GA Property 選擇儲存
        if (isset($_POST['wpgalr_selected_ga_property']) && $current_wp_user_id) {
             $selected_property_id = sanitize_text_field($_POST['wpgalr_selected_ga_property']);

             // 從暫存的列表中查找選中的 Property 詳細信息 (如果存在)
             $ga_properties_list_temp = get_transient('wpgalr_user_ga_properties_' . $current_wp_user_id);
             $selected_property_details = null;
             if ($ga_properties_list_temp && is_array($ga_properties_list_temp)) {
                  foreach ($ga_properties_list_temp as $prop) {
                       if (isset($prop['id']) && $prop['id'] === $selected_property_id) {
                            $selected_property_details = $prop;
                            break;
                       }
                  }
             }

             $update_data = ['ga_property_id' => $selected_property_id];
             if ($selected_property_details) {
                  $update_data['ga_account_name'] = $selected_property_details['account_name'];
                  $update_data['ga_property_name'] = $selected_property_details['name'];
             }

             $update_success = wpgalr_update_user_config($current_wp_user_id, $update_data);

             if ($update_success === false) {
                  add_settings_error('wpgalr_settings_messages', 'wpgalr_ga_property_save_failed', __('儲存 GA Property 失敗。', 'wpgalr'), 'error');
             } else {
                  add_settings_error('wpgalr_settings_messages', 'wpgalr_ga_property_saved', __('GA Property 設定已儲存。', 'wpgalr'), 'success');
                  // 更新 $user_config 以反映最新狀態
                  $user_config = $wpdb->get_row($wpdb->prepare(
                      "SELECT * FROM $config_table WHERE wp_user_id = %d",
                      $current_wp_user_id
                  ));
             }
             // 清除暫存
             delete_transient('wpgalr_user_ga_properties_' . $current_wp_user_id);
        }

        // 重新載入頁面以顯示更新後的狀態和訊息 (可選，或使用 AJAX)
        // wp_redirect(admin_url('admin.php?page=wpgalr-settings'));
        // exit;
    }

    // 顯示設定頁面內容
    ?>
    <div class="wrap">
        <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

        <?php settings_errors('wpgalr_settings_messages'); ?>

        <form method="post" action="">
            <?php wp_nonce_field('wpgalr_save_settings', 'wpgalr_settings_nonce'); ?>

            <h2><?php esc_html_e('Google API 設定', 'wpgalr'); ?></h2>
            <p><?php esc_html_e('請在 Google Cloud Platform 中建立一個專案，啟用 Analytics Reporting API 和 Analytics Admin API，並建立 OAuth 同意畫面憑證。', 'wpgalr'); ?></p>
             <p><?php esc_html_e('設定 OAuth 憑證的「已授權的重新導向 URI」為：', 'wpgalr'); ?> <strong><code><?php echo esc_url(site_url('/?wpgalr_google_callback=1')); ?></code></strong></p>

            <table class="form-table">
                <tr>
                    <th scope="row"><label for="wpgalr_google_client_id"><?php esc_html_e('Google Client ID', 'wpgalr'); ?></label></th>
                    <td><input name="wpgalr_google_client_id" type="text" id="wpgalr_google_client_id" value="<?php echo esc_attr(get_option('wpgalr_google_client_id')); ?>" class="regular-text"></td>
                </tr>
                <tr>
                    <th scope="row"><label for="wpgalr_google_client_secret"><?php esc_html_e('Google Client Secret', 'wpgalr'); ?></label></th>
                    <td><input name="wpgalr_google_client_secret" type="text" id="wpgalr_google_client_secret" value="<?php echo esc_attr(get_option('wpgalr_google_client_secret')); ?>" class="regular-text"></td>
                </tr>
            </table>

            <?php submit_button(__('儲存 API 設定', 'wpgalr'), 'primary', 'wpgalr_settings_submit'); ?>
        </form>

        <hr>

        <h2><?php esc_html_e('Google 帳號連結與 GA4 資源選擇', 'wpgalr'); ?></h2>
        <?php
        $google_linked = ($user_config && !empty($user_config->google_refresh_token_encrypted));
        $ga_property_set = ($user_config && !empty($user_config->ga_property_id));

        if (!$google_linked) {
            // 未連結 Google 帳號，提供連結按鈕
            $client_id = get_option('wpgalr_google_client_id');
            $redirect_uri = get_option('wpgalr_google_redirect_uri');

            if (!empty($client_id) && !empty($redirect_uri)) {
                // 構建 Google 授權 URL
                // 在實際應用中，建議使用 Google PHP Client Library 來處理 OAuth URL 的生成
                $auth_url = add_query_arg(
                    array(
                        'client_id' => $client_id,
                        'redirect_uri' => $redirect_uri,
                        'scope' => 'openid email https://www.googleapis.com/auth/analytics.readonly', // 需要讀取 GA 資料的權限
                        'response_type' => 'code',
                        'access_type' => 'offline', // 獲取 Refresh Token
                        'prompt' => 'consent', // 確保每次都顯示同意畫面
                    ),
                    'https://accounts.google.com/o/oauth2/auth' // 或從 Discovery Document 獲取
                );

                echo '<p>' . esc_html__('請點擊按鈕連結您的 Google 帳號以授權此外掛存取您的 Google Analytics 資料：', 'wpgalr') . '</p>';
                echo '<p><a href="' . esc_url($auth_url) . '" class="button button-primary">' . esc_html__('連結 Google 帳號', 'wpgalr') . '</a></p>';
            } else {
                 echo '<p style="color: orange;">' . esc_html__('請先在上方輸入 Google Client ID 和 Client Secret 並儲存。', 'wpgalr') . '</p>';
            }

        } else {
            // 已連結 Google 帳號
            echo '<p style="color: green;">✔ ' . esc_html__('已成功連結 Google 帳號', 'wpgalr') . (empty($user_config->google_email) ? '' : ' (' . esc_html($user_config->google_email) . ')') . '</p>';

            if (!$ga_property_set) {
                 // Google 帳號已連結，但 GA Property 未設定，顯示 GA 資源選擇
                 echo '<h3>' . esc_html__('選擇 Google Analytics 4 資源', 'wpgalr') . '</h3>';

                 // 嘗試獲取 GA 資源列表
                 $ga_properties = wpgalr_get_user_ga_properties($current_wp_user_id);

                 if (is_wp_error($ga_properties)) {
                     // 獲取資源失敗，顯示錯誤訊息
                     echo '<p style="color: red;">' . esc_html__('無法獲取 Google Analytics 資源列表：', 'wpgalr') . esc_html($ga_properties->get_error_message()) . '</p>';
                 } elseif (empty($ga_properties)) {
                      // 獲取到空列表
                     echo '<p style="color: orange;">' . esc_html__('找不到任何 Google Analytics 4 資源。請確認您的 Google 帳號擁有 GA4 資源的讀取權限。', 'wpgalr') . '</p>';
                 } else {
                      // 成功獲取資源列表，顯示下拉選單
                     echo '<form method="post" action="">';
                     wp_nonce_field('wpgalr_save_settings', 'wpgalr_settings_nonce'); // 相同的 nonce
                     echo '<table class="form-table">';
                     echo '<tr>';
                     echo '<th scope="row"><label for="wpgalr_selected_ga_property">' . esc_html__('選擇 GA4 資源', 'wpgalr') . '</label></th>';
                     echo '<td>';
                     echo '<select name="wpgalr_selected_ga_property" id="wpgalr_selected_ga_property">';
                     echo '<option value="">' . esc_html__('-- 請選擇 --', 'wpgalr') . '</option>';

                     // 將資源列表暫存起來，以便在表單提交時獲取 account_name 和 property_name
                     set_transient('wpgalr_user_ga_properties_' . $current_wp_user_id, $ga_properties, HOUR_IN_SECONDS ); // 暫存 1 小時

                     foreach ($ga_properties as $property) {
                         echo '<option value="' . esc_attr($property['id']) . '">' . esc_html($property['name'] . ' (帳號: ' . $property['account_name'] . ')') . '</option>';
                     }
                     echo '</select>';
                     echo '</td>';
                     echo '</tr>';
                     echo '</table>';

                     submit_button(__('儲存 GA4 資源', 'wpgalr'), 'primary', 'wpgalr_settings_submit');
                     echo '</form>';
                 }

            } else {
                 // GA Property 已設定
                 echo '<p style="color: green;">✔ ' . esc_html__('已選擇 GA4 資源：', 'wpgalr') . esc_html($user_config->ga_property_name) . ' (' . esc_html($user_config->ga_property_id) . ')' . (empty($user_config->ga_account_name) ? '' : ' [' . esc_html__('帳號', 'wpgalr') . ': ' . esc_html($user_config->ga_account_name) . ']') . '</p>';

                 // TODO: 提供修改 GA Property 的按鈕
            }

            // TODO: 提供取消連結 Google 帳號的按鈕

        }
        ?>

        <?php
        // 顯示回呼處理結果訊息 (從 URL 參數) - 這些訊息在頁面頂部的 settings_errors 已經處理了，這裡可以移除重複部分或只保留特定訊息
        // if (isset($_GET['status']) && $_GET['status'] === 'google_linked') {
        //     echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Google 帳號連結成功！', 'wpgalr') . '</p></div>';
        // }
        // if (isset($_GET['error_code'])) {
        //      $error_message = isset($_GET['error_message']) ? sanitize_text_field(urldecode($_GET['error_message'])) : __('發生未知錯誤。', 'wpgalr');
        //      echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__('連結 Google 帳號失敗：', 'wpgalr') . esc_html($error_message) . '</p></div>';
        // }
        ?>

        <h2><?php esc_html_e('加密金鑰設定 (重要!)', 'wpgalr'); ?></h2>
        <p><?php esc_html_e('為了安全儲存 Google Refresh Token，此外掛使用加密功能。請在您的網站根目錄下的 ', 'wpgalr'); ?> <strong><code>wp-config.php</code></strong> <?php esc_html_e('檔案中，在 ', 'wpgalr'); ?> <code>/* That's all, stop editing! Happy publishing. */</code> <?php esc_html_e('這行之前，加入以下程式碼並替換 ', 'wpgalr'); ?> <code>'YOUR_VERY_SECURE_RANDOM_KEY_HERE'</code> <?php esc_html_e('為一個由足夠長度且隨機字元組成的強密碼。', 'wpgalr'); ?></p>
        <p><code>define('WPGA_LINE_REPORTER_ENCRYPTION_KEY', 'YOUR_VERY_SECURE_RANDOM_KEY_HERE');</code></p>
        <p><?php esc_html_e('請確保此金鑰的安全性，不要與他人分享。如果金鑰遺失或更改，已連結的 Google 帳號將需要重新授權。', 'wpgalr'); ?></p>

        <?php
        // TODO: 其他設定項目 (LINE 設定, 排程設定)
        ?>

        <hr>

        <h2><?php esc_html_e('LINE 通知設定', 'wpgalr'); ?></h2>
        <p><?php esc_html_e('請在 LINE Developers 建立一個 Messaging API Channel，並取得 Channel Access Token。', 'wpgalr'); ?></p>

        <form method="post" action="">
            <?php wp_nonce_field('wpgalr_save_settings', 'wpgalr_settings_nonce'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><label for="wpgalr_line_channel_token"><?php esc_html_e('LINE Channel Access Token', 'wpgalr'); ?></label></th>
                    <td>
                        <input name="wpgalr_line_channel_token" type="text" id="wpgalr_line_channel_token" 
                               value="<?php echo esc_attr(get_option('wpgalr_line_channel_token')); ?>" class="regular-text">
                        <p class="description"><?php esc_html_e('請輸入 LINE Messaging API 的 Channel Access Token。', 'wpgalr'); ?></p>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php esc_html_e('報表排程', 'wpgalr'); ?></th>
                    <td>
                        <fieldset>
                            <label>
                                <input type="checkbox" name="wpgalr_enable_daily_report" value="1" 
                                       <?php checked(get_option('wpgalr_enable_daily_report'), '1'); ?>>
                                <?php esc_html_e('啟用每日報表', 'wpgalr'); ?>
                            </label>
                            <br>
                            <label>
                                <input type="time" name="wpgalr_report_time" 
                                       value="<?php echo esc_attr(get_option('wpgalr_report_time', '09:00')); ?>">
                                <?php esc_html_e('報表發送時間', 'wpgalr'); ?>
                            </label>
                        </fieldset>
                    </td>
                </tr>
            </table>

            <?php submit_button(__('儲存 LINE 設定', 'wpgalr'), 'primary', 'wpgalr_line_settings_submit'); ?>
        </form>

        <hr>

        <h2><?php esc_html_e('手動發送報表', 'wpgalr'); ?></h2>
        <p><?php esc_html_e('選擇日期範圍並手動發送報表。', 'wpgalr'); ?></p>

        <form method="post" action="">
            <?php wp_nonce_field('wpgalr_manual_report', 'wpgalr_manual_report_nonce'); ?>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php esc_html_e('報表日期範圍', 'wpgalr'); ?></th>
                    <td>
                        <fieldset>
                            <label>
                                <?php esc_html_e('開始日期：', 'wpgalr'); ?>
                                <input type="date" name="wpgalr_report_start_date" 
                                       value="<?php echo esc_attr(date('Y-m-d', strtotime('-7 days'))); ?>" 
                                       max="<?php echo esc_attr(date('Y-m-d')); ?>">
                            </label>
                            <br>
                            <label>
                                <?php esc_html_e('結束日期：', 'wpgalr'); ?>
                                <input type="date" name="wpgalr_report_end_date" 
                                       value="<?php echo esc_attr(date('Y-m-d')); ?>" 
                                       max="<?php echo esc_attr(date('Y-m-d')); ?>">
                            </label>
                        </fieldset>
                    </td>
                </tr>
            </table>

            <?php submit_button(__('發送報表', 'wpgalr'), 'primary', 'wpgalr_manual_report_submit'); ?>
        </form>

        <script type="text/javascript">
        jQuery(document).ready(function($) {
            // 確保結束日期不早於開始日期
            $('input[name="wpgalr_report_start_date"]').on('change', function() {
                var startDate = $(this).val();
                var endDateInput = $('input[name="wpgalr_report_end_date"]');
                if (startDate > endDateInput.val()) {
                    endDateInput.val(startDate);
                }
                endDateInput.attr('min', startDate);
            });

            // 確保開始日期不晚於結束日期
            $('input[name="wpgalr_report_end_date"]').on('change', function() {
                var endDate = $(this).val();
                var startDateInput = $('input[name="wpgalr_report_start_date"]');
                if (endDate < startDateInput.val()) {
                    startDateInput.val(endDate);
                }
                startDateInput.attr('max', endDate);
            });
        });
        </script>

    </div>
    <?php
}

/**
 * 獲取 Google Analytics 數據。
 * 
 * @param int    $wp_user_id WordPress 使用者 ID。
 * @param string $start_date 開始日期 (YYYY-MM-DD)。
 * @param string $end_date   結束日期 (YYYY-MM-DD)。
 * @return array|WP_Error 成功時返回數據陣列，失敗時返回 WP_Error。
 */
function wpgalr_get_ga_data($wp_user_id, $start_date, $end_date) {
    // 獲取 Access Token
    $access_token = wpgalr_get_google_access_token($wp_user_id);
    if (is_wp_error($access_token)) {
        return $access_token;
    }

    // 獲取使用者的 GA Property ID
    global $wpdb;
    $config_table = $wpdb->prefix . 'wpgalr_user_configs';
    $user_config = $wpdb->get_row($wpdb->prepare(
        "SELECT ga_property_id FROM $config_table WHERE wp_user_id = %d",
        $wp_user_id
    ));

    if (!$user_config || empty($user_config->ga_property_id)) {
        return new WP_Error('wpgalr_no_ga_property', '未設定 Google Analytics Property ID。');
    }

    // 準備 API 請求
    $property_id = $user_config->ga_property_id;
    $api_url = "https://analyticsdata.googleapis.com/v1beta/properties/{$property_id}:runReport";

    // 準備請求體
    $request_body = array(
        'dateRanges' => array(
            array(
                'startDate' => $start_date,
                'endDate' => $end_date
            )
        ),
        'dimensions' => array(
            array('name' => 'date')
        ),
        'metrics' => array(
            array('name' => 'totalRevenue'),
            array('name' => 'sessions')
        ),
        'orderBys' => array(
            array(
                'dimension' => array('dimensionName' => 'date'),
                'desc' => true
            )
        )
    );

    // 發送 API 請求
    $response = wp_remote_post($api_url, array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $access_token,
            'Content-Type' => 'application/json'
        ),
        'body' => json_encode($request_body),
        'timeout' => 30
    ));

    if (is_wp_error($response)) {
        return new WP_Error('wpgalr_api_request_failed', 'API 請求失敗：' . $response->get_error_message());
    }

    $status_code = wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    if ($status_code !== 200) {
        $error_message = isset($data['error']['message']) ? $data['error']['message'] : '未知錯誤';
        return new WP_Error('wpgalr_api_error', 'Google Analytics API 錯誤：' . $error_message);
    }

    // 處理 API 回應數據
    $processed_data = array();
    if (isset($data['rows'])) {
        foreach ($data['rows'] as $row) {
            $date = $row['dimensionValues'][0]['value'];
            $metrics = $row['metricValues'];

            $processed_data[] = array(
                'date' => $date,
                'revenue' => floatval($metrics[0]['value']),
                'sessions' => intval($metrics[1]['value'])
            );
        }
    }

    return $processed_data;
}

/**
 * 格式化 Google Analytics 數據為報表格式。
 * 
 * @param array $ga_data Google Analytics 數據。
 * @return string 格式化後的報表內容。
 */
function wpgalr_format_ga_report($ga_data) {
    if (empty($ga_data)) {
        return '無數據可顯示。';
    }

    // 按日期分組數據
    $grouped_data = array();
    foreach ($ga_data as $row) {
        $date = $row['date'];
        if (!isset($grouped_data[$date])) {
            $grouped_data[$date] = array(
                'revenue' => 0,
                'sessions' => 0
            );
        }
        $grouped_data[$date]['revenue'] += $row['revenue'];
        $grouped_data[$date]['sessions'] += $row['sessions'];
    }

    // 生成報表
    $report = "📊 Google Analytics 報表\n\n";
    foreach ($grouped_data as $date => $data) {
        $report .= "📅 {$date}\n";
        $report .= "💰 收入：NT$ " . number_format($data['revenue'], 2) . "\n";
        $report .= "👥 造訪次數：{$data['sessions']}\n\n";
    }

    return $report;
}

/**
 * 發送 LINE 通知。
 * 
 * @param string $message 要發送的訊息。
 * @param string $line_channel_token LINE Channel Access Token。
 * @return bool|WP_Error 成功時返回 true，失敗時返回 WP_Error。
 */
function wpgalr_send_line_notification($message, $line_channel_token) {
    if (empty($line_channel_token)) {
        return new WP_Error('wpgalr_no_line_token', '未設定 LINE Channel Access Token。');
    }

    $line_api_url = 'https://api.line.me/v2/bot/message/broadcast';
    
    $response = wp_remote_post($line_api_url, array(
        'headers' => array(
            'Authorization' => 'Bearer ' . $line_channel_token,
            'Content-Type' => 'application/json'
        ),
        'body' => json_encode(array(
            'messages' => array(
                array(
                    'type' => 'text',
                    'text' => $message
                )
            )
        )),
        'timeout' => 30
    ));

    if (is_wp_error($response)) {
        return new WP_Error('wpgalr_line_api_error', 'LINE API 請求失敗：' . $response->get_error_message());
    }

    $status_code = wp_remote_retrieve_response_code($response);
    if ($status_code !== 200) {
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        $error_message = isset($data['message']) ? $data['message'] : '未知錯誤';
        return new WP_Error('wpgalr_line_api_error', 'LINE API 錯誤：' . $error_message);
    }

    return true;
}

/**
 * 發送每日報表。
 */
function wpgalr_send_daily_report() {
    // 獲取所有啟用的使用者
    global $wpdb;
    $config_table = $wpdb->prefix . 'wpgalr_user_configs';
    $active_users = $wpdb->get_results(
        "SELECT wp_user_id, ga_property_id FROM $config_table WHERE is_active = 1"
    );

    if (empty($active_users)) {
        return;
    }

    $line_channel_token = get_option('wpgalr_line_channel_token');
    if (empty($line_channel_token)) {
        error_log('WPGA_LINE_REPORTER: LINE Channel Access Token 未設定');
        return;
    }

    // 計算日期範圍（昨天）
    $end_date = date('Y-m-d', strtotime('-1 day'));
    $start_date = $end_date;

    foreach ($active_users as $user) {
        $ga_data = wpgalr_get_ga_data($user->wp_user_id, $start_date, $end_date);
        if (!is_wp_error($ga_data)) {
            $report = wpgalr_format_ga_report($ga_data);
            wpgalr_send_line_notification($report, $line_channel_token);
        }
    }
}

// 註冊排程任務
add_action('wpgalr_daily_report', 'wpgalr_send_daily_report');

// 在外掛停用時清除排程任務
register_deactivation_hook(__FILE__, function() {
    wp_clear_scheduled_hook('wpgalr_daily_report');
});

// TODO: 移除外掛時的清理函式 (選擇性)
// register_deactivation_hook(__FILE__, 'wpgalr_deactivate');
// register_uninstall_hook(__FILE__, 'wpgalr_uninstall');

// function wpgalr_uninstall() {
//     global $wpdb;
//     $table_name = $wpdb->prefix . 'wpgalr_user_configs';
//     $wpdb->query("DROP TABLE IF EXISTS $table_name");
//     delete_option('wpgalr_db_version');
//     delete_option('wpgalr_google_client_id');
//     delete_option('wpgalr_google_client_secret');
//     delete_option('wpgalr_google_redirect_uri');
//     // TODO: 刪除其他選項和使用者中繼資料
// }

/**
 * 處理手動發送報表的請求。
 */
function wpgalr_handle_manual_report() {
    if (!isset($_POST['wpgalr_manual_report_nonce']) || 
        !wp_verify_nonce($_POST['wpgalr_manual_report_nonce'], 'wpgalr_manual_report')) {
        wp_die(__('安全性檢查失敗，請重試。', 'wpgalr'));
    }

    if (!current_user_can('manage_options')) {
        wp_die(__('您沒有足夠的權限執行此操作。', 'wpgalr'));
    }

    $start_date = isset($_POST['wpgalr_report_start_date']) ? sanitize_text_field($_POST['wpgalr_report_start_date']) : '';
    $end_date = isset($_POST['wpgalr_report_end_date']) ? sanitize_text_field($_POST['wpgalr_report_end_date']) : '';

    if (empty($start_date) || empty($end_date)) {
        add_settings_error('wpgalr_settings_messages', 'wpgalr_manual_report_error', 
                          __('請選擇報表日期範圍。', 'wpgalr'), 'error');
        return;
    }

    $current_user_id = get_current_user_id();
    $ga_data = wpgalr_get_ga_data($current_user_id, $start_date, $end_date);

    if (is_wp_error($ga_data)) {
        add_settings_error('wpgalr_settings_messages', 'wpgalr_manual_report_error', 
                          __('獲取 GA 數據失敗：' . $ga_data->get_error_message(), 'wpgalr'), 'error');
        return;
    }

    $report = wpgalr_format_ga_report($ga_data);
    $line_channel_token = get_option('wpgalr_line_channel_token');

    if (empty($line_channel_token)) {
        add_settings_error('wpgalr_settings_messages', 'wpgalr_manual_report_error', 
                          __('LINE Channel Access Token 未設定。', 'wpgalr'), 'error');
        return;
    }

    $result = wpgalr_send_line_notification($report, $line_channel_token);

    if (is_wp_error($result)) {
        add_settings_error('wpgalr_settings_messages', 'wpgalr_manual_report_error', 
                          __('發送 LINE 通知失敗：' . $result->get_error_message(), 'wpgalr'), 'error');
    } else {
        add_settings_error('wpgalr_settings_messages', 'wpgalr_manual_report_success', 
                          __('報表已成功發送。', 'wpgalr'), 'success');
    }
}

// 註冊處理手動發送報表的動作
add_action('admin_init', function() {
    if (isset($_POST['wpgalr_manual_report_submit'])) {
        wpgalr_handle_manual_report();
    }
});

?>
