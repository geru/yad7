<?php
/**
 * Created by: hugh
 * Date: 4/29/20
 * Time: 12:27 PM
 * hard redirects and anti-hacking measures go here.
 */
global $base_url;

$URL_PermRedirect = [
  // '/example/src/redirect-path' => '/example/dest/redirect-path'
];
if( isset( $URL_PermRedirect[$_SERVER['REQUEST_URI']] ) ){
  header('HTTP/1.0 301 Moved Permanently');
  header('Location: ' . $base_url . $URL_PermRedirect[$_SERVER['REQUEST_URI']]);
  exit();
}

$URL_PermRedirectPattern = [
  // '/^\/examplepattern\/(.*)/i' => '/$1',
];
foreach( $URL_PermRedirectPattern as $searchpattern => $replacementpattern ) {
  $new_URL = preg_replace($searchpattern, $replacementpattern, $_SERVER['REQUEST_URI'] );
  if( $new_URL && $new_URL != $_SERVER['REQUEST_URI']) {
    header('HTTP/1.0 301 Moved Permanently');
    header('Location: ' . $base_url . $new_URL );
    exit();
  }
}

/* Spam prefilter: return FALSE if allowed to pass. TRUE if spam */
function _spam_prefilter() {
  $remoteip = ip_address();
  // whitelist sister-sites
  if( in_array($remoteip,
    [ // '127.0.0.1', // example whitelist ip address
    ]) ){
    return FALSE;
  }

  $spam = array(
    'banoutright' => [
      '/wp-login.php',

      // '/node/add'
    ],
    'banpattern' => [
      '/q=user\/register/',
      '/recumbent-gearing-calculator\?q=/',
      '/aspx$/',
    ],
    'selfonly' => array(
      '/user', '/user/login', '/user/register', '/user/password', '/contact'
    ),
    'referpath' => array( '/user/register/' => '/^user$/',
      '/user/password' => '/^user$/',
      '/q=node\/add/' => '/^admin\/content$/'
    ),
    'ipban' => array(
      0xffffffff => array(
        // '127.0.0.1', // test ban self
        '23.247.15.2', // digital frag networks 180129
        '34.248.123.113', // Amazon Data Services Ireland
        '40.76.56.112', // microsoft
        '45.55.206.84', // digitalocean
        '46.4.64.197', // Hetzner Online
        '46.105.98.166', // OVH SAS
        '52.170.37.81', // microsoft azure
        '52.179.1.148',
        '52.186.123.246',
        '69.30.198.202', // WholeSale Internet, Inc.
        '82.80.249.192', // Bezeqint Hosting
        '93.158.161.114', // Yandex
        '136.243.50.145',
        '138.197.104.225', // digitalocean
        '142.4.215.116',
        '144.76.63.35', // Hetzner Online
        '162.158.88.119', // Cloudflare Germany 171221
        '172.93.192.34',
        '172.103.121.231',
        '173.242.117.250', // volumedrive
        '193.200.241.230', // Contabo GmbH
        '198.27.80.144', // ovhhosting
        '212.237.19.200',
        '216.97.12.86',
        // '98.255.6.202', // 12 via los arboles for testing
      ),
      0xffffff00 => array(
        '35.153.226.0', // amazon
        '40.77.167.0',
        '51.255.65.0', // OVH SAS added 5/19/17
        '52.91.136.0', // amazon
        '64.62.252.0', // hurricane electric
        '66.249.79.0',
        '81.209.177.0', // netEstate GmbH 180129
        '104.218.62', // canada
        '107.172.1.0',
        '107.172.43.0',
        '107.173.76.0',
        '136.243.6.0', // Hetzner 136.243.6.84 added 170528
        '138.201.34.0',
        '145.132.2.0', // netherlands
        '157.55.39.0',
        '164.132.162.0', // OVH SAS added 5/19/17
        '172.69.62.0', // Cloudflare USA 171221

        '198.23.216.0',
        '203.162.13.0', // 180218 203.162.13.173
        '204.44.124.0', // 180218 204.44.124.78
        '207.46.13.0',
        '213.159.38.0', // 180218 213.159.38.90
        '216.244.66.0', // wowrack.com
        '217.182.132.0', // OVH SAS added 5/19/17
        // '24.23.24.0', Sac shop
        // '207.46.13.0', bingbot
        // '127.0.0.0',
      ),
      0xffff0000 => array(
        '34.207.0.0', // 180218 34.224.16.173
        '34.224.0.0', // 180218 34.224.16.173
        '34.226.0.0', // 180218 34.224.16.173
        '34.229.0.0', // 180218 34.224.16.173
        '34.232.0.0', // 180218 34.224.16.173
        '34.239.0.0', // 180218 34.224.16.173
        '37.9.0.0', // europe
        '42.236.0.0', // chinese 180218
        '52.71.0.0', // amazon
        '52.73.0.0', // amazon
        '52.91.0.0', // amazon
        '52.201.0.0', // amazon
        '54.36.0.0', // OVH 180129
        '54.37.0.0', // 180218 54.37.85.55
        '54.152.0.0', // amazon
        '54.165.0.0', // amazon
        '54.167.0.0', // amazon
        '54.197.0.0', // amazon
        '54.235.0.0', // amazon
        '54.237.0.0', // amazon
        // '98.255.0.0', // 12 via los arboles
//        '104.131.73.215', // digitalocean 170406
//        '104.131.88.40', // digitialocean 170528
        '104.131.0.0', // digitalocean
//        '104.236.108.0', // 104.236.108.149 digitalocean
//        '104.236.109.0', // 104.236.109.26 digitalocean
        '104.236.0.0', // digitalocean whitelist sites are: hkern0:104.236.142.117, fomcstl 104.236.144.155, and 138.197.200.68
//        '107.175.67.250',
//        '107.175.64.0',
//        '107.175.149.0',
//        '107.175.152.0',
//        '107.175.64.0',
//        '107.175.149.0',
//        '107.175.152.0',
        '107.23.0.0', // amazon
        '107.175.0.0',
//        '108.162.0.0', // cloudflare
//        '141.101.0.0', // cloudflare
//        '162.158.0.0', // cloudflare
//        '172.68.0.0', // cloudflare
        '119.48.0.0', // chinese 180218
        '124.88.0.0', // 180218 124.88.64.199
        '124.90.0.0', // 124.90.50.132 180218
        '124.235.0.0', // chinese 180218 124.235.138.242
        '125.76.0.0', // china
        '137.74.0.0', // OVH SAS 180129
        '136.243.0.0', // hetzner online
        '139.59.0.0',
        '139.170.0.0', // china
        '141.8.0.0',
        '141.105.0.0',
        '142.4.0.0', // canada and seo dogs
        '142.44.0.0', // canada
        '146.185.0.0', // russian 180218
        '159.65.0.0', // digitalocean
        '172.245.0.0', // colocrossing 180218 172.245.25.188
        '174.127.0.0', // us based
        '180.76.0.0', // chines 180218
        '188.165.0.0', // 180218 188.166.184.79
        '188.166.0.0', // 180218 188.166.184.79
        '192.3.0.0', // colocrossing
        '220.248.0.0', // chinese 180218
        '213.180.0.0', // russia
        '217.69.0.0', // europe
        '217.182.0.0', // europe
      ),
      0xff000000 => array(
        '5.0.0.0',   // europe
        '46.0.0.0',  // europe
        '58.0.0.0',  // china and asia
        '84.0.0.0',  // europe
        '85.0.0.0',  // europe
        '86.0.0.0',  // europe
        '87.0.0.0',  // europe
        '94.0.0.0',  // europe
        '95.0.0.0',  // europe
        '106.0.0.0', // asia
        '109.0.0.0', // europe
        '111.0.0.0', // asia
        '112.0.0.0', // asia
        '116.0.0.0', // asia
        '118.0.0.0', // asia
        '121.0.0.0', // asia
        '123.0.0.0', // asia
        '134.0.0.0', // shell
        '178.0.0.0', // hodgepodge eastern europe
        '185.0.0.0', // hodgepodge
        '188.0.0.0', // hodgepodge includes some cloudflare
        '195.0.0.0', // hodgepodge
        '219.0.0.0', // asia
        '220.0.0.0', // asia
        '221.0.0.0', // asia
        '222.0.0.0', // asia
        '223.0.0.0', // asia
      ),
    ),
  );

  $path = $_SERVER['REQUEST_URI'];
  // filter outright banned paths
  if (in_array($path, $spam['banoutright'])) {
    return -1;
  }

  // filter by pattern in path
  foreach ($spam['banpattern'] as $pattern) {
    if (preg_match($pattern, $path)) {
      return -1;
    }
  }

  // ban certain IP's outright
  $longremote = ip2long($remoteip);
  foreach ($spam['ipban'] as $mask => $bannedIPs) {
    $ip = long2ip($longremote & $mask);
    if (in_array($ip, $bannedIPs)) {
      return 1;
    }
  }

  // filter based on must self-refer
  $substrings = explode('/', $_SERVER['HTTP_REFERER']);
  array_shift($substrings);
  array_shift($substrings);
  $referdomain = array_shift($substrings);
  $referpath = implode('/', $substrings);
  // referer domain must be self
  if (in_array($path, $spam['selfonly']) && (empty($referdomain) || !stristr($referdomain, $_SERVER['HTTP_HOST']))) {
    return -1;
  }

  // referring path must be particular
  if (isset($spam['referpath'][$path]) && !preg_match($spam['referpath'][$path], $referpath)) {
    return -1;
  }
  return FALSE;
} // end of _spamprefilter() function

function __superfast_404_noexceptions() {
  drupal_add_http_header('Status', '404 Not Found');
  $fast_404_html = variable_get('404_fast_html', '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML+RDFa 1.0//EN" "http://www.w3.org/MarkUp/DTD/xhtml-rdfa-1.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL "@path" was not found on this server.</p></body></html>');
  // Replace @path in the variable with the page path.
  print strtr($fast_404_html, array('@path' => check_plain(request_uri())));
  exit;
}

function _blocking_action() {
  $time = REQUEST_TIME + ord(substr(ip_address(), -1));
  $time &= 15;
  $time |= 16;
  sleep($time);
}

/* filter certain spam situations outright */
switch ( $type = _spam_prefilter() ) {
  case -1:
    __superfast_404_noexceptions();
    break;
  case 0:
    break;
  default:
    _blocking_action();
    break;
}
