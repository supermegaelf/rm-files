<?php
declare(strict_types=1);

$PANEL   = rtrim((string) (getenv('PANEL_URL')   ?: 'http://remnawave:3000'), '/');
$SUBPAGE = rtrim((string) (getenv('SUBPAGE_URL') ?: 'http://remnawave-subscription-page:3010'), '/');
$SERVICE = trim((string) getenv('SERVICE_SHORT_UUID'));
$SWAP    = array_values(array_filter(array_map('trim',
    explode(',', strtolower((string) (getenv('SWAP_STATUSES') ?: 'expired,limited'))))));
$PREFIX  = trim((string) (getenv('SUB_PREFIX') ?: 'sub'), '/');

$method   = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri      = $_SERVER['REQUEST_URI'] ?? '/';
$path     = parse_url($uri, PHP_URL_PATH) ?: '/';
$query    = parse_url($uri, PHP_URL_QUERY);
$qs       = $query ? ('?' . $query) : '';

$host     = $_SERVER['HTTP_HOST'] ?? '';
$ua       = $_SERVER['HTTP_USER_AGENT'] ?? '';
$accept   = $_SERVER['HTTP_ACCEPT'] ?? '';
$lang     = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
$clientIp = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['REMOTE_ADDR'] ?? '');

function fwdHeaders(): array
{
    global $host, $ua, $accept, $lang, $clientIp;
    $h = [];
    if ($host)     $h[] = 'Host: ' . $host;
    if ($ua)       $h[] = 'User-Agent: ' . $ua;
    if ($accept)   $h[] = 'Accept: ' . $accept;
    if ($lang)     $h[] = 'Accept-Language: ' . $lang;
    if ($clientIp) {
        $h[] = 'X-Forwarded-For: ' . $clientIp;
        $h[] = 'X-Real-IP: ' . $clientIp;
    }
    $h[] = 'X-Forwarded-Proto: https';
    return $h;
}

function httpReq(string $method, string $url, array $headers, ?string $body = null): array
{
    $opts = ['http' => [
        'method'          => $method,
        'header'          => implode("\r\n", $headers),
        'ignore_errors'   => true,
        'timeout'         => 15,
        'follow_location' => 0,
    ]];
    if ($body !== null) {
        $opts['http']['content'] = $body;
    }
    $out = @file_get_contents($url, false, stream_context_create($opts));

    $code        = 0;
    $respHeaders = [];
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $mm)) {
            $code        = (int) $mm[1];
            $respHeaders = [];
            continue;
        }
        $p = explode(':', $line, 2);
        if (count($p) === 2) {
            $respHeaders[strtolower(trim($p[0]))] = trim($p[1]);
        }
    }

    return ['code' => $code, 'headers' => $respHeaders, 'body' => $out === false ? '' : $out];
}

function emitHeaders(array $headers): void
{
    $drop = ['transfer-encoding', 'connection', 'content-length', 'content-encoding'];
    foreach ($headers as $k => $v) {
        if (in_array($k, $drop, true)) {
            continue;
        }
        header($k . ': ' . $v);
    }
}

function passthrough(): void
{
    global $SUBPAGE, $uri, $method;
    $reqBody = ($method === 'GET' || $method === 'HEAD') ? null : file_get_contents('php://input');
    $r = httpReq($method, $SUBPAGE . $uri, fwdHeaders(), $reqBody);
    http_response_code($r['code'] ?: 502);
    emitHeaders($r['headers']);
    echo $r['body'];
}

if (!preg_match('#^/' . preg_quote($PREFIX, '#') . '/([A-Za-z0-9_-]{4,64})#', $path, $m)) {
    passthrough();
    exit;
}
$shortUuid = $m[1];

if ($SERVICE === '') {
    passthrough();
    exit;
}

if (stripos($accept, 'text/html') !== false) {
    passthrough();
    exit;
}

$info   = httpReq('GET', $PANEL . '/api/sub/' . rawurlencode($shortUuid) . '/info',
    ['Accept: application/json', 'X-Forwarded-For: ' . $clientIp]);
$status = 'active';
if ($info['code'] === 200) {
    $data   = json_decode($info['body'], true);
    $status = strtolower((string) ($data['response']['user']['userStatus'] ?? 'active'));
}

if (!in_array($status, $SWAP, true)) {
    passthrough();
    exit;
}

$rest = substr($path, strlen('/' . $PREFIX . '/' . $shortUuid));
$orig = httpReq('GET', $SUBPAGE . '/' . $PREFIX . '/' . rawurlencode($shortUuid) . $rest . $qs, fwdHeaders());
$svc  = httpReq('GET', $SUBPAGE . '/' . $PREFIX . '/' . rawurlencode($SERVICE)   . $rest . $qs, fwdHeaders());

if ($svc['code'] !== 200 || $svc['body'] === '') {
    passthrough();
    exit;
}

http_response_code(200);

$keep = [
    'subscription-userinfo', 'profile-title', 'profile-update-interval', 'support-url',
    'announce', 'content-disposition', 'profile-web-page-url', 'subscription-refill-date',
];
foreach ($keep as $k) {
    if (isset($orig['headers'][$k])) {
        header($k . ': ' . $orig['headers'][$k]);
    }
}
header('Content-Type: ' . ($svc['headers']['content-type'] ?? 'text/plain; charset=utf-8'));
echo $svc['body'];
