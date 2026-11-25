<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\HttpFoundation\IpUtils;

/** Password SMTP and TLS relay accounts, without a client certificate. */
final class StandardAccount
{
    public const KEYS = ['transport','mode','host','port','username','app_password','sender_email',
        'encryption','auth_mode','ca_file','allow_private_network'];

    public static function is(array $v): bool { return ($v['transport'] ?? null) === 'smtp'; }

    public static function validate(array $v): void
    {
        SafeFailure::require(in_array($v['mode'] ?? null, ['test','production'], true), 'smtp_mode');
        $host = $v['host'] ?? null;
        SafeFailure::require(is_string($host) && strlen($host) <= 253 && (filter_var($host, FILTER_VALIDATE_IP) !== false
            || preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/iD', $host) === 1), 'smtp_hostname');
        SafeFailure::require(is_int($v['port'] ?? null) && $v['port'] >= 1 && $v['port'] <= 65535, 'smtp_port');
        SafeFailure::require(in_array($v['encryption'] ?? null, ['starttls','tls'], true), 'smtp_encryption');
        SafeFailure::require(is_string($v['sender_email'] ?? null) && filter_var($v['sender_email'], FILTER_VALIDATE_EMAIL) !== false
            && preg_match('/^[\x21-\x7e]{1,320}$/D', $v['sender_email']) === 1, 'smtp_sender');
        SafeFailure::require(in_array($v['auth_mode'] ?? null, ['password','none'], true), 'smtp_auth_mode');
        if ($v['auth_mode'] === 'password') {
            SafeFailure::require(is_string($v['username'] ?? null) && preg_match('/^[\x21-\x7e]{1,320}$/D', $v['username']) === 1
                && is_string($v['app_password'] ?? null) && strlen($v['app_password']) >= 1 && strlen($v['app_password']) <= 4096
                && strpbrk($v['app_password'], "\r\n\0") === false, 'smtp_credentials');
        } else {
            SafeFailure::require(($v['username'] ?? null) === '' && ($v['app_password'] ?? null) === '', 'smtp_relay_credentials');
        }
        SafeFailure::require(is_string($v['ca_file'] ?? null) && strlen($v['ca_file']) <= 4096
            && is_bool($v['allow_private_network'] ?? null), 'smtp_options');
    }

    public static function tls(array $v): array
    {
        self::validate($v);
        $ca = realpath($v['ca_file']);
        SafeFailure::require(is_string($ca) && $ca === $v['ca_file'] && is_file($ca) && is_readable($ca), 'server_ca_file');
        return ['ssl'=>['cafile'=>$ca,'verify_peer'=>true,'verify_peer_name'=>true,'allow_self_signed'=>false,
            'peer_name'=>$v['host'],'SNI_enabled'=>true,
            'crypto_method'=>STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT]];
    }

    public static function addressAllowed(string $ip, bool $private): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) { return false; }
        if (IpUtils::checkIp($ip, ['0.0.0.0/8','169.254.0.0/16','224.0.0.0/4','240.0.0.0/4','::','fe80::/10','ff00::/8'])) { return false; }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) { return true; }
        return $private && IpUtils::checkIp($ip, ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','127.0.0.0/8','::1','fc00::/7']);
    }

    public static function resolve(array $v): string
    {
        self::validate($v);$host=$v['host'];
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) { $addresses=[$host]; }
        else {
            $addresses=@gethostbynamel($host) ?: [];
            if (!$addresses) {
                foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                    if (isset($record['ipv6'])) { $addresses[]=$record['ipv6']; }
                }
            }
        }
        SafeFailure::require(count($addresses) > 0 && count($addresses) <= 16, 'smtp_dns');
        foreach ($addresses as $ip) { SafeFailure::require(self::addressAllowed($ip, $v['allow_private_network']), 'smtp_address_not_allowed'); }
        return str_contains($addresses[0], ':') ? '['.$addresses[0].']' : $addresses[0];
    }
}
