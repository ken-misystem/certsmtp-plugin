<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

/** Uploaded material is embedded only inside the authenticated encrypted registry. */
final class CertificateUpload
{
    public const BOUND = 262144;

    public static function prepare(array $files, string $password, string $username): array
    {
        $p12=$files['p12']??'';$certificate=$files['certificate']??'';$private=$files['private_key']??'';
        foreach([$p12,$certificate,$private] as $raw)SafeFailure::require(is_string($raw)&&strlen($raw)<=self::BOUND,'upload_size');
        SafeFailure::require(strlen($password)<=256,'certificate_password');
        if($p12!==''){
            SafeFailure::require($certificate===''&&$private==='','upload_choose_one');
            $parts=[];SafeFailure::require(@openssl_pkcs12_read($p12,$parts,$password),'upload_p12');
            $certificate=$parts['cert']??'';$private=$parts['pkey']??'';
            foreach($parts['extracerts']??[] as $extra){SafeFailure::require(@openssl_x509_read($extra)!==false,'upload_certificate');$certificate.="\n".$extra;}
            $password='';
        }
        SafeFailure::require($certificate!==''&&$private!=='','upload_pair_required');
        if(!str_contains($certificate,'-----BEGIN CERTIFICATE-----'))$certificate="-----BEGIN CERTIFICATE-----\n".chunk_split(base64_encode($certificate),64,"\n")."-----END CERTIFICATE-----\n";
        preg_match_all('~-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----~s',$certificate,$blocks);
        SafeFailure::require(count($blocks[0])>=1&&count($blocks[0])<=8&&trim(preg_replace('~-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----~s','',$certificate))==='','upload_certificate');
        $clean='';foreach($blocks[0] as $block){$x=@openssl_x509_read($block);SafeFailure::require($x!==false&&openssl_x509_export($x,$pem),'upload_certificate');$clean.=$pem;}$certificate=$clean;
        $cert=@openssl_x509_read($certificate);$key=@openssl_pkey_get_private($private,$password);
        SafeFailure::require($cert!==false&&$key!==false&&openssl_x509_check_private_key($cert,$key),'upload_pair');
        $info=@openssl_x509_parse($cert);SafeFailure::require(is_array($info)&&$info['validFrom_time_t']<=time()&&$info['validTo_time_t']>time(),'upload_expired');
        $names=[];foreach(['CN','emailAddress'] as $field){$value=$info['subject'][$field]??[];foreach((array)$value as $name)$names[]=strtolower($name);}
        foreach(explode(',',(string)($info['extensions']['subjectAltName']??'')) as $name){if(preg_match('/^email:(.+)$/i',trim($name),$m))$names[]=strtolower($m[1]);}
        SafeFailure::require(in_array(strtolower($username),$names,true),'upload_identity');
        $usage=(string)($info['extensions']['extendedKeyUsage']??'');
        SafeFailure::require($usage===''||str_contains($usage,'TLS Web Client Authentication')||str_contains($usage,'1.3.6.1.5.5.7.3.2'),'upload_client_usage');
        $details=openssl_pkey_get_details($key);SafeFailure::require(is_array($details)&&(($details['type']===OPENSSL_KEYTYPE_RSA&&$details['bits']>=2048)||($details['type']===OPENSSL_KEYTYPE_EC&&$details['bits']>=256)),'upload_key_strength');
        // The temporary TLS key remains password-encrypted even if a process is killed.
        $passphrase=bin2hex(random_bytes(32));SafeFailure::require(openssl_pkey_export($key,$encrypted,$passphrase),'upload_key_export');
        SafeFailure::require(strlen($certificate)<=self::BOUND&&strlen($encrypted)<=self::BOUND,'upload_size');
        return ['material'=>['certificate'=>$certificate,'private_key'=>$encrypted],'passphrase'=>$passphrase];
    }

    public static function is(array $v): bool
    {
        return ($v['cert_file']??null)==='@uploaded'
            &&($v['key_file']??null)===$v['cert_file'];
    }
}
