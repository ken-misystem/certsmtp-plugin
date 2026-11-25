<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

/** Shared Web/worker account selection. Credentials remain encrypted outside the project. */
final class Accounts
{
    public static function id(string $id): void
    {
        SafeFailure::require(preg_match('/^[a-z][a-z0-9_-]{0,31}$/D', $id) === 1, 'account_id');
    }

    public static function read(array $base): array
    {
        $path = $base['state_dir'].'/accounts.enc';
        if (!file_exists($path) && !is_link($path)) {
            return ['version'=>3,'active'=>'default','accounts'=>['default'=>self::fields($base)],'metadata'=>[],'uploads'=>[],'overrides'=>[],'superseded'=>[]];
        }
        $sealed = PrivateFiles::read($path, 1048576);
        SafeFailure::require(strlen($sealed) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES, 'accounts_shape');
        $raw = sodium_crypto_secretbox_open(substr($sealed, 24), substr($sealed, 0, 24), $base['queue_key']);
        SafeFailure::require(is_string($raw), 'accounts_authentication');
        try { $v = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); }
        catch (\Throwable) { throw new SafeFailure('accounts_json'); }
        SafeFailure::require(is_array($v)&&in_array($v['version']??null,[1,2,3],true),'accounts_shape');
        $keys=match($v['version']){1=>['version','active','accounts'],2=>['version','active','accounts','metadata','uploads'],3=>['version','active','accounts','metadata','uploads','overrides','superseded']};
        SafeFailure::require(array_keys($v)===$keys&&is_string($v['active'])&&is_array($v['accounts'])
            &&count($v['accounts'])>=1&&count($v['accounts'])<=20&&isset($v['accounts'][$v['active']]),'accounts_shape');
        if($v['version']===1){$v['version']=2;$v['metadata']=[];$v['uploads']=[];}
        if($v['version']===2){$v['version']=3;$v['overrides']=[];$v['superseded']=[];}
        SafeFailure::require(in_array($v['overrides'],[[],['default']],true)&&is_array($v['superseded'])&&count($v['superseded'])<=19,'accounts_shape');
        foreach($v['superseded'] as $old=>$next){
            SafeFailure::require(is_string($old)&&is_string($next)&&$old!==$next&&isset($v['accounts'][$old],$v['accounts'][$next])&&$v['active']!==$old,'account_revision');
            $seen=[$old];while(isset($v['superseded'][$next])){SafeFailure::require(!in_array($next,$seen,true),'account_revision');$seen[]=$next;$next=$v['superseded'][$next];}
            SafeFailure::require(!in_array($next,$seen,true),'account_revision');
        }
        SafeFailure::require(is_array($v['metadata'])&&is_array($v['uploads'])&&count($v['metadata'])<=20&&count($v['uploads'])<=20,'accounts_shape');
        foreach($v['metadata'] as $id=>$meta){
            SafeFailure::require(isset($v['accounts'][$id])&&is_array($meta)&&array_keys($meta)===['label','enabled']
                &&is_string($meta['label'])&&mb_strlen($meta['label'])<=64&&preg_match('//u',$meta['label'])===1&&is_bool($meta['enabled']),'account_metadata');
        }
        foreach($v['uploads'] as $id=>$material){
            SafeFailure::require(isset($v['accounts'][$id])&&is_array($material)&&array_keys($material)===['certificate','private_key']
                &&!StandardAccount::is($v['accounts'][$id])&&$v['accounts'][$id]['cert_file']==='@uploaded'
                &&$v['accounts'][$id]['key_file']===$v['accounts'][$id]['cert_file'],'upload_material');
            foreach($material as $raw)SafeFailure::require(is_string($raw)&&strlen($raw)>0&&strlen($raw)<=CertificateUpload::BOUND,'upload_material');
        }
        self::id($v['active']);
        // Keep the original mounted account live for password/certificate
        // rotation, as in the single-account release. Never use a stale copy.
        SafeFailure::require(isset($v['accounts']['default']), 'default_account_missing');
        if(!in_array('default',$v['overrides'],true))$v['accounts']['default'] = self::fields($base);
        $usernames = [];
        foreach ($v['accounts'] as $id=>$account) {
            SafeFailure::require(is_string($id) && is_array($account), 'account_shape');
            self::id($id);
            SafeFailure::require(array_keys($account) === array_keys(self::fields($account)), 'account_shape');
            Config::validateAccount($account);
            SafeFailure::require(!CertificateUpload::is($account)||isset($v['uploads'][$id]),'upload_material');
            if(!isset($v['superseded'][$id])){
                SafeFailure::require(!in_array(Config::accountIdentity($account), $usernames, true), 'account_username_duplicate');
                $usernames[] = Config::accountIdentity($account);
            }
        }
        return $v;
    }

    public static function fields(array $v): array
    {
        $out = [];
        $keys = StandardAccount::is($v) ? StandardAccount::KEYS
            : ['mode','host','port','username','app_password','cert_file','key_file','key_passphrase','ca_file'];
        foreach ($keys as $k) {
            $out[$k] = $v[$k] ?? null;
        }
        return $out;
    }

    public static function change(array $base, \Closure $change): void
    {
        $path = $base['state_dir'].'/accounts.lock';
        SafeFailure::require(!is_link($path), 'accounts_lock_symlink');
        $old = umask(0077);
        try { $lock = @fopen($path, 'c+b'); } finally { umask($old); }
        SafeFailure::require(is_resource($lock), 'accounts_lock');
        $temp = null;
        try {
            $s = fstat($lock);
            SafeFailure::require(($s['mode'] & 0777) === 0600 && $s['uid'] === posix_geteuid()
                && $s['nlink'] === 1 && ($s['mode'] & 0170000) === 0100000, 'accounts_lock_permissions');
            SafeFailure::require(flock($lock, LOCK_EX), 'accounts_lock');
            $v = $change(self::read($base));
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $sealed = $nonce.sodium_crypto_secretbox(json_encode($v, JSON_THROW_ON_ERROR), $nonce, $base['queue_key']);
            SafeFailure::require(strlen($sealed)<=1048576,'account_storage_limit');
            $temp = $base['state_dir'].'/accounts-'.bin2hex(random_bytes(12)).'.tmp';
            $old = umask(0077);
            try { $fd = @fopen($temp, 'x+b'); } finally { umask($old); }
            SafeFailure::require(is_resource($fd), 'accounts_write');
            try {
                SafeFailure::require(fwrite($fd, $sealed) === strlen($sealed) && fflush($fd) && fsync($fd), 'accounts_write');
            } finally { fclose($fd); }
            SafeFailure::require(rename($temp, $base['state_dir'].'/accounts.enc'), 'accounts_replace');
            $temp = null;
        } finally {
            if ($temp !== null && is_file($temp)) { unlink($temp); }
            flock($lock, LOCK_UN); fclose($lock);
        }
    }
}
