<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Config
{
    private array $certificateLeases=[];
    public function __construct(private readonly string $path, private readonly string $projectDir, private readonly bool $debug = false)
    {
    }

    private function bootstrap(): array
    {
        // Refresh every operation: workers see credential/certificate replacement on next attempt.
        SafeFailure::require(extension_loaded('sodium') && extension_loaded('pdo_sqlite') && extension_loaded('openssl'), 'required_extensions');
        SafeFailure::require(!$this->debug && (bool)ini_get('zend.exception_ignore_args'),'debug_or_exception_arguments_enabled');
        try {
            $v = json_decode(PrivateFiles::read($this->path), true, 16, JSON_THROW_ON_ERROR);
        } catch (SafeFailure $e) {
            throw $e;
        } catch (\Throwable) {
            throw new SafeFailure('config_json');
        }
        SafeFailure::require(is_array($v), 'config_shape');
        $keys = StandardAccount::is($v) ? array_merge(StandardAccount::KEYS, ['state_dir','queue_key'])
            : ['mode','host','port','username','app_password','cert_file','key_file','key_passphrase','ca_file','state_dir','queue_key'];
        SafeFailure::require(is_array($v) && count($v) === count($keys) && !array_diff($keys, array_keys($v)), 'config_shape');
        self::validateAccount($v);
        SafeFailure::require(is_string($v['state_dir']), 'config_path_type');
        $this->outsideProject($this->path);
        $key = is_string($v['queue_key']) ? base64_decode($v['queue_key'], true) : false;
        SafeFailure::require(is_string($key) && strlen($key) === SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'queue_key_shape');
        $v['queue_key'] = $key;
        PrivateFiles::stateDirectory($v['state_dir'], $this->projectDir);
        return $v;
    }

    public static function validateAccount(array $v): void
    {
        if (StandardAccount::is($v)) { StandardAccount::validate($v); return; }
        SafeFailure::require(isset($v['mode'],$v['host'],$v['port']) && in_array($v['mode'], ['test','production'], true)
            && is_string($v['host']) && strlen($v['host'])<=253
            && preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/iD',$v['host'])===1
            && is_int($v['port']) && $v['port']>=1 && $v['port']<=65535, 'smtp_endpoint');
        SafeFailure::require(is_string($v['username']) && filter_var($v['username'], FILTER_VALIDATE_EMAIL) !== false
            && preg_match('/^[\x21-\x7e]{1,320}$/D', $v['username']) === 1, 'smtp_username');
        SafeFailure::require(is_string($v['app_password']) && preg_match('/^[\x21-\x7e]{16,256}$/D', $v['app_password']) === 1
            && is_string($v['key_passphrase']) && strlen($v['key_passphrase']) <= 256, 'secret_shape');
        foreach (['cert_file','key_file','ca_file'] as $k) {
            SafeFailure::require(is_string($v[$k]) && strlen($v[$k]) <= 4096, 'config_path_type');
        }
    }

    public static function sender(array $v): string
    {
        return StandardAccount::is($v) ? $v['sender_email'] : $v['username'];
    }

    public static function accountIdentity(array $v): string
    {
        return hash('sha256', json_encode([StandardAccount::is($v)?'smtp':'certsmtp',strtolower($v['host']),
            $v['port'],$v['username'],self::sender($v),$v['encryption']??'starttls'], JSON_THROW_ON_ERROR));
    }

    private function outsideProject(string $path): void
    {
        $project = realpath($this->projectDir);
        SafeFailure::require(is_string($project), 'project_directory');
        $real = realpath($path);
        SafeFailure::require(is_string($real) && $real !== $project
            && !str_starts_with($real.DIRECTORY_SEPARATOR,$project.DIRECTORY_SEPARATOR), 'secrets_must_be_outside_project');
    }

    public function get(?string $accountId = null): array
    {
        $base = $this->bootstrap();
        $registry = Accounts::read($base);
        if($accountId===null)SafeFailure::require($registry['metadata'][$registry['active']]['enabled']??true,'account_disabled');
        $accountId ??= $registry['active'];
        Accounts::id($accountId);
        SafeFailure::require(isset($registry['accounts'][$accountId]), 'account_not_registered');
        $v = self::resolveAccount($base, $registry['accounts'][$accountId]);
        if (!StandardAccount::is($v)&&!CertificateUpload::is($v)) { foreach (['cert_file','key_file'] as $k) { $this->outsideProject($v[$k]); } }
        $v['account_id'] = $accountId;
        return $v;
    }

    private static function resolveAccount(array $base, array $account): array
    {
        // Account settings are a complete transport-specific record, not an
        // overlay. Only the encrypted store's location/key belong to the base.
        // Inheriting SMTP-only keys can silently select the wrong transport or
        // sender; inheriting certificate keys can leak them into plain SMTP.
        return Accounts::fields($account) + [
            'state_dir' => $base['state_dir'],
            'queue_key' => $base['queue_key'],
        ];
    }

    public function forMessage(array $payload): array
    {
        if (isset($payload['account_id'])) {
            SafeFailure::require(is_string($payload['account_id']), 'queued_account_id');
            $v = $this->get($payload['account_id']);
        } else {
            // Old encrypted payloads keep their original sender after a switch.
            $base = $this->bootstrap(); $registry = Accounts::read($base); $matches = [];
            foreach ($registry['accounts'] as $candidate=>$account) {
                if (self::sender($account) === ($payload['sender'] ?? null)) { $matches[] = $candidate; }
            }
            SafeFailure::require(count($matches) > 0, 'queued_sender_not_registered');
            // Pre-account-ID messages originated from the old default account.
            // Prefer that exact historical binding, never the active account.
            if (in_array('default', $matches, true)) { $id = 'default'; }
            else {
                SafeFailure::require(count($matches) === 1, 'queued_sender_ambiguous');
                $id = $matches[0];
            }
            $v = $this->get($id);
        }
        SafeFailure::require(($payload['sender'] ?? null) === self::sender($v), 'queued_sender_identity_changed');
        return $v;
    }

    public function registeredSender(string $sender): bool
    {
        $registry = Accounts::read($this->bootstrap());
        foreach ($registry['accounts'] as $account) {
            if (self::sender($account) === $sender) { return true; }
        }
        return false;
    }

    public function register(string $id, string $privateFile): void
    {
        Accounts::id($id);
        SafeFailure::require($id !== 'default', 'default_account_reserved');
        $this->outsideProject($privateFile);
        try { $account = json_decode(PrivateFiles::read($privateFile), true, 16, JSON_THROW_ON_ERROR); }
        catch (SafeFailure $e) { throw $e; }
        catch (\Throwable) { throw new SafeFailure('account_file_json'); }
        $base = $this->bootstrap();
        SafeFailure::require(is_array($account) && count($account) === count(Accounts::fields($account))
            && !array_diff(array_keys(Accounts::fields($account)), array_keys($account)), 'account_file_shape');
        $account = Accounts::fields($account);
        self::validateAccount($account);
        if (!StandardAccount::is($account)) { foreach (['cert_file','key_file'] as $k) { $this->outsideProject($account[$k]); } }
        $this->tls($account); // Local pair/validity/CA checks only; never connect to SMTP.
        Accounts::change($base, static function (array $registry) use ($id, $account): array {
            SafeFailure::require(!isset($registry['accounts'][$id]), 'account_id_duplicate');
            SafeFailure::require(count($registry['accounts']) < 20, 'account_limit');
            foreach ($registry['accounts'] as $registered) {
                SafeFailure::require(self::accountIdentity($registered) !== self::accountIdentity($account), 'account_username_duplicate');
            }
            $registry['accounts'][$id] = $account;
            return $registry;
        });
    }

    public function select(string $id): void
    {
        Accounts::id($id);
        $base = $this->bootstrap();
        Accounts::change($base, function (array $registry) use ($id, $base): array {
            SafeFailure::require(isset($registry['accounts'][$id]), 'account_not_registered');
            SafeFailure::require(!isset($registry['superseded'][$id]),'account_not_editable');
            SafeFailure::require($registry['metadata'][$id]['enabled']??true,'account_disabled');
            // Selection is not a delivery; require usable local TLS material first.
            $this->tls(self::resolveAccount($base, $registry['accounts'][$id])+['account_id'=>$id]);
            $registry['active'] = $id;
            return $registry;
        });
    }

    public function accountStatus(): array
    {
        $registry = Accounts::read($this->bootstrap()); $out = [];
        foreach ($registry['accounts'] as $id=>$account) {
            $out[] = ['id'=>$id,'active'=>$id === $registry['active'],'mode'=>$account['mode'],
                'username'=>$account['username'],'sender_email'=>self::sender($account),'host'=>$account['host'],'port'=>$account['port'],
                'transport'=>StandardAccount::is($account)?'smtp':'certsmtp',
                'encryption'=>$account['encryption']??'starttls','auth_mode'=>$account['auth_mode']??'password'];
        }
        return $out;
    }

    public function tls(array $v): array
    {
        if (StandardAccount::is($v)) { return StandardAccount::tls($v); }
        if(CertificateUpload::is($v))$v=$this->uploadedPaths($v);
        $certRaw = PrivateFiles::read($v['cert_file'], 1048576);
        $keyRaw = PrivateFiles::read($v['key_file'], 1048576);
        $cert = @openssl_x509_read($certRaw);
        $key = @openssl_pkey_get_private($keyRaw, $v['key_passphrase']);
        SafeFailure::require($cert !== false && $key !== false && openssl_x509_check_private_key($cert, $key), 'certificate_key_pair');
        $info = @openssl_x509_parse($cert);
        SafeFailure::require(is_array($info) && $info['validFrom_time_t'] <= time() && $info['validTo_time_t'] > time(), 'certificate_expired_or_not_yet_valid');
        $ca = realpath($v['ca_file']);
        SafeFailure::require(is_string($ca) && $ca === $v['ca_file'] && is_file($ca) && is_readable($ca), 'server_ca_file');
        return ['ssl' => ['local_cert' => $v['cert_file'], 'local_pk' => $v['key_file'], 'passphrase' => $v['key_passphrase'],
            'cafile' => $ca, 'verify_peer' => true, 'verify_peer_name' => true, 'allow_self_signed' => false,
            'peer_name' => $v['host'], 'SNI_enabled' => true,
            'crypto_method' => STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT]];
    }

    public function publicStatus(): array
    {
        try {
            $v = $this->get();
            $tls=$this->tls($v);
            if (StandardAccount::is($v)) {
                return ['configured'=>true,'account_id'=>$v['account_id'],'mode'=>$v['mode'],'username'=>$v['username'],
                    'sender_email'=>self::sender($v),'transport'=>'smtp','encryption'=>$v['encryption'],'auth_mode'=>$v['auth_mode'],
                    'host'=>$v['host'],'port'=>$v['port'],'expires_at'=>null,'reason'=>null];
            }
            $info = openssl_x509_parse(openssl_x509_read(PrivateFiles::read($tls['ssl']['local_cert'], 1048576)));
            return ['configured' => true, 'account_id'=>$v['account_id'], 'mode' => $v['mode'], 'username' => $v['username'],
                'sender_email'=>self::sender($v),'transport'=>'certsmtp','encryption'=>'starttls','auth_mode'=>'password',
                'host' => $v['host'], 'port' => $v['port'], 'expires_at' => gmdate('Y-m-d H:i:s', $info['validTo_time_t']), 'reason' => null];
        } catch (\Throwable $e) {
            return ['configured' => false, 'reason' => $e instanceof SafeFailure ? $e->reason : 'config_unavailable'];
        }
    }

    public function registerForm(array $input,array $files): string
    {
        $base=$this->bootstrap();[$account,$upload,$label,$status]=$this->formAccount($input,$files);
        $id='smtp-'.bin2hex(random_bytes(8));
        Accounts::change($base,static function(array $registry)use($id,$account,$upload,$label,$status):array{
            SafeFailure::require(count($registry['accounts'])<20,'account_limit');
            foreach($registry['accounts'] as $other=>$a)if(!isset($registry['superseded'][$other]))SafeFailure::require(self::accountIdentity($a)!==self::accountIdentity($account),'account_username_duplicate');
            $registry['accounts'][$id]=$account;$registry['metadata'][$id]=['label'=>$label,'enabled'=>$status==='enabled'];
            if($upload!==null)$registry['uploads'][$id]=$upload['material'];
            return $registry;
        });
        return $id;
    }

    private function formAccount(array $input,array $files,?array $old=null): array
    {
        $str=static function(string $name,string $default='')use($input):string{SafeFailure::require(!isset($input[$name])||is_string($input[$name]),'account_input');return $input[$name]??$default;};
        $sender=trim($str('sender_email'));$username=trim($str('username'));$host=trim($str('host'));$port=$str('port','587');
        SafeFailure::require(preg_match('/^[0-9]{1,5}$/D',$port)===1,'smtp_port');
        $kind=$str('transport','smtp');SafeFailure::require(in_array($kind,['smtp','certsmtp'],true),'account_input');
        $status=$str('status','enabled');SafeFailure::require(in_array($status,['enabled','disabled'],true),'account_input');
        $label=trim($str('label'));if($label==='')$label=$sender;
        SafeFailure::require(mb_strlen($label)<=64&&preg_match('//u',$label)===1&&!preg_match('/[\x00-\x1f\x7f]/',$label),'account_label');
        $password=$str('password');$sameTransport=$old!==null&&(($kind==='smtp')===StandardAccount::is($old));
        if($password===''&&$sameTransport)$password=$old['app_password'];
        $ca=$sameTransport?$old['ca_file']:'/etc/ssl/certs/ca-certificates.crt';$upload=null;
        if($kind==='smtp'){
            foreach($files as $raw)SafeFailure::require($raw==='','upload_standard');
            SafeFailure::require($str('certificate_password')==='','upload_standard');
            $auth=$str('auth_mode','password');
            $account=['transport'=>'smtp','mode'=>$sameTransport?$old['mode']:'production','host'=>$host,'port'=>(int)$port,'username'=>$auth==='none'?'':$username,
                'app_password'=>$auth==='none'?'':$password,'sender_email'=>$sender,'encryption'=>$str('encryption','starttls'),
                'auth_mode'=>$auth,'ca_file'=>$ca,'allow_private_network'=>$str('allow_private_network')==='1'];
            self::validateAccount($account);$this->tls($account);
        }else{
            SafeFailure::require($sender===$username&&$str('encryption','starttls')==='starttls','upload_sender');
            $hasFile=false;foreach($files as $raw){SafeFailure::require(is_string($raw),'upload_size');$hasFile=$hasFile||$raw!=='';}
            if($hasFile){
                $upload=CertificateUpload::prepare($files,$str('certificate_password'),$username);
                $account=['mode'=>$sameTransport?$old['mode']:'production','host'=>$host,'port'=>(int)$port,'username'=>$username,'app_password'=>$password,
                    'cert_file'=>'@uploaded','key_file'=>'@uploaded','key_passphrase'=>$upload['passphrase'],'ca_file'=>$ca];
            }else{
                SafeFailure::require($sameTransport,'upload_pair_required');
                SafeFailure::require($str('certificate_password')==='','upload_password_without_file');
                SafeFailure::require($username===$old['username'],'upload_identity');
                $account=array_replace($old,['host'=>$host,'port'=>(int)$port,'username'=>$username,'app_password'=>$password]);
            }
            self::validateAccount($account);
        }
        return [$account,$upload,$label,$status];
    }

    private function editRevision(array $registry,string $id,array $base): string
    {
        return hash_hmac('sha256',json_encode([$id,$registry['accounts'][$id],$registry['metadata'][$id]??null,$registry['uploads'][$id]??null,$registry['active']],JSON_THROW_ON_ERROR),$base['queue_key']);
    }

    public function editData(string $id): array
    {
        Accounts::id($id);$base=$this->bootstrap();$registry=Accounts::read($base);
        SafeFailure::require(isset($registry['accounts'][$id])&&!isset($registry['superseded'][$id]),'account_not_editable');
        $a=$registry['accounts'][$id];$meta=$registry['metadata'][$id]??[];
        return ['id'=>$id,'label'=>$meta['label']??$id,'enabled'=>$meta['enabled']??true,'active'=>$registry['active']===$id,
            'sender_email'=>self::sender($a),'host'=>$a['host'],'port'=>$a['port'],'username'=>$a['username'],
            'transport'=>StandardAccount::is($a)?'smtp':'certsmtp','encryption'=>$a['encryption']??'starttls','auth_mode'=>$a['auth_mode']??'password',
            'allow_private_network'=>$a['allow_private_network']??false,'revision'=>$this->editRevision($registry,$id,$base)];
    }

    public function updateForm(string $id,array $input,array $files): string
    {
        Accounts::id($id);$base=$this->bootstrap();
        $lock=(new Store($this))->lock();SafeFailure::require($lock!==null,'account_delivery_busy');
        $saved=$id;
        try{
            Accounts::change($base,function(array $registry)use($id,$input,$files,$base,&$saved):array{
                SafeFailure::require(isset($registry['accounts'][$id])&&!isset($registry['superseded'][$id]),'account_not_editable');
                $revision=$input['revision']??null;SafeFailure::require(is_string($revision)&&hash_equals($this->editRevision($registry,$id,$base),$revision),'account_edit_conflict');
                [$account,$upload,$label,$status]=$this->formAccount($input,$files,$registry['accounts'][$id]);
                SafeFailure::require($registry['active']!==$id||$status==='enabled','account_active_disable');
                $differentIdentity=self::accountIdentity($account)!==self::accountIdentity($registry['accounts'][$id]);
                foreach($registry['accounts'] as $other=>$a)if($other!==$id&&!isset($registry['superseded'][$other]))SafeFailure::require(self::accountIdentity($a)!==self::accountIdentity($account),'account_username_duplicate');
                if($differentIdentity){
                    // Immutable historical IDs keep every previously queued payload bound to its original endpoint/sender.
                    SafeFailure::require(count($registry['accounts'])<20,'account_limit');$saved='smtp-'.bin2hex(random_bytes(8));
                    $registry['superseded'][$id]=$saved;
                    if(isset($registry['uploads'][$id]))$registry['uploads'][$saved]=$registry['uploads'][$id];
                    if($registry['active']===$id)$registry['active']=$saved;
                }elseif($id==='default'&&!in_array('default',$registry['overrides'],true))$registry['overrides'][]='default';
                $registry['accounts'][$saved]=$account;$registry['metadata'][$saved]=['label'=>$label,'enabled'=>$status==='enabled'];
                if($upload!==null)$registry['uploads'][$saved]=$upload['material'];
                elseif(StandardAccount::is($account))unset($registry['uploads'][$saved]);
                return $registry;
            });
        }finally{flock($lock,LOCK_UN);fclose($lock);}
        return $saved;
    }

    public function setEnabled(string $id,bool $enabled): void
    {
        Accounts::id($id);$base=$this->bootstrap();
        Accounts::change($base,static function(array $registry)use($id,$enabled):array{
            SafeFailure::require(isset($registry['accounts'][$id]),'account_not_registered');
            SafeFailure::require(!isset($registry['superseded'][$id]),'account_not_editable');
            SafeFailure::require($enabled||$registry['active']!==$id,'account_active_disable');
            $registry['metadata'][$id]=['label'=>$registry['metadata'][$id]['label']??$id,'enabled'=>$enabled];return $registry;
        });
    }

    public function accountStatusForUi(): array
    {
        $registry=Accounts::read($this->bootstrap());$out=$this->accountStatus();
        foreach($out as &$row){$m=$registry['metadata'][$row['id']]??[];$row['label']=$m['label']??$row['id'];$row['enabled']=$m['enabled']??true;$row['retired']=isset($registry['superseded'][$row['id']]);}
        return $out;
    }

    private function uploadedPaths(array $v): array
    {
        $base=$this->bootstrap();$id=$v['account_id']??'';Accounts::id($id);$registry=Accounts::read($base);
        SafeFailure::require(isset($registry['uploads'][$id])&&CertificateUpload::is($v),'upload_material');
        $material=$registry['uploads'][$id];$cache=hash('sha256',serialize([$id,$material]));
        if(!isset($this->certificateLeases[$cache]))$this->certificateLeases[$cache]=new CertificateLease($material,$this->projectDir);
        $lease=$this->certificateLeases[$cache];$v['cert_file']=$lease->certificate;$v['key_file']=$lease->key;
        return $v;
    }

    public function gatewayIPv4(string $host): string
    {
        // Certificate SMTP is public-network only. Preserve IP pinning and TLS hostname verification.
        self::validateAccount(['mode'=>'production','host'=>$host,'port'=>587,'username'=>'sender@example.test',
            'app_password'=>str_repeat('x',16),'key_passphrase'=>'','cert_file'=>'','key_file'=>'','ca_file'=>'']);
        $addresses = gethostbynamel($host);
        SafeFailure::require(is_array($addresses) && count($addresses) > 0 && count($addresses) <= 16,'gateway_dns');
        foreach ($addresses as $ip) {
            SafeFailure::require(filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false, 'gateway_must_not_be_local');
        }
        return $addresses[0];
    }

    public function __debugInfo(): array
    {
        return ['secrets' => '[redacted]'];
    }
}
