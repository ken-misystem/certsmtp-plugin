<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

/** Minimal private files required by OpenSSL; never persisted in a named volume. */
final class CertificateLease
{
    private string $directory;
    public readonly string $certificate;
    public readonly string $key;
    public function __construct(array $material,string $project)
    {
        SafeFailure::require(array_keys($material)===['certificate','private_key'],'upload_material');
        foreach($material as $raw)SafeFailure::require(is_string($raw)&&strlen($raw)>0&&strlen($raw)<=CertificateUpload::BOUND,'upload_material');
        $tmp=realpath(sys_get_temp_dir());$project=realpath($project);SafeFailure::require(is_string($tmp)&&is_dir($tmp)&&is_string($project)&&$tmp!==$project&&!str_starts_with($tmp.'/', $project.'/'),'upload_temporary_directory');
        $this->directory=$tmp.'/certsmtp-'.bin2hex(random_bytes(16));
        SafeFailure::require(mkdir($this->directory,0700),'upload_temporary_directory');
        $this->certificate=$this->directory.'/client.pem';$this->key=$this->directory.'/client.key';
        try{
            foreach([$this->certificate=>$material['certificate'],$this->key=>$material['private_key']] as $path=>$raw){
                $old=umask(0077);try{$fd=@fopen($path,'xb');}finally{umask($old);}
                SafeFailure::require(is_resource($fd),'upload_temporary_file');
                try{SafeFailure::require(fwrite($fd,$raw)===strlen($raw)&&fflush($fd),'upload_temporary_file');}finally{fclose($fd);}
            }
        }catch(\Throwable $e){$this->cleanup();throw $e;}
    }
    public function cleanup(): void
    {
        foreach([$this->certificate,$this->key] as $file)if(is_file($file))@unlink($file);
        if(isset($this->directory)&&is_dir($this->directory))@rmdir($this->directory);
    }
    public function __destruct(){$this->cleanup();}
    public function __debugInfo(): array{return ['material'=>'[redacted]'];}
}
