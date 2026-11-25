<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Diagnostics
{
    public static function error(\Throwable $e, string $phase): array
    {
        $frames = [];
        foreach ($e->getTrace() as $frame) {
            if (isset($frame['class']) && str_starts_with($frame['class'],__NAMESPACE__.'\\')) {
                $frames[] = ['component'=>substr($frame['class'],strlen(__NAMESPACE__)+1),'function'=>$frame['function'],
                    'source'=>isset($frame['file']) ? basename($frame['file']) : null,'line'=>$frame['line'] ?? null];
                if (count($frames) === 5) { break; }
            }
        }
        $sqlstate = $e instanceof \PDOException && isset($e->errorInfo[0]) && preg_match('/^[0-9A-Z]{5}$/D',$e->errorInfo[0]) ? $e->errorInfo[0] : null;
        return ['class'=>$e instanceof SafeFailure ? 'SafeFailure' : ($e instanceof \PDOException ? 'PDOException' : 'Exception'),
            'reason'=>$e instanceof SafeFailure ? $e->reason : 'internal_operation_failed','phase'=>$phase,'frames'=>$frames,
            'sqlstate'=>$sqlstate,'native_code'=>$e instanceof \PDOException && isset($e->errorInfo[1]) && is_int($e->errorInfo[1]) ? $e->errorInfo[1] : null,'raw_error_saved'=>false];
    }
}
