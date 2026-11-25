<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Outcome
{
    public const DELAYS = [60,300,900,3600];

    public static function accepted(): array
    {
        return ['state'=>'accepted','reason'=>'smtp_accepted_not_receipt','smtp_code'=>250,'safe_retry'=>false];
    }

    public static function failure(\Throwable $error, string $phase, int $attempts): array
    {
        $code = $error->getCode();
        $smtp = is_int($code) && $code >= 400 && $code <= 599 ? $code : null;
        $reason = $error instanceof SafeFailure ? $error->reason : 'transport_failed';
        $state = 'failed';
        $safe = $phase !== 'data';
        if ($phase === 'accepted') {
            return self::accepted();
        }
        if ($phase === 'data' && $smtp === null) {
            $state = 'uncertain';
            $reason = 'smtp_acceptance_unknown';
        } elseif ($smtp !== null) {
            $safe = true; // Explicit negative response, so this transaction was not accepted.
            $reason = $phase === 'authentication' ? 'smtp_authentication_rejected' : 'smtp_rejected';
            if ($smtp < 500 && $attempts < 5) { $state = 'retry'; }
        } elseif (!($error instanceof SafeFailure) && in_array($phase,['connecting','tls','authentication','envelope'],true)) {
            $safe = true;
            // Classify a bounded message in memory only; never save/export its text.
            $tlsRejected = $phase === 'tls' && preg_match('/certificate verify failed|peer certificate|certificate.*(?:expired|mismatch|not match)|self.signed certificate/i',substr($error->getMessage(),0,8192)) === 1;
            $reason = $tlsRejected ? 'tls_verification_failed' : 'smtp_connection_failed';
            if (!$tlsRejected && $attempts < 5) { $state = 'retry'; }
        }
        if ($state === 'failed' && $safe && $attempts >= 5) { $reason = 'retry_limit_reached'; }
        $frame = null;
        foreach ($error->getTrace() as $trace) {
            if (isset($trace['class']) && str_starts_with($trace['class'],__NAMESPACE__.'\\')) { $frame = $trace; break; }
        }
        return ['state'=>$state,'reason'=>$reason,'smtp_code'=>$smtp,'safe_retry'=>$safe,
            'failure_class'=>$error instanceof SafeFailure ? 'SafeFailure' : ($smtp !== null ? 'SmtpNegativeReply' : 'TransportFailure'),
            'failure_component'=>$frame ? substr($frame['class'],strlen(__NAMESPACE__)+1).'::'.$frame['function'] : 'Worker',
            'failure_line'=>$frame['line'] ?? null];
    }

    public static function due(int $attempts, int $now): int
    {
        return $now + self::DELAYS[min(3,max(0,$attempts-1))];
    }
}
