<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

/** Never attach an original exception/debug transcript to an application exception. */
final class SafeFailure extends \RuntimeException
{
    public function __construct(public readonly string $reason, public readonly string $phase = 'preflight')
    {
        parent::__construct('CertSmtp: '.$reason);
    }

    public static function require(bool $condition, string $reason): void
    {
        if (!$condition) {
            throw new self($reason);
        }
    }
}
