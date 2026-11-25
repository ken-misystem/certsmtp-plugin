<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Progress
{
    public string $phase = 'preflight';
    public function __construct(private readonly \Closure $persist)
    {
    }
    public function move(string $phase): void
    {
        // A positive final SMTP reply is terminal, including after cleanup errors.
        if ($this->phase === 'accepted') { return; }
        if ($phase === 'accepted') {
            // Latch the observed reply before persistence, so a DB failure cannot make it retryable.
            $this->phase = 'accepted';
            ($this->persist)($phase);
            return;
        }
        // Persist uncertainty BEFORE sending DATA or message bytes.
        ($this->persist)($phase);
        $this->phase = $phase;
    }
}
