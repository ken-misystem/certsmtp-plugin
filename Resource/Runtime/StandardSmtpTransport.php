<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Transport\Smtp\Auth\{LoginAuthenticator,PlainAuthenticator};

/** Explicit TLS policy, SMTP AUTH LOGIN/PLAIN, and the same final-250 latch. */
final class StandardSmtpTransport extends EsmtpTransport
{
    private bool $verifiedTls = false;
    private bool $authenticated = false;
    private bool $starting = false;

    public function __construct(string $host, int $port, private readonly Progress $progress,
        private readonly string $encryption, private readonly bool $authRequired = true)
    {
        SafeFailure::require(in_array($encryption, ['starttls','tls'], true), 'smtp_encryption');
        parent::__construct($host, $port, $encryption === 'tls');
        $this->setAuthenticators([new LoginAuthenticator(), new PlainAuthenticator()]);
        $this->setRestartThreshold(PHP_INT_MAX);
    }

    public function start(): void
    {
        $this->starting = true;
        if ($this->encryption === 'tls') { $this->progress->move('tls'); }
        try { parent::start(); } finally { $this->starting = false; }
    }

    public function executeCommand(string $command, array $codes): string
    {
        if ($this->progress->phase === 'accepted' && (str_starts_with($command,'AUTH ')
            || str_starts_with($command,'MAIL FROM:') || str_starts_with($command,'RCPT TO:')
            || $command === "DATA\r\n" || $command === "\r\n.\r\n")) {
            throw new SafeFailure('smtp_transaction_already_accepted', 'accepted');
        }
        if (str_starts_with($command,'HELO ') && $codes === [250] && !$this->verifiedTls) {
            SafeFailure::require($this->starting, 'smtp_greeting_before_initialization');
            if ($this->encryption === 'tls') {
                // Parent start() reached HELO only after ssl:// initialize and
                // the encrypted 220 greeting succeeded. isTLS alone is not proof.
                SafeFailure::require($this->getStream()->isTLS(), 'implicit_tls_required');
                $this->verifiedTls = true;
            } else {
                $this->progress->move('tls');
                $response = parent::executeCommand('EHLO '.$this->getLocalDomain()."\r\n", [250]);
                SafeFailure::require(preg_match('/^250[ -]STARTTLS(?:\s|$)/mi', $response) === 1, 'starttls_not_advertised');
                parent::executeCommand("STARTTLS\r\n", [220]);
                SafeFailure::require($this->getStream()->startTLS(), 'starttls_failed');
                $this->verifiedTls = true;
            }
        }
        if ($command === "STARTTLS\r\n" && $this->verifiedTls) { throw new SafeFailure('unexpected_tls_restart','tls'); }
        if (str_starts_with($command, 'AUTH ')) {
            SafeFailure::require($this->verifiedTls && $this->authRequired, 'authentication_without_tls');
            $this->progress->move('authentication');
        }
        if (str_starts_with($command,'MAIL FROM:') || str_starts_with($command,'RCPT TO:') || $command === "DATA\r\n") {
            SafeFailure::require($this->verifiedTls && (!$this->authRequired || $this->authenticated), 'smtp_authentication_required');
            $this->progress->move($command === "DATA\r\n" ? 'data' : 'envelope');
        }
        $response = parent::executeCommand($command, $codes);
        if ($this->progress->phase === 'authentication' && in_array(235, $codes, true)) { $this->authenticated = true; }
        if ($command === "\r\n.\r\n" && $codes === [250]) { $this->progress->move('accepted'); }
        return $response;
    }
}
