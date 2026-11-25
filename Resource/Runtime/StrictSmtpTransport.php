<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Exception\TransportException;

/** Symfony 6.4 public command hook; never use isTLS() as STARTTLS-completion proof. */
final class StrictSmtpTransport extends EsmtpTransport
{
    private bool $verifiedTls = false;
    private bool $authenticated = false;

    public function __construct(string $host, int $port, private readonly Progress $progress)
    {
        parent::__construct($host,$port,false);
        $this->setAuthenticators([new \Symfony\Component\Mailer\Transport\Smtp\Auth\PlainAuthenticator()]);
        // A fresh transport handles one queued message. Zero restarts after every send in Mailer 6.4.46.
        $this->setRestartThreshold(PHP_INT_MAX);
    }

    public function executeCommand(string $command, array $codes): string
    {
        if ($this->progress->phase === 'accepted' && (str_starts_with($command,'AUTH ')
            || str_starts_with($command,'MAIL FROM:') || str_starts_with($command,'RCPT TO:')
            || $command === "DATA\r\n" || $command === "\r\n.\r\n")) {
            throw new SafeFailure('smtp_transaction_already_accepted','accepted');
        }
        if (str_starts_with($command,'HELO ') && $codes === [250] && !$this->verifiedTls) {
            $this->progress->move('tls');
            $response = parent::executeCommand('EHLO '.$this->getLocalDomain()."\r\n",[250]);
            if (preg_match('/^250[ -]STARTTLS(?:\s|$)/mi',$response) !== 1) {
                throw new SafeFailure('starttls_not_advertised','tls');
            }
            parent::executeCommand("STARTTLS\r\n",[220]);
            if (!$this->getStream()->startTLS()) {
                throw new SafeFailure('starttls_failed','tls');
            }
            $this->verifiedTls = true;
        }
        if (str_starts_with($command,'AUTH ')) {
            SafeFailure::require($this->verifiedTls,'authentication_without_tls');
            $this->progress->move('authentication');
        }
        if (str_starts_with($command,'MAIL FROM:') || str_starts_with($command,'RCPT TO:') || $command === "DATA\r\n") {
            SafeFailure::require($this->verifiedTls && $this->authenticated,'smtp_authentication_required');
            $this->progress->move($command === "DATA\r\n" ? 'data' : 'envelope');
        }
        $response = parent::executeCommand($command,$codes);
        if ($this->progress->phase === 'authentication' && in_array(235,$codes,true)) {
            $this->authenticated = true;
        }
        if ($command === "\r\n.\r\n" && $codes === [250]) {
            $this->progress->move('accepted');
        }
        return $response;
    }
}
