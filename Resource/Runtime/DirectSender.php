<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\RawMessage;

final class DirectSender
{
    public function __construct(private readonly Config $config)
    {
    }

    public function deliver(array $payload, Progress $progress): void
    {
        $v = $this->config->forMessage($payload);
        $options = $this->config->tls($v);
        // Bind one resolved IP per attempt; TLS checks the configured hostname.
        // Certificate gateways remain public-network only.
        $transport = StandardAccount::is($v)
            ? new StandardSmtpTransport(StandardAccount::resolve($v),$v['port'],$progress,$v['encryption'],$v['auth_mode']==='password')
            : new StrictSmtpTransport($this->config->gatewayIPv4($v['host']),$v['port'],$progress);
        $transport->getStream()->setStreamOptions($options)->setTimeout(15);
        $transport->setUsername($v['username']);
        $transport->setPassword($v['app_password']);
        $transport->setLocalDomain('[127.0.0.1]');
        $envelope = new Envelope(new Address($payload['sender']),array_map(static fn(string $v) => new Address($v),$payload['recipients']));
        try {
            $progress->move('connecting');
            // A private transport with no external logger/dispatcher. Debug never leaves RAM.
            $mime = base64_decode($payload['mime'],true);
            SafeFailure::require(is_string($mime),'queued_mime_encoding');
            $transport->send(new RawMessage($mime),$envelope);
            SafeFailure::require($progress->phase === 'accepted','smtp_acceptance_unverified');
        } finally {
            try {
                $transport->stop();
            } finally {
                // Also close a failed STARTTLS connection that never reached started=true.
                $transport->getStream()->terminate();
                $transport->setPassword('');
            }
        }
    }
}
