<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\Mailer\Transport\Dsn;
use Symfony\Component\Mailer\Transport\TransportFactoryInterface;
use Symfony\Component\Mailer\Transport\TransportInterface;

final class TransportFactory implements TransportFactoryInterface
{
    public function __construct(private readonly QueueTransport $transport)
    {
    }
    public function supports(Dsn $dsn): bool
    {
        return $dsn->getScheme() === 'certsmtp';
    }
    public function create(Dsn $dsn): TransportInterface
    {
        SafeFailure::require($this->supports($dsn) && $dsn->getHost() === 'default' && $dsn->getUser() === null
            && $dsn->getPassword() === null && $dsn->getPort() === null,'certsmtp_dsn_no_secrets');
        return $this->transport;
    }
}
