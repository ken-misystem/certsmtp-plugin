<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\RawMessage;

final class QueueTransport implements TransportInterface
{
    public function __construct(private readonly Config $config, private readonly Store $store)
    {
    }

    public function send(RawMessage $message, ?Envelope $envelope = null): ?SentMessage
    {
        try {
            $v = $this->config->get();
            $sender = Config::sender($v);
            SafeFailure::require($message instanceof Email,'email_object_required');
            $from = $message->getFrom();
            SafeFailure::require(count($from) === 1 && $this->config->registeredSender($from[0]->getAddress()), 'from_identity_mismatch');
            $envelope ??= Envelope::create($message);
            SafeFailure::require($envelope->getSender()->getAddress() === $from[0]->getAddress(), 'envelope_sender_mismatch');
            $recipients = array_map(static fn($v) => $v->getAddress(),$envelope->getRecipients());
            SafeFailure::require(count($recipients) > 0 && count($recipients) <= 100,'recipient_count_bound');
            // Apply the selected registered account without changing store DB settings.
            // Do not mutate the caller's object or rewrite recipients/Bcc/Reply-To.
            $message = clone $message;
            $message->from(new Address($sender, $from[0]->getName()))->sender($sender);
            $message->getHeaders()->remove('Return-Path');
            $envelope = new Envelope(new Address($sender), $envelope->getRecipients());
            $sent = new SentMessage($message,$envelope);
            $this->store->enqueue(['sender'=>$sender,'recipients'=>$recipients,'mime'=>base64_encode($sent->toString()),'account_id'=>$v['account_id']]);
            return $sent; // QUEUED, not a delivery/receipt acknowledgment.
        } catch (\Throwable $e) {
            throw new TransportException('CertSmtp: '.($e instanceof SafeFailure ? $e->reason : 'queue_write_failed'));
        }
    }

    public function __toString(): string
    {
        return 'certsmtp://default';
    }
}
