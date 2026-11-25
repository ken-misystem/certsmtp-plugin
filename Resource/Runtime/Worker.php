<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Worker
{
    private \Closure $send;
    public function __construct(private readonly Store $store, DirectSender|\Closure $sender)
    {
        $this->send = $sender instanceof \Closure ? $sender : $sender->deliver(...);
    }

    public function once(?int $now = null, ?WorkerAdmission $admission = null): array
    {
        if (!$this->deliveryAllowed($admission)) {
            return ['status'=>'admission_denied'];
        }
        $lock = $this->store->lock();
        if ($lock === null) { return ['status'=>'busy']; }
        try {
            $recovered = $this->store->recoverInterrupted();
            if (!$this->deliveryAllowed($admission)) {
                return ['status'=>'admission_denied'];
            }
            $row = $this->store->claim($now);
            if ($row === null) { return ['status'=>'idle','recovered'=>$recovered]; }
            $progress = new Progress(fn(string $phase) => $this->store->phase($row['id'],$phase));
            try {
                $payload = $this->store->openPayload($row);
                if (!$this->deliveryAllowed($admission)) {
                    // Preserve the preflight claim for the existing interrupted-attempt recovery.
                    return ['status'=>'admission_denied'];
                }
                ($this->send)($payload,$progress);
                SafeFailure::require($progress->phase === 'accepted','sender_returned_without_acceptance');
                $result = Outcome::accepted();
            } catch (\Throwable $e) {
                $result = Outcome::failure($e,$progress->phase,$row['attempts']);
            }
            $this->store->finish($row['id'],$result,Outcome::due($row['attempts'],$now ?? time()));
            return ['status'=>$result['state'],'id'=>$row['id'],'attempts'=>$row['attempts'],'reason'=>$result['reason'],
                'phase'=>$progress->phase,'smtp_code'=>$result['smtp_code']];
        } finally {
            flock($lock,LOCK_UN);
            fclose($lock);
        }
    }

    private function deliveryAllowed(?WorkerAdmission $admission): bool
    {
        try {
            return $admission === null || $admission->allowsDelivery();
        } catch (\Throwable) {
            return false;
        }
    }
}
