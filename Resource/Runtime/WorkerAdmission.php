<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

interface WorkerAdmission
{
    /** Check the current delivery permission without waiting for it to become available. */
    public function allowsDelivery(): bool;
}
