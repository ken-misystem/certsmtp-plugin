<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Command;

use Plugin\CertSmtp\Resource\Runtime\Config;
use Plugin\CertSmtp\Resource\Runtime\Store;
use Plugin\CertSmtp\Resource\Runtime\SafeFailure;
use Plugin\CertSmtp\Resource\Runtime\Diagnostics;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class StatusCommand extends Command
{
    public function __construct(private readonly Config $config, private readonly Store $store)
    {
        parent::__construct('cert-smtp:status');
    }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $status = $this->config->publicStatus();
            $counts = $this->store->counts();
            $health = $this->store->health();
            $bad = !$status['configured'];
            if ((int)$health['oldest_pending'] > 0 && time() - (int)$health['oldest_pending'] > 900) { $bad = true; }
            if ($status['configured'] && $status['expires_at'] !== null && strtotime($status['expires_at'].' UTC') - time() < 30*86400) { $bad = true; }
            foreach ($counts as $row) {
                if (in_array($row['state'],['failed','uncertain'],true) && (int)$row['records'] > 0) { $bad = true; }
            }
            $output->writeln(json_encode(['component'=>'cert_smtp','status'=>$bad ? 'attention' : 'ok','config'=>$status,'counts'=>$counts,'health'=>$health,'latest'=>$this->store->history(),'attempts'=>$this->store->attemptHistory()],JSON_THROW_ON_ERROR));
            return $bad ? 1 : 0;
        } catch (\Throwable $e) {
            $output->writeln(json_encode(['component'=>'cert_smtp','status'=>'failed','failure'=>Diagnostics::error($e,'status')]));
            return 1;
        }
    }
}
