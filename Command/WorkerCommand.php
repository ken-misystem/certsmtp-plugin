<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Command;

use Plugin\CertSmtp\Resource\Runtime\Worker;
use Plugin\CertSmtp\Resource\Runtime\WorkerAdmission;
use Plugin\CertSmtp\Resource\Runtime\Diagnostics;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class WorkerCommand extends Command
{
    private const ADMISSION_DENIED = 77;

    public function __construct(
        private readonly Worker $worker,
        private readonly string $requireAdmission = '0',
        private readonly ?WorkerAdmission $admission = null,
    ) {
        parent::__construct('cert-smtp:work');
    }
    protected function configure(): void
    {
        $this->setDescription('Process the encrypted certificate SMTP outbox.');
        $this->addOption('once',null,InputOption::VALUE_NONE,'Process at most one due message.');
    }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($this->requireAdmission !== '0' && ($this->requireAdmission !== '1' || $this->admission === null)) {
            $output->writeln('{"component":"cert_smtp","status":"worker_admission_unavailable"}');
            return self::ADMISSION_DENIED;
        }
        $stop = false;
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            foreach ([SIGTERM,SIGINT] as $signal) { pcntl_signal($signal,static function () use (&$stop): void { $stop = true; }); }
        }
        do {
            try {
                $result = $this->worker->once(admission: $this->admission);
                $output->writeln(json_encode(['component'=>'cert_smtp','at'=>gmdate('c'),'result'=>$result],JSON_THROW_ON_ERROR));
            } catch (\Throwable $e) {
                $output->writeln(json_encode(['component'=>'cert_smtp','status'=>'worker_failed','failure'=>Diagnostics::error($e,'worker')]));
                return 1;
            }
            if ($result['status'] === 'admission_denied') {
                return self::ADMISSION_DENIED;
            }
            if (!$input->getOption('once') && in_array($result['status'],['idle','busy'],true)) { sleep(5); }
        } while (!$stop && !$input->getOption('once'));
        return 0;
    }
}
