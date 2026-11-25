<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Command;

use Plugin\CertSmtp\Resource\Runtime\Config;
use Plugin\CertSmtp\Resource\Runtime\SafeFailure;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

final class AccountCommand extends Command
{
    public function __construct(private readonly Config $config) { parent::__construct('cert-smtp:account'); }
    protected function configure(): void
    {
        $this->setDescription('Register from a private file, select, or list SMTP accounts; never send mail.')
            ->addArgument('action', InputArgument::REQUIRED, 'add, select, list')
            ->addArgument('id', InputArgument::OPTIONAL)
            ->addArgument('settings-file', InputArgument::OPTIONAL);
    }
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $action = $input->getArgument('action');
            if ($action === 'add') { $this->config->register((string)$input->getArgument('id'), (string)$input->getArgument('settings-file')); }
            elseif ($action === 'select') { $this->config->select((string)$input->getArgument('id')); }
            else { SafeFailure::require($action === 'list', 'account_action'); }
            $output->writeln(json_encode(['status'=>'ok', 'accounts'=>$this->config->accountStatus()], JSON_THROW_ON_ERROR));
            return 0;
        } catch (\Throwable $e) {
            $output->writeln(json_encode(['status'=>'failed', 'reason'=>$e instanceof SafeFailure ? $e->reason : 'account_operation_failed']));
            return 1;
        }
    }
}
