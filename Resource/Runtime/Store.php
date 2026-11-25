<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class Store
{
    private ?\PDO $db = null;
    private ?string $keyId = null;

    public function __construct(private readonly Config $config)
    {
    }

    private function connection(): \PDO
    {
        $v = $this->config->get();
        $keyId = hash('sha256', $v['queue_key']);
        if ($this->db !== null) {
            SafeFailure::require($keyId === $this->keyId, 'queue_key_changed');
            return $this->db;
        }
        $path = $v['state_dir'].DIRECTORY_SEPARATOR.'outbox.sqlite';
        if (file_exists($path) || is_link($path)) {
            SafeFailure::require(!is_link($path), 'queue_file_symlink');
            $s = lstat($path);
            SafeFailure::require(($s['mode'] & 0170000) === 0100000 && $s['nlink'] === 1, 'queue_file_type');
            if (PHP_OS_FAMILY !== 'Windows') {
                SafeFailure::require(($s['mode'] & 0777) === 0600 && $s['uid'] === posix_geteuid(), 'queue_file_permissions');
            }
        }
        $oldMask = umask(0077);
        try {
            $db = new \PDO('sqlite:'.$path, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION]);
        } finally {
            umask($oldMask);
        }
        $db->exec('PRAGMA busy_timeout=5000');
        $db->exec('PRAGMA journal_mode=WAL');
        $db->exec('PRAGMA synchronous=FULL');
        $db->exec('CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), key_id TEXT NOT NULL)');
        $db->exec('CREATE TABLE IF NOT EXISTS outbox (id TEXT PRIMARY KEY, dedupe TEXT UNIQUE NOT NULL, payload BLOB, state TEXT NOT NULL,
            created_at INTEGER NOT NULL, started_at INTEGER, finished_at INTEGER, due_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            phase TEXT NOT NULL DEFAULT \'queued\', reason TEXT, smtp_code INTEGER, safe_retry INTEGER NOT NULL DEFAULT 0,
            failure_class TEXT, failure_component TEXT, failure_line INTEGER)');
        $db->exec('CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,due_at)');
        $db->exec('CREATE TABLE IF NOT EXISTS attempts (run_id INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT NOT NULL,
            attempt INTEGER NOT NULL, started_at INTEGER NOT NULL, finished_at INTEGER, state TEXT NOT NULL,
            phase TEXT NOT NULL, reason TEXT, smtp_code INTEGER, failure_class TEXT, failure_component TEXT, failure_line INTEGER)');
        $q = $db->prepare('INSERT OR IGNORE INTO metadata(id,key_id) VALUES(1,?)');
        $q->execute([$keyId]);
        SafeFailure::require($db->query('SELECT key_id FROM metadata WHERE id=1')->fetchColumn() === $keyId, 'queue_key_mismatch');
        $this->db = $db;
        $this->keyId = $keyId;
        return $db;
    }

    public function enqueue(array $payload, ?int $now = null): string
    {
        $db = $this->connection();
        $raw = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        SafeFailure::require(strlen($raw) <= 10485760, 'message_size_limit');
        $key = $this->config->get()['queue_key'];
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $sealed = $nonce.sodium_crypto_secretbox($raw, $nonce, $key);
        $dedupe = hash('sha256', $raw);
        $db->exec('BEGIN IMMEDIATE');
        try {
            $q = $db->prepare('SELECT id FROM outbox WHERE dedupe=?');
            $q->execute([$dedupe]);
            $prior = $q->fetchColumn();
            if (is_string($prior)) {
                $db->exec('COMMIT');
                return $prior;
            }
            $usage = $db->query('SELECT COUNT(*),COALESCE(SUM(LENGTH(payload)),0) FROM outbox WHERE payload IS NOT NULL')->fetch(\PDO::FETCH_NUM);
            SafeFailure::require((int)$usage[0] < 10000 && (int)$usage[1] + strlen($sealed) <= 104857600, 'queue_capacity_exceeded');
            $id = bin2hex(random_bytes(16));
            $q = $db->prepare('INSERT INTO outbox(id,dedupe,payload,state,created_at,due_at) VALUES(?,?,CAST(? AS BLOB),\'queued\',?,?)');
            $q->execute([$id,$dedupe,$sealed,$now ?? time(),$now ?? time()]);
            $db->exec('COMMIT');
            return $id;
        } catch (\Throwable $e) {
            try { $db->exec('ROLLBACK'); } catch (\Throwable) { /* SQLite may already have rolled back. */ }
            throw $e;
        }
    }

    /** Caller holds the worker lock for recovery, claim and complete send. */
    public function recoverInterrupted(): int
    {
        $rows = $this->connection()->query("SELECT id,phase,attempts FROM outbox WHERE state='sending'")->fetchAll(\PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            if ($row['phase'] === 'accepted') {
                $outcome = Outcome::accepted();
            } elseif ($row['phase'] === 'data') {
                $outcome = ['state'=>'uncertain','reason'=>'worker_interrupted_during_data','smtp_code'=>null,'safe_retry'=>false];
            } else {
                $outcome = ['state'=>(int)$row['attempts'] < 5 ? 'retry' : 'failed','reason'=>'worker_interrupted_before_data','smtp_code'=>null,'safe_retry'=>true];
            }
            $this->finish($row['id'],$outcome,Outcome::due((int)$row['attempts'],time()));
        }
        return count($rows);
    }

    public function claim(?int $now = null): ?array
    {
        $db = $this->connection();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $q = $db->prepare("SELECT id,payload,attempts FROM outbox WHERE state IN ('queued','retry') AND due_at<=? ORDER BY due_at,created_at,id LIMIT 1");
            $q->execute([$now ?? time()]);
            $row = $q->fetch(\PDO::FETCH_ASSOC);
            if ($row === false) {
                $db->exec('COMMIT');
                return null;
            }
            $q = $db->prepare("UPDATE outbox SET state='sending',attempts=attempts+1,started_at=?,finished_at=NULL,phase='preflight' WHERE id=? AND state IN ('queued','retry')");
            $q->execute([$now ?? time(),$row['id']]);
            SafeFailure::require($q->rowCount() === 1, 'claim_conflict');
            $q = $db->prepare("INSERT INTO attempts(message_id,attempt,started_at,state,phase) VALUES(?,?,?,'sending','preflight')");
            $q->execute([$row['id'],(int)$row['attempts']+1,$now ?? time()]);
            $db->exec('COMMIT');
            $row['attempts'] = (int)$row['attempts'] + 1;
            return $row;
        } catch (\Throwable $e) {
            try { $db->exec('ROLLBACK'); } catch (\Throwable) { /* Preserve the original failure. */ }
            throw $e;
        }
    }

    public function openPayload(array $row): array
    {
        $sealed = $row['payload'];
        SafeFailure::require(is_string($sealed) && strlen($sealed) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES, 'queue_payload_shape');
        $raw = sodium_crypto_secretbox_open(substr($sealed,24), substr($sealed,0,24), $this->config->get()['queue_key']);
        SafeFailure::require(is_string($raw), 'queue_payload_authentication');
        $v = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
        SafeFailure::require(is_array($v) && in_array(array_keys($v), [['sender','recipients','mime'],['sender','recipients','mime','account_id']], true) && is_string($v['sender']) && is_string($v['mime'])
            && is_array($v['recipients']) && count($v['recipients']) > 0 && count($v['recipients']) <= 100, 'queue_payload_schema');
        if (array_key_exists('account_id', $v)) { SafeFailure::require(is_string($v['account_id']), 'queued_account_id'); Accounts::id($v['account_id']); }
        return $v;
    }

    public function phase(string $id, string $phase): void
    {
        SafeFailure::require(in_array($phase, ['preflight','connecting','tls','authentication','envelope','data','accepted'], true), 'phase_label');
        $q = $this->connection()->prepare("UPDATE outbox SET phase=? WHERE id=? AND state='sending'");
        $q->execute([$phase,$id]);
        SafeFailure::require($q->rowCount() === 1, 'phase_state_conflict');
        $q = $this->connection()->prepare('UPDATE attempts SET phase=? WHERE run_id=(SELECT MAX(run_id) FROM attempts WHERE message_id=?)');
        $q->execute([$phase,$id]);
    }

    public function finish(string $id, array $result, int $due): void
    {
        SafeFailure::require(in_array($result['state'], ['accepted','retry','failed','uncertain'], true), 'finish_state');
        $db = $this->connection();
        $db->exec('BEGIN IMMEDIATE');
        try {
            $q = $db->prepare("UPDATE outbox SET state=?,finished_at=?,due_at=?,reason=?,smtp_code=?,safe_retry=?,failure_class=?,failure_component=?,failure_line=?,payload=CASE WHEN ?='accepted' THEN NULL ELSE payload END WHERE id=? AND state='sending'");
            $q->execute([$result['state'],time(),$due,$result['reason'],$result['smtp_code'],(int)$result['safe_retry'],
                $result['failure_class'] ?? null,$result['failure_component'] ?? null,$result['failure_line'] ?? null,$result['state'],$id]);
            SafeFailure::require($q->rowCount() === 1, 'finish_state_conflict');
            $q = $db->prepare('UPDATE attempts SET state=?,finished_at=?,reason=?,smtp_code=?,failure_class=?,failure_component=?,failure_line=? WHERE run_id=(SELECT MAX(run_id) FROM attempts WHERE message_id=?)');
            $q->execute([$result['state'],time(),$result['reason'],$result['smtp_code'],$result['failure_class'] ?? null,
                $result['failure_component'] ?? null,$result['failure_line'] ?? null,$id]);
            $db->exec('COMMIT');
        } catch (\Throwable $e) { try { $db->exec('ROLLBACK'); } catch (\Throwable) { /* Preserve the original failure. */ } throw $e; }
    }

    public function manualRetry(string $id): bool
    {
        SafeFailure::require(preg_match('/^[0-9a-f]{32}$/D',$id) === 1, 'queue_id');
        // An unknown acceptance can never be retried by this convenience control.
        $q = $this->connection()->prepare("UPDATE outbox SET state='retry',due_at=?,reason='manual_retry',attempts=0 WHERE id=? AND state='failed' AND safe_retry=1");
        $q->execute([time(),$id]);
        return $q->rowCount() === 1;
    }

    public function history(): array
    {
        return $this->connection()->query('SELECT id,state,created_at,started_at,finished_at,due_at,attempts,phase,reason,smtp_code,safe_retry,failure_class,failure_component,failure_line FROM outbox ORDER BY created_at DESC,id DESC LIMIT 10')->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function counts(): array
    {
        return $this->connection()->query('SELECT state,COUNT(*) AS records FROM outbox GROUP BY state')->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function attemptHistory(): array
    {
        return $this->connection()->query('SELECT attempt,started_at,finished_at,state,phase,reason,smtp_code,failure_class,failure_component,failure_line FROM attempts ORDER BY run_id DESC LIMIT 10')->fetchAll(\PDO::FETCH_ASSOC);
    }

    public function health(): array
    {
        return $this->connection()->query("SELECT COALESCE(MIN(CASE WHEN state IN ('queued','retry') THEN created_at END),0) AS oldest_pending,
            SUM(CASE WHEN state IN ('failed','uncertain') THEN 1 ELSE 0 END) AS needs_attention FROM outbox")->fetch(\PDO::FETCH_ASSOC);
    }

    public function lock(): mixed
    {
        $path = $this->config->get()['state_dir'].DIRECTORY_SEPARATOR.'worker.lock';
        SafeFailure::require(!is_link($path), 'worker_lock_symlink');
        $old = umask(0077);
        try { $fd = fopen($path,'c+b'); } finally { umask($old); }
        SafeFailure::require(is_resource($fd), 'worker_lock_open');
        if (!flock($fd, LOCK_EX | LOCK_NB)) {
            fclose($fd);
            return null;
        }
        return $fd;
    }
}
