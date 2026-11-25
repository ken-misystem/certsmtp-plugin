<?php
declare(strict_types=1);
namespace Plugin\CertSmtp\Resource\Runtime;

final class PrivateFiles
{
    public static function read(string $path, int $bound = 65536): string
    {
        SafeFailure::require($path !== '' && !str_contains($path, "\0") && !str_contains($path, '://'), 'private_path');
        $real = realpath($path);
        SafeFailure::require(is_string($real) && $real === $path && !is_link($path), 'private_path_not_canonical');
        $before = lstat($path);
        SafeFailure::require(is_array($before) && ($before['mode'] & 0170000) === 0100000
            && $before['nlink'] === 1 && $before['size'] > 0 && $before['size'] <= $bound, 'private_file_metadata');
        if (PHP_OS_FAMILY !== 'Windows') {
            SafeFailure::require(($before['mode'] & 0007) === 0 && ($before['mode'] & 0022) === 0, 'private_file_permissions');
            SafeFailure::require(function_exists('posix_geteuid') && in_array($before['uid'], [0, posix_geteuid()], true), 'private_file_owner');
        }
        $fd = @fopen($path, 'rb');
        SafeFailure::require(is_resource($fd), 'private_file_open');
        try {
            $held = fstat($fd);
            SafeFailure::require($held['dev'] === $before['dev'] && $held['ino'] === $before['ino'], 'private_file_open_race');
            $raw = stream_get_contents($fd, $bound + 1);
            clearstatcache(true, $path);
            $after = lstat($path);
            $identity = static fn(array $s): array => array_intersect_key($s,array_flip(['dev','ino','mode','uid','gid','nlink','size','mtime','ctime']));
            SafeFailure::require(is_string($raw) && strlen($raw) === $before['size'] && strlen($raw) <= $bound
                && is_array($after) && $identity($before) === $identity($after)
                && $identity(fstat($fd)) === $identity($held), 'private_file_changed');
            return $raw;
        } finally {
            fclose($fd);
        }
    }

    public static function stateDirectory(string $path, string $project): void
    {
        $real = realpath($path);
        SafeFailure::require(is_string($real) && $real === $path && is_dir($real) && !is_link($path), 'state_directory_canonical');
        $project = realpath($project);
        SafeFailure::require(is_string($project) && $real !== $project
            && !str_starts_with($real.DIRECTORY_SEPARATOR, $project.DIRECTORY_SEPARATOR), 'state_must_be_outside_project');
        if (PHP_OS_FAMILY !== 'Windows') {
            $s = lstat($path);
            SafeFailure::require(($s['mode'] & 0777) === 0700 && function_exists('posix_geteuid')
                && $s['uid'] === posix_geteuid(), 'state_directory_owner_mode');
        }
    }
}
