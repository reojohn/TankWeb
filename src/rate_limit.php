<?php

declare(strict_types=1);

/**
 * Small server-side rate limiter for second-factor endpoints.
 * Uses files outside the public web root and supports both IP and account keys.
 * This is appropriate for a single-instance course deployment. For multi-node
 * production deployments, replace with Redis or a database-backed limiter.
 */
function fortress_rate_limit_dir(): string
{
    $dir = __DIR__ . '/../data/ratelimits';
    if (!is_dir($dir)) {
        @mkdir($dir, 0700, true);
    }
    return $dir;
}

function fortress_rate_limit_file(string $action, string $key): string
{
    $safeAction = preg_replace('/[^a-z0-9_\-]/i', '_', $action) ?: 'action';
    return fortress_rate_limit_dir() . '/' . $safeAction . '_' . hash('sha256', $key) . '.json';
}

function fortress_rate_limit_state(string $action, string $key, int $windowSeconds): array
{
    $file = fortress_rate_limit_file($action, $key);
    $now = time();
    $events = [];

    if (is_file($file)) {
        $decoded = json_decode((string)@file_get_contents($file), true);
        if (is_array($decoded)) {
            $events = array_values(array_filter($decoded, static fn($t): bool => is_int($t) || ctype_digit((string)$t)));
        }
    }

    $events = array_values(array_filter($events, static fn($t): bool => ((int)$t + $windowSeconds) > $now));
    return [$file, $events];
}

function fortress_rate_limit_is_blocked(string $action, string $key, int $limit, int $windowSeconds): bool
{
    [, $events] = fortress_rate_limit_state($action, $key, $windowSeconds);
    return count($events) >= $limit;
}

function fortress_rate_limit_record_failure(string $action, string $key, int $windowSeconds): void
{
    [$file, $events] = fortress_rate_limit_state($action, $key, $windowSeconds);
    $events[] = time();
    @file_put_contents($file, json_encode($events), LOCK_EX);
}

function fortress_rate_limit_clear(string $action, string $key): void
{
    $file = fortress_rate_limit_file($action, $key);
    if (is_file($file)) {
        @unlink($file);
    }
}
