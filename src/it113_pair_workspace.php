<?php
/**
 * Login-free, two-seat academic collaboration. Authorization is via the
 * existing 256-bit HttpOnly browser session and a one-use, short-lived invite.
 * Invite tokens are hashed before storage; only the owner receives the raw
 * token once. This module NEVER reads operational/admin tables.
 */
declare(strict_types=1);

function it113_pair_enabled(): bool {
    return filter_var(getenv('IT113_PAIR_WORKSPACE_ENABLED') ?: 'false', FILTER_VALIDATE_BOOL)
        && it113_store_enabled();
}

function it113_pair_uuid(): string {
    $b = random_bytes(16);
    $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
    $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
    $h = bin2hex($b);
    return substr($h,0,8).'-'.substr($h,8,4).'-'.substr($h,12,4).'-'.substr($h,16,4).'-'.substr($h,20);
}

/** Null means a backend problem; a non-null result is an authorized scope. */
function it113_pair_scope(bool $createSession=true): ?array {
    $pdo = it113_store_db();
    if (!$pdo) return null;
    $sid = it113_store_session($createSession);
    if (!$sid) return null;
    $scope = ['sid'=>$sid, 'workspace_id'=>null, 'role'=>null];
    if (!it113_pair_enabled()) return $scope;
    try {
        $st = $pdo->prepare('SELECT m.workspace_id::text AS workspace_id, m.role
            FROM public.it113_pair_members m
            JOIN public.it113_pair_workspaces w ON w.workspace_id=m.workspace_id
            WHERE m.session_digest=? LIMIT 1');
        $st->execute([$sid]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        if ($row) { $scope['workspace_id'] = trim((string)$row['workspace_id']); $scope['role'] = $row['role']; }
        return $scope;
    } catch (Throwable $e) {
        it113_store_log_error('pair scope', $e);
        return null; // fail closed; NEVER fall back to another session's data
    }
}

function it113_pair_status(): ?array {
    $scope = it113_pair_scope(true);
    if (!$scope) return null;
    if (!$scope['workspace_id']) return ['active'=>false,'role'=>null,'members'=>0,'max_members'=>2];
    try {
        $pdo=it113_store_db();
        $st=$pdo->prepare('SELECT COUNT(*) FROM public.it113_pair_members WHERE workspace_id=?');
        $st->execute([$scope['workspace_id']]);
        return ['active'=>true,'role'=>$scope['role'],'members'=>(int)$st->fetchColumn(),
            'max_members'=>2, 'workspace_id'=>$scope['workspace_id']];
    } catch(Throwable $e) { it113_store_log_error('pair status',$e); return null; }
}

/** Returns [success, code, optional one-time invite token]. */
function it113_pair_action(string $action, array $request): array {
    if (!it113_pair_enabled()) return [false,'disabled'];
    $pdo=it113_store_db(); $sid=it113_store_session(true);
    if (!$pdo || !$sid) return [false,'unavailable'];
    try {
        $pdo->beginTransaction();
        $st=$pdo->prepare('SELECT workspace_id::text, role FROM public.it113_pair_members WHERE session_digest=? FOR UPDATE');
        $st->execute([$sid]);
        $current=$st->fetch(PDO::FETCH_ASSOC);
        if ($action === 'create') {
            if ($current) { $pdo->rollBack(); return [false,'already_member']; }
            if (count($request)!==2 || ($request['action']??null)!=='create'
                || !is_bool($request['include_private']??null)) { $pdo->rollBack();return [false,'invalid']; }
            $wid=it113_pair_uuid();
            $s=$pdo->prepare('INSERT INTO public.it113_pair_workspaces (workspace_id, owner_digest) VALUES (?, ?)');
            $s->execute([$wid,$sid]);
            $s=$pdo->prepare("INSERT INTO public.it113_pair_members(workspace_id,session_digest,role) VALUES (?,?,'owner')");
            $s->execute([$wid,$sid]);
            if ($request['include_private']) {
                $s=$pdo->prepare('UPDATE public.it113_demo_assessments SET workspace_id=?
                    WHERE session_digest=? AND workspace_id IS NULL');
                $s->execute([$wid,$sid]);
            }
            $pdo->commit();
            return [true,'created'];
        }
        if ($action === 'join') {
            if ($current) { $pdo->rollBack(); return [false,'already_member']; }
            $token=$request['token']??null;
            if (count($request)!==2 || !is_string($token) || !preg_match('/^[a-f0-9]{64}$/D',$token)) {
                $pdo->rollBack(); return [false,'invalid'];
            }
            $s=$pdo->prepare('SELECT workspace_id::text FROM public.it113_pair_workspaces
              WHERE invite_digest=? AND invite_expires>NOW() FOR UPDATE');
            $s->execute([hash('sha256',$token)]);
            $w=$s->fetch(PDO::FETCH_ASSOC);
            if (!$w) { $pdo->rollBack(); return [false,'invalid_or_expired_invite']; }
            $wid=$w['workspace_id'];
            $s=$pdo->prepare('SELECT COUNT(*) FROM public.it113_pair_members WHERE workspace_id=?');
            $s->execute([$wid]);
            if ((int)$s->fetchColumn() !== 1) { $pdo->rollBack(); return [false,'full']; }
            $s=$pdo->prepare("INSERT INTO public.it113_pair_members (workspace_id,session_digest,role) VALUES (?,?,'partner')");
            $s->execute([$wid,$sid]);
            $s=$pdo->prepare('UPDATE public.it113_pair_workspaces SET invite_digest=NULL,
               invite_expires=NULL,updated_at=NOW() WHERE workspace_id=?');
            $s->execute([$wid]);
            $pdo->commit();
            return [true,'joined'];
        }
        if (!$current) { $pdo->rollBack(); return [false,'not_member']; }
        $wid=(string)$current['workspace_id'];
        $s=$pdo->prepare('SELECT workspace_id FROM public.it113_pair_workspaces WHERE workspace_id=? FOR UPDATE');
        $s->execute([$wid]);
        if (!$s->fetchColumn()) { $pdo->rollBack();return [false,'unavailable']; }
        if ($action === 'invite') {
            if (count($request)!==1 || $current['role']!=='owner') { $pdo->rollBack();return [false,'forbidden']; }
            $s=$pdo->prepare('SELECT COUNT(*) FROM public.it113_pair_members WHERE workspace_id=?');
            $s->execute([$wid]);
            if ((int)$s->fetchColumn()>=2) { $pdo->rollBack(); return [false,'full']; }
            $raw=bin2hex(random_bytes(32));
            $s=$pdo->prepare("UPDATE public.it113_pair_workspaces SET invite_digest=?, invite_expires=NOW()+INTERVAL '48 hours',
               updated_at=NOW() WHERE workspace_id=?");
            $s->execute([hash('sha256',$raw),$wid]);
            $pdo->commit();
            return [true,'invite_created',$raw];
        }
        if ($action === 'remove_partner') {
            if (count($request)!==1 || $current['role']!=='owner') { $pdo->rollBack();return [false,'forbidden']; }
            $s=$pdo->prepare("DELETE FROM public.it113_pair_members WHERE workspace_id=? AND role='partner'");
            $s->execute([$wid]);
            $s=$pdo->prepare('UPDATE public.it113_pair_workspaces SET invite_digest=NULL,invite_expires=NULL,
              updated_at=NOW() WHERE workspace_id=?');
            $s->execute([$wid]);
            $pdo->commit();
            return [true,'partner_removed'];
        }
        if ($action === 'leave') {
            if (count($request)!==1 || $current['role']!=='partner') { $pdo->rollBack();return [false,'forbidden']; }
            $s=$pdo->prepare("DELETE FROM public.it113_pair_members WHERE workspace_id=? AND session_digest=? AND role='partner'");
            $s->execute([$wid,$sid]);
            $pdo->commit();
            return [true,'left'];
        }
        $pdo->rollBack();return [false,'invalid'];
    } catch(Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        it113_store_log_error('pair '.$action,$e);
        return [false,'unavailable'];
    }
}
