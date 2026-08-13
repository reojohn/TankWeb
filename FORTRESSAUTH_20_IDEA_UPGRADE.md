# FortressAuth Command Center Upgrade

This build implements the 20-part dashboard/security-console expansion requested on 2026-08-12.

## Implemented

1. Persistent FortressAuth security navbar
2. Overview as the main Command Center
3. Live protection/posture score derived from defense state
4. Password → School ID → Session → Protected Area verification chain
5. 24-hour authentication activity chart
6. Recent authentication attempts table
7. School ID security status card
8. Protected session security panel and live duration
9. Request-defense / attack-surface metrics
10. Threat Monitor with visible pressure calculation
11. Fortress Integrity status
12. Protected administrator resources panel
13. Dedicated Access Activity page
14. Dedicated Threat Center page
15. Expanded School ID Authentication page
16. Rebuilt structured Security Logs page
17. Dedicated Blocked IPs page with CSRF-protected unblock action
18. Dedicated Security Controls page
19. Current-session Fortress Timeline
20. Rebalanced dashboard layout to remove the large empty side column

## New files

- `src/fortress_metrics.php`
- `public/partials/command_header.php`
- `public/access_activity.php`
- `public/threats.php`
- `public/blocked_ips.php`
- `public/security_controls.php`

## Reworked files

- `public/dashboard.php`
- `public/school_id_manage.php`
- `public/admin_logs.php`
- `public/css/dashboard.css`
- `public/js/dashboard.js`
- `src/auth.php`

The server-side session timeout was aligned with the existing browser/dashboard policy at 15 minutes.

All PHP files in `public/` and `src/` passed `php -l`, and `public/js/dashboard.js` passed Node syntax validation before packaging.
