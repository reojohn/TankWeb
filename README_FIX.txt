Mobile refresh false Recon fix

Changed files:
1. public/security_probe.php
   - Ignores automatic mobile browser icon/manifest/discovery requests.
   - Keeps sensitive-path probes detectable.
2. src/fortress_metrics.php
   - Filters previously persisted benign browser-generated recon events from metrics/notifications.
3. public/js/security_alerts.js
   - Does not replay historical unread events as fresh toast notifications on initial page load/refresh.
   - New events received after the notification cursor is established still toast normally.
