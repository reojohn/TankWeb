/* Academic review policy: persisted score = min(1, error / (2.5 * threshold)). */
'use strict';
window.AegisReview = Object.freeze({
  anomalous: e => Number.isFinite(Number(e?.anomaly_score)) && Number(e.anomaly_score) > 0.4,
  requiresReview: e => e.classification !== 'NORMAL' || window.AegisReview.anomalous(e),
  anomalyOnly: e => e.classification === 'NORMAL' && window.AegisReview.anomalous(e),
  disposition: e => window.AegisReview.anomalyOnly(e) ? 'Anomaly requiring review' : window.AegisReview.requiresReview(e) ? 'Classified threat requiring review' : 'Baseline',
  followup: e => window.AegisReview.requiresReview(e) && ['INVESTIGATING','MITIGATED','RESOLVED'].includes(e.status),
  unresolved: e => window.AegisReview.requiresReview(e) && e.status !== 'RESOLVED',
});
