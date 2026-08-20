import React, { useEffect, useMemo, useState } from 'react';

export function PageState({ loading, error, children }) {
  if (loading) return <section className="v3-route-skeleton" aria-label="Syncing FortressAuth data" aria-busy="true"><span className="sr-only">Syncing security data</span><div className="v3-skeleton-metrics">{[0,1,2,3].map((item) => <span key={item} />)}</div><div className="v3-skeleton-panels"><span /><span /></div></section>;
  if (error) return <section className="panel v3-error-panel"><i className="fa-solid fa-triangle-exclamation" /><div><strong>Unable to load this workspace</strong><span>{error}</span></div></section>;
  return children;
}

export function PageHero({ eyebrow, title, description, icon, danger = false, children }) {
  return <section className="page-hero compact-page-hero"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1><p>{description}</p>{children}</div><div className={`page-hero-icon ${danger ? 'danger' : ''}`}><i className={`fa-solid ${icon}`} /></div></section>;
}

export function MetricGrid({ items }) {
  return <section className="metric-grid">{items.map((item, index) => <article className="metric-card" key={`${item.label}-${index}`}><div className={`metric-icon ${item.tone || ''}`}><i className={`fa-solid ${item.icon}`} /></div><div><span>{item.label}</span><strong className={item.small ? 'small-metric-value' : 'metric-number'} data-count={typeof item.value === 'number' ? item.value : undefined}>{item.value}</strong><small>{item.note}</small></div></article>)}</section>;
}

export function StatusPill({ outcome }) {
  const key = String(outcome || 'RECORDED').toLowerCase();
  return <span className={`status-pill status-${key}`}>{String(outcome || 'RECORDED')}</span>;
}

export function TableFilters({ search, setSearch, category, setCategory, categories = [] }) {
  return <div className="table-tools"><label className="search-control"><i className="fa-solid fa-magnifying-glass" /><input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search records..." /></label>{categories.length ? <select value={category} onChange={(e) => setCategory(e.target.value)}><option value="all">All categories</option>{categories.map((c) => <option key={c} value={c.toLowerCase()}>{c}</option>)}</select> : null}</div>;
}

export function useFilteredRows(rows = [], { fields = [], categoryField = 'category' } = {}) {
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('all');
  const filtered = useMemo(() => rows.filter((row) => {
    const haystack = fields.map((f) => row?.[f] ?? '').join(' ').toLowerCase();
    const categoryValue = String(row?.[categoryField] ?? '').toLowerCase();
    return (!search || haystack.includes(search.toLowerCase())) && (category === 'all' || categoryValue === category);
  }), [rows, fields.join('|'), search, category, categoryField]);
  return { search, setSearch, category, setCategory, filtered };
}

export function CanvasLine({ id, labels, success, failed, school, blocked }) {
  return <canvas id={id} data-labels={JSON.stringify(labels || [])} data-success={JSON.stringify(success || [])} data-failed={JSON.stringify(failed || [])} data-school={JSON.stringify(school || [])} data-blocked={JSON.stringify(blocked || [])} />;
}

export function SecurityChart({ type, title, labels, values, series, centerValue, centerLabel }) {
  return <canvas data-security-chart={type} data-chart-title={title} data-labels={JSON.stringify(labels || [])} data-values={JSON.stringify(values || [])} data-series={JSON.stringify(series || [])} data-center-value={centerValue ?? ''} data-center-label={centerLabel ?? ''} role="img" aria-label={title} />;
}

export function useLegacyUiInit(data, { ai = false } = {}) {
  useEffect(() => {
    if (!data) return;
    const id = window.setTimeout(() => {
      window.FortressDashboard?.init?.();
      if (ai) window.FortressAI?.init?.();
    }, 30);
    return () => window.clearTimeout(id);
  }, [data, ai]);
}

export function Footer({ left, right, icon = 'fa-shield-halved' }) {
  return <footer className="command-footer"><span><i className={`fa-solid ${icon}`} /> {left}</span><span>{right}</span></footer>;
}
