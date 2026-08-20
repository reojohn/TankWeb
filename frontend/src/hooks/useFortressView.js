import { useEffect, useState } from 'react';
import { fetchView, getCachedView } from '../api/fortressApi.js';

export default function useFortressView(view) {
  const [state, setState] = useState(() => {
    const cached = getCachedView(view);
    return {
      loading: cached == null,
      refreshing: false,
      data: cached,
      error: '',
    };
  });

  const load = (force = false) => {
    setState((old) => ({
      ...old,
      loading: old.data == null,
      refreshing: old.data != null,
      error: '',
    }));

    return fetchView(view, { force })
      .then((data) => setState({ loading: false, refreshing: false, data, error: '' }))
      .catch((error) => setState((old) => ({
        ...old,
        loading: false,
        refreshing: false,
        error: error.message || String(error),
      })));
  };

  useEffect(() => {
    const cached = getCachedView(view);
    if (cached != null) {
      setState((old) => ({ ...old, loading: false, data: cached, error: '' }));
    }
    load();
  }, [view]);

  return { ...state, reload: () => load(true) };
}
