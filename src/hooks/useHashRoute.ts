import { useCallback, useEffect, useState } from 'react';

export type View = 'overview' | 'launch' | 'analytics' | 'findings';
export const VIEW_IDS: View[] = ['overview', 'launch', 'analytics', 'findings'];

export interface Route {
  view: View;
  params: URLSearchParams;
}

/** "#/analytics?q=/about" -> { view: 'analytics', params: q=/about }. Unknown hashes fall back to Overview. */
export function parseHash(hash: string): Route {
  const [path, query = ''] = hash.replace(/^#\/?/, '').split('?', 2);
  const view = VIEW_IDS.includes(path as View) ? (path as View) : 'overview';
  return { view, params: new URLSearchParams(query) };
}

export function hrefFor(view: View, params?: Record<string, string>) {
  const query = params ? new URLSearchParams(params).toString() : '';
  return `#/${view}${query ? `?${query}` : ''}`;
}

/** Hash-based routing: views are bookmarkable, work with Back/Forward, and need no server configuration. */
export function useHashRoute() {
  const [route, setRoute] = useState<Route>(() => parseHash(window.location.hash));

  useEffect(() => {
    const onChange = () => setRoute(parseHash(window.location.hash));
    window.addEventListener('hashchange', onChange);
    return () => window.removeEventListener('hashchange', onChange);
  }, []);

  const navigate = useCallback((view: View, params?: Record<string, string>) => {
    const href = hrefFor(view, params);
    if (window.location.hash === href) return;
    window.location.hash = href;
  }, []);

  return { ...route, navigate };
}
