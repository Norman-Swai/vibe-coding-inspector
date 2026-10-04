import { TriangleAlert } from 'lucide-react';
import { Component, type ErrorInfo, type ReactNode } from 'react';

interface Props {
  /** Changing this (view or scan) clears the error so the user can move on. */
  resetKey: string;
  onForgetScan: () => void;
  children: ReactNode;
}

/** Never leave a blank page: if a view fails to render, explain and offer a way out. */
export class ViewErrorBoundary extends Component<Props, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('View failed to render', error, info.componentStack);
  }

  componentDidUpdate(previous: Props) {
    if (previous.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <section className="panel crash-panel" role="alert" aria-labelledby="crash-title">
        <h1 id="crash-title" tabIndex={-1} data-view-heading>
          <TriangleAlert size={22} aria-hidden="true" /> This view could not be displayed
        </h1>
        <p>
          The most common cause is a backend that is older than this page (for example, it was not restarted after updating the code). If a warning about the
          inspector API is shown above, follow it first.
        </p>
        <pre className="evidence">{error.message}</pre>
        <div className="button-row">
          <button type="button" className="button button-primary" onClick={this.props.onForgetScan}>
            Forget the current scan
          </button>
          <button type="button" className="button button-ghost" onClick={() => window.location.reload()}>
            Reload the page
          </button>
        </div>
      </section>
    );
  }
}
