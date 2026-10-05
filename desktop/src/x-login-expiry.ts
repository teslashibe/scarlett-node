// Keep one bounded expiry callback for the active UI operation. The active flag
// also fences a callback already queued when completion or cancellation wins.
export function scheduleXLoginExpiry(
  expiresAt: string,
  onExpire: () => void,
  isCurrent: () => boolean = () => true,
): () => void {
  let active = true;
  const remaining = Date.parse(expiresAt) - Date.now();
  const delay = Number.isFinite(remaining) ? Math.max(0, Math.min(240_000, remaining)) : 0;
  const timer = setTimeout(() => {
    if (!active || !isCurrent()) return;
    active = false;
    onExpire();
  }, delay);
  return () => {
    active = false;
    clearTimeout(timer);
  };
}
