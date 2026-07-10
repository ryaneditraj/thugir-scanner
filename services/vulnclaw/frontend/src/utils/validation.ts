export function parseOptionalPort(value: string): number | undefined {
  const normalized = value.trim();
  if (!normalized) return undefined;

  if (!/^\d+$/.test(normalized)) {
    throw new Error("Port must be a number between 1 and 65535.");
  }

  const parsed = Number(normalized);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error("Port must be a number between 1 and 65535.");
  }

  return parsed;
}
