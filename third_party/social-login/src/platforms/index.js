export const PLATFORM_NAMES = Object.freeze([
  "facebook",
  "instagram",
  "linkedin",
  "reddit",
  "tiktok",
  "x",
]);

export function assertPlatform(value) {
  if (!PLATFORM_NAMES.includes(value)) {
    throw new Error(`unsupported platform: ${value}`);
  }
  return value;
}
