import { getVersion } from '@/lib/version';

export function useVersion(): string {
  return getVersion();
}
