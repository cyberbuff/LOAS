import getConfig from 'next/config';

export function getVersion(): string {
  try {
    const { publicRuntimeConfig } = getConfig() || {};
    return publicRuntimeConfig?.appVersion || '0.1.4';
  } catch (error) {
    console.warn('Failed to get version from runtime config:', error);
    return '0.1.4';
  }
}
