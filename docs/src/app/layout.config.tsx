import type { BaseLayoutProps } from "fumadocs-ui/layouts/shared";

/**
 * Shared layout configurations
 *
 * you can customise layouts individually from:
 * Home Layout: app/(home)/layout.tsx
 * Docs Layout: app/docs/layout.tsx
 */
export const baseOptions: BaseLayoutProps = {
  nav: {
    title: (
      <span className="flex items-center gap-2 font-semibold tracking-tight">
        🍎 <span>LOAS</span>
      </span>
    ),
  },
  themeSwitch: {
    enabled: false,
  },
  githubUrl: "https://github.com/cyberbuff/loas",
};
