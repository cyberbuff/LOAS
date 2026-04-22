import { HomeLayout } from "fumadocs-ui/layouts/home";
import type { ReactNode } from "react";
import { baseOptions } from "@/app/layout.config";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <HomeLayout
      {...baseOptions}
      links={[
        {
          text: "Scripts",
          url: "/docs",
        },
        {
          text: "Coverage",
          url: "/docs/coverage",
        },
        {
          text: "Contributing",
          url: "/docs/contributing",
        },
      ]}
    >
      {children}
    </HomeLayout>
  );
}
