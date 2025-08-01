import { HomeLayout } from "fumadocs-ui/layouts/home";
import Link from "next/link";
import type { ReactNode } from "react";
import { baseOptions } from "@/app/layout.config";

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <HomeLayout
      {...baseOptions}
      links={[
        {
          type: "custom",
          children: <Link href="/docs">Scripts</Link>,
        },
        // other items
      ]}
    >
      {children}
    </HomeLayout>
  );
}
