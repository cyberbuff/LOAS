"use client";

import { motion } from "motion/react";
import Link from "next/link";
import { Code2, Target, Terminal } from "lucide-react";

import { DataTableWithFilters } from "@/components/data-table-with-filters";
import { columns, type Script } from "@/components/scripts-columns";

interface AnimatedHomepageProps {
  scripts: Script[];
  uniqueTechniques: number;
}

const stats = (scripts: Script[], uniqueTechniques: number) => [
  {
    value: 2,
    label: "Script Types",
    sublabel: "AppleScript & JXA",
    icon: Code2,
  },
  {
    value: uniqueTechniques,
    label: "ATT&CK Techniques",
    sublabel: "MITRE ATT&CK mapped",
    icon: Target,
  },
  {
    value: scripts.length,
    label: "Total Scripts",
    sublabel: "Atomic tests",
    icon: Terminal,
  },
];

export function AnimatedHomepage({
  scripts,
  uniqueTechniques,
}: AnimatedHomepageProps) {
  const statItems = stats(scripts, uniqueTechniques);

  return (
    <main className="min-h-screen bg-background">
      {/* Hero Section */}
      <div className="relative overflow-hidden border-b border-border">
        {/* Grid background */}
        <div
          className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `linear-gradient(currentColor 1px, transparent 1px), linear-gradient(90deg, currentColor 1px, transparent 1px)`,
            backgroundSize: "40px 40px",
          }}
        />
        {/* Radial gradient overlay */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_50%_at_50%_-10%,hsl(var(--primary)/0.15),transparent)]" />

        <div className="container mx-auto px-4 py-24 relative z-10">
          <motion.div
            className="text-center space-y-8 max-w-4xl mx-auto"
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7 }}
          >
            {/* Title */}
            <motion.h1
              className="text-5xl md:text-6xl font-bold leading-tight tracking-tight text-foreground"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2, duration: 0.7 }}
            >
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.12, rotate: [0, -4, 4, 0] }}
                transition={{ duration: 0.3 }}
              >
                L
              </motion.span>
              <span>iving off the </span>
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.12, rotate: [0, 4, -4, 0] }}
                transition={{ duration: 0.3 }}
              >
                O
              </motion.span>
              <span>rchard</span>
              <span className="block text-3xl md:text-4xl mt-2 text-muted-foreground font-medium tracking-normal">
                <motion.span
                  className="inline-block text-primary"
                  whileHover={{ scale: 1.12, rotate: [0, -4, 4, 0] }}
                  transition={{ duration: 0.3 }}
                >
                  A
                </motion.span>
                pple{" "}
                <motion.span
                  className="inline-block text-primary"
                  whileHover={{ scale: 1.12, rotate: [0, 4, -4, 0] }}
                  transition={{ duration: 0.3 }}
                >
                  S
                </motion.span>
                cript
              </span>
            </motion.h1>

            {/* Description */}
            <motion.p
              className="text-lg text-muted-foreground leading-relaxed max-w-2xl mx-auto"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4, duration: 0.7 }}
            >
              A curated library of{" "}
              <span className="text-foreground font-semibold">AppleScript</span>{" "}
              and <span className="text-foreground font-semibold">JXA</span>{" "}
              atomic tests mapped to the{" "}
              <span className="text-foreground font-semibold">
                MITRE ATT&amp;CK®
              </span>{" "}
              framework — helping security teams test and validate macOS
              defenses.
            </motion.p>

            {/* CTA Buttons */}
            <motion.div
              className="flex flex-wrap items-center justify-center gap-4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5, duration: 0.6 }}
            >
              <Link
                href="/docs"
                className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-primary text-primary-foreground font-medium text-sm hover:opacity-90 transition-opacity"
              >
                Browse Scripts
                <Terminal className="w-4 h-4" />
              </Link>
              <a
                href="https://github.com/cyberbuff/loas"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg border border-border bg-card text-foreground font-medium text-sm hover:bg-muted transition-colors"
              >
                View on GitHub
                <svg
                  className="w-4 h-4"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
                </svg>
              </a>
            </motion.div>
          </motion.div>

          {/* Stats Cards */}
          <motion.div
            className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-3xl mx-auto mt-16"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.65, duration: 0.7 }}
          >
            {statItems.map((stat, i) => {
              const Icon = stat.icon;
              return (
                <motion.div
                  key={stat.label}
                  className="bg-card/60 backdrop-blur-sm border border-border rounded-xl p-6 text-center hover:border-primary/40 transition-colors group"
                  whileHover={{ y: -2 }}
                  transition={{ duration: 0.2 }}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  // stagger via transition delay
                  style={{ transitionDelay: `${0.7 + i * 0.1}s` }}
                >
                  <div className="flex justify-center mb-3">
                    <div className="p-2 rounded-lg bg-primary/10 group-hover:bg-primary/15 transition-colors">
                      <Icon className="w-5 h-5 text-primary" />
                    </div>
                  </div>
                  <div className="text-3xl font-bold text-foreground tabular-nums">
                    {stat.value}
                  </div>
                  <div className="text-sm font-medium text-foreground mt-1">
                    {stat.label}
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">
                    {stat.sublabel}
                  </div>
                </motion.div>
              );
            })}
          </motion.div>
        </div>
      </div>

      {/* Database Section */}
      <div className="container mx-auto px-4 py-12">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9, duration: 0.7 }}
        >
          <div className="mb-6 flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2.5 mb-1">
                <motion.div
                  className="w-2 h-2 bg-primary rounded-full"
                  animate={{ opacity: [0.4, 1, 0.4] }}
                  transition={{ duration: 2, repeat: Number.POSITIVE_INFINITY }}
                />
                <h2 className="text-xl font-semibold text-foreground">
                  Script Database
                </h2>
              </div>
              <p className="text-sm text-muted-foreground ml-4">
                {scripts.length} scripts across {uniqueTechniques} ATT&amp;CK
                techniques
              </p>
            </div>
          </div>

          <div className="bg-card border border-border rounded-xl overflow-hidden">
            <div className="p-6">
              <DataTableWithFilters columns={columns} data={scripts} />
            </div>
          </div>
        </motion.div>
      </div>
    </main>
  );
}
