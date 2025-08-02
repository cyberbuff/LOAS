"use client";

import { motion } from "motion/react";
import { DataTableWithFilters } from "@/components/data-table-with-filters";
import { columns, type Script } from "@/components/scripts-columns";
import Link from "next/link";
import type { ReactNode } from "react";
import { CircleQuestionMark } from "lucide-react";

interface AnimatedHomepageProps {
  scripts: Script[];
  uniqueTechniques: number;
}

function Badge({
  href,
  text,
  icon,
}: {
  href: string;
  text: string;
  icon: ReactNode;
}) {
  return (
    <Link href={href}>
      <motion.div
        className="inline-flex items-center px-4 py-2 rounded-full bg-muted border border-border mb-8"
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.2, duration: 0.6 }}
      >
        <span className="text-lg mr-2">{icon}</span>
        <span className="text-muted-foreground font-medium text-sm">
          {text}
        </span>
      </motion.div>
    </Link>
  );
}

export function AnimatedHomepage({
  scripts,
  uniqueTechniques,
}: AnimatedHomepageProps) {
  return (
    <main className="min-h-screen bg-background">
      <div className="container mx-auto py-12 relative z-10">
        {/* Hero Section */}
        <motion.div
          className="mb-16 text-center space-y-8"
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <Badge
            href="/docs/T1005"
            text="AppleScript Collection ->"
            icon="🍎"
          />

          {/* Title */}
          <div className="relative">
            <motion.h1
              className="text-4xl md:text-5xl font-bold leading-tight text-foreground"
              initial={{ opacity: 0, y: 30 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4, duration: 0.8 }}
            >
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.1, rotate: [0, -5, 5, 0] }}
                transition={{ duration: 0.3 }}
              >
                L
              </motion.span>
              <span>iving off the </span>
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.1, rotate: [0, 5, -5, 0] }}
                transition={{ duration: 0.3 }}
              >
                O
              </motion.span>
              <span>rchard: </span>
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.1, rotate: [0, -5, 5, 0] }}
                transition={{ duration: 0.3 }}
              >
                A
              </motion.span>
              <span>pple </span>
              <motion.span
                className="inline-block text-primary"
                whileHover={{ scale: 1.1, rotate: [0, 5, -5, 0] }}
                transition={{ duration: 0.3 }}
              >
                S
              </motion.span>
              <span>cript</span>
            </motion.h1>
          </div>

          <motion.div
            className="max-w-4xl mx-auto"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.8 }}
          >
            <p className="text-lg text-muted-foreground leading-relaxed">
              A comprehensive database documenting how{" "}
              <span className="font-semibold text-primary">AppleScript</span>{" "}
              and <span className="font-semibold text-primary">JXA</span> are
              leveraged by threat actors for malicious purposes.
            </p>
          </motion.div>

          {/* Stats Cards */}
          <motion.div
            className="grid grid-cols-3 gap-6 max-w-2xl mx-auto"
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8, duration: 0.8 }}
          >
            <motion.div
              className="bg-card border border-border rounded-lg p-6 hover:border-border/60 transition-colors"
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.2 }}
            >
              <motion.div
                className="text-2xl font-bold text-primary mb-1"
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                2
              </motion.div>
              <div className="text-sm text-muted-foreground">Script Types</div>
            </motion.div>

            <motion.div
              className="bg-card border border-border rounded-lg p-6 hover:border-border/60 transition-colors"
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.2 }}
            >
              <motion.div
                className="text-2xl font-bold text-primary mb-1"
                animate={{ y: [0, -2, 0] }}
                transition={{ duration: 1.5, repeat: Infinity }}
              >
                {uniqueTechniques}
              </motion.div>
              <div className="text-sm text-muted-foreground">
                ATT&CK Techniques
              </div>
            </motion.div>

            <motion.div
              className="bg-card border border-border rounded-lg p-6 hover:border-border/60 transition-colors"
              whileHover={{ scale: 1.02 }}
              transition={{ duration: 0.2 }}
            >
              <motion.div
                className="text-2xl font-bold text-primary mb-1"
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 2.5, repeat: Infinity }}
              >
                {scripts.length}
              </motion.div>
              <div className="text-sm text-muted-foreground">Scripts</div>
            </motion.div>
          </motion.div>
        </motion.div>

        {/* Database Section */}
        <motion.div
          className="bg-card border border-border rounded-xl overflow-hidden"
          initial={{ opacity: 0, y: 50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 1, duration: 0.8 }}
        >
          <div className="px-8 py-6 border-b border-border">
            <div className="flex items-center gap-3 mb-2">
              <motion.div
                className="w-2 h-2 bg-primary rounded-full"
                animate={{ opacity: [0.5, 1, 0.5] }}
                transition={{ duration: 2, repeat: Infinity }}
              />
              <h2 className="text-2xl font-semibold text-foreground">
                Script Database
              </h2>
            </div>
            <p className="text-muted-foreground">
              Explore our curated collection of {scripts.length} scripts
            </p>
          </div>
          <div className="p-8">
            <DataTableWithFilters columns={columns} data={scripts} />
          </div>
        </motion.div>
      </div>
    </main>
  );
}
