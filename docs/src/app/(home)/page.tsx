import { AnimatedHomepage } from "@/components/animated-homepage";
import type { Script } from "@/components/scripts-columns";

async function getScripts(): Promise<Script[]> {
  try {
    // In a real app, you might fetch from an API
    // For now, we'll import the JSON directly
    const scripts = await import("../../../public/api/scripts.json");
    return scripts.default as Script[];
  } catch (error) {
    console.error("Failed to load scripts data:", error);
    return [];
  }
}

function getUniqueCount<T>(items: T[], key: keyof T): number {
  const unique = new Set(items.map((item) => item[key]));
  return unique.size;
}

export default async function HomePage() {
  const scripts = await getScripts();
  const uniqueTechniques = getUniqueCount(scripts, "technique_id");

  return (
    <AnimatedHomepage scripts={scripts} uniqueTechniques={uniqueTechniques} />
  );
}
