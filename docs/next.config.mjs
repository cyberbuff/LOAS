import { createMDX } from "fumadocs-mdx/next";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const packageJson = JSON.parse(readFileSync(join(__dirname, "package.json"), "utf8"));
const { version } = packageJson;

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
	reactStrictMode: true,
	publicRuntimeConfig: {
		version,
	},
};

export default withMDX(config);
