import { createMDX } from "fumadocs-mdx/next";

const withMDX = createMDX();

/** @type {import('next').NextConfig} */
const config = {
	reactStrictMode: true,
	publicRuntimeConfig: {
		appVersion: process.env.APP_VERSION || "0.1.4",
	},
};

export default withMDX(config);
