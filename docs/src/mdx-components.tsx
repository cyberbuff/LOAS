import * as TabsComponents from "fumadocs-ui/components/tabs";
import defaultMdxComponents from "fumadocs-ui/mdx";
import { Code, Terminal } from "lucide-react";
import type { MDXComponents } from "mdx/types";
import DownloadButton from "./components/DownloadButton";

// use this function to get MDX components, you will need it for rendering MDX
export function getMDXComponents(components?: MDXComponents): MDXComponents {
	return {
		...defaultMdxComponents,
		...TabsComponents,
		// Lucide icons
		Code,
		Terminal,
		DownloadButton,
		...components,
	};
}
