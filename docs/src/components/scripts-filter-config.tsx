"use client";

import { Code, FileText, Shield, Target } from "lucide-react";
import { createColumnConfigHelper } from "@/components/data-table-filter/core/filters";
import type { Script } from "./scripts-columns";

// Create the configuration builder instance
const dtf = createColumnConfigHelper<Script>();

// Create the column configurations for filtering
export const columnsConfig = [
	dtf
		.text()
		.id("name")
		.accessor((row) => row.name)
		.displayName("Script Name")
		.icon(FileText)
		.build(),
	dtf
		.text()
		.id("technique_id")
		.accessor((row) => row.technique_id)
		.displayName("Technique ID")
		.icon(Target)
		.build(),
	dtf
		.text()
		.id("technique_name")
		.accessor((row) => row.technique_name)
		.displayName("Technique")
		.icon(Target)
		.build(),
	dtf
		.option()
		.id("language")
		.accessor((row) => row.language)
		.displayName("Language")
		.icon(Code)
		.options([
			{ label: "AppleScript", value: "AppleScript" },
			{ label: "JavaScript", value: "JavaScript" },
		])
		.build(),
	dtf
		.option()
		.id("elevation_required")
		.accessor((row) => row.elevation_required.toString())
		.displayName("Elevation Required")
		.icon(Shield)
		.options([
			{ label: "Required", value: "true" },
			{ label: "Not Required", value: "false" },
		])
		.build(),
	dtf
		.option()
		.id("tcc_required")
		.accessor((row) => row.tcc_required.toString())
		.displayName("TCC Required")
		.icon(Shield)
		.options([
			{ label: "Required", value: "true" },
			{ label: "Not Required", value: "false" },
		])
		.build(),
] as const;
