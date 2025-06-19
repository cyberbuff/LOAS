"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { ArrowUpDown, CircleCheckBig, CircleMinus, Code } from "lucide-react";
import { Button } from "@/components/ui/button";

export type Script = {
	name: string;
	command: string;
	language: "AppleScript" | "JavaScript";
	elevation_required: boolean;
	tcc_required: boolean;
	technique_id: string;
	technique_name: string;
	test_number: number;
};

export const columns: ColumnDef<Script>[] = [
	{
		accessorKey: "technique_id",
		header: ({ column }) => {
			return (
				<Button
					variant="ghost"
					onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
					className="h-auto p-0 font-medium"
				>
					Technique ID
					<ArrowUpDown className="ml-2 h-4 w-4" />
				</Button>
			);
		},
		cell: ({ row }) => {
			return (
				<div className="font-mono text-sm">{row.getValue("technique_id")}</div>
			);
		},
	},
	{
		accessorKey: "technique_name",
		header: "Technique",
		enableHiding: true,
		meta: {
			isHidden: true,
		},
		cell: ({ row }) => {
			return (
				<div
					className="max-w-[300px] truncate"
					title={row.getValue("technique_name")}
				>
					{row.getValue("technique_name")}
				</div>
			);
		},
	},
	{
		accessorKey: "name",
		header: ({ column }) => {
			return (
				<Button
					variant="ghost"
					onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
					className="h-auto p-0 font-medium"
				>
					Script Name
					<ArrowUpDown className="ml-2 h-4 w-4" />
				</Button>
			);
		},
		cell: ({ row }) => {
			return <div className="font-medium">{row.getValue("name")}</div>;
		},
	},
	{
		accessorKey: "language",
		header: ({ column }) => {
			return (
				<Button
					variant="ghost"
					onClick={() => column.toggleSorting(column.getIsSorted() === "asc")}
					className="h-auto p-0 font-medium"
				>
					Language
					<ArrowUpDown className="ml-2 h-4 w-4" />
				</Button>
			);
		},
		cell: ({ row }) => {
			const language = row.getValue("language") as string;
			return (
				<div className="flex items-center gap-2">
					<Code className="h-4 w-4" />
					<span className="font-mono text-sm">{language}</span>
				</div>
			);
		},
	},
	{
		accessorKey: "elevation_required",
		header: "Elevation",
		cell: ({ row }) => {
			const elevationRequired = row.getValue("elevation_required") as boolean;
			return (
				<div className="flex items-center gap-2">
					{elevationRequired ? (
						<>
							<CircleCheckBig className="h-4 w-4 text-green-500" />
						</>
					) : (
						<>
							<CircleMinus className="h-4 w-4 text-red-500" />
						</>
					)}
				</div>
			);
		},
	},
	{
		accessorKey: "tcc_required",
		header: "TCC",
		cell: ({ row }) => {
			const tccRequired = row.getValue("tcc_required") as boolean;
			return (
				<div className="flex items-center gap-2">
					{tccRequired ? (
						<>
							<CircleCheckBig className="h-4 w-4 text-green-500" />
						</>
					) : (
						<>
							<CircleMinus className="h-4 w-4 text-red-500" />
						</>
					)}
				</div>
			);
		},
	},
];
