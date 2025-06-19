import { DataTableWithFilters } from "@/components/data-table-with-filters";
import { columns, type Script } from "@/components/scripts-columns";

async function getScripts(): Promise<Script[]> {
	try {
		// In a real app, you might fetch from an API
		// For now, we'll import the JSON directly
		const scripts = await import("../../../public/data/scripts.json");
		return scripts.default as Script[];
	} catch (error) {
		console.error("Failed to load scripts data:", error);
		return [];
	}
}

export default async function HomePage() {
	const scripts = await getScripts();

	return (
		<main className="container mx-auto py-8">
			<div className="mb-8 text-center">
				<h1 className="mb-4 text-3xl font-bold">
					Living off the Orchard: Apple Script
				</h1>
				<p className="text-fd-muted-foreground text-lg max-w-3xl mx-auto">
					<b>L</b>iving off the <b>O</b>rchard: <b>A</b>pple <b>S</b>cript is
					designed to provide detailed information on various
					scripts(AppleScript, JXA) and how they are being used by threat actors
					for malicious purposes.
				</p>
			</div>

			<div className="mb-4">
				<h2 className="text-xl font-semibold mb-2">Script Database</h2>
				<p className="text-sm text-muted-foreground mb-4">
					Browse and search through {scripts.length} available scripts across
					different techniques.
				</p>
			</div>

			<DataTableWithFilters columns={columns} data={scripts} />
		</main>
	);
}
