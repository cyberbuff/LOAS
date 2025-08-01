"use client";

import {
  type ColumnDef,
  type ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  type SortingState,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import { ChevronDown } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import {
  DataTableFilter,
  useDataTableFilters,
} from "@/components/data-table-filter";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Script } from "./scripts-columns";
import { columnsConfig } from "./scripts-filter-config";

interface DataTableWithFiltersProps<TData, TValue> {
  columns: ColumnDef<TData, TValue>[];
  data: TData[];
}

// Simple client-side filtering function
function applyFilters<T>(data: T[], filters: any[], columns: any[]): T[] {
  if (filters.length === 0) return data;

  return data.filter((row) => {
    return filters.every((filter) => {
      const column = columns.find((col) => col.id === filter.columnId);
      if (!column) return true;

      const value = column.accessor(row);
      const filterValues = filter.values;

      switch (filter.type) {
        case "text": {
          const textValue = String(value).toLowerCase();
          const searchTerm = String(filterValues[0] || "").toLowerCase();
          if (filter.operator === "contains") {
            return textValue.includes(searchTerm);
          }
          if (filter.operator === "does not contain") {
            return !textValue.includes(searchTerm);
          }
          return true;
        }

        case "option": {
          const stringValue = String(value);
          if (filter.operator === "is") {
            return filterValues.includes(stringValue);
          }
          if (filter.operator === "is not") {
            return !filterValues.includes(stringValue);
          }
          if (filter.operator === "is any of") {
            return filterValues.includes(stringValue);
          }
          if (filter.operator === "is none of") {
            return !filterValues.includes(stringValue);
          }
          return true;
        }

        default:
          return true;
      }
    });
  });
}

export function DataTableWithFilters<TData, TValue>({
  columns,
  data,
}: DataTableWithFiltersProps<TData, TValue>) {
  const router = useRouter();
  const [sorting, setSorting] = React.useState<SortingState>([
    {
      id: "technique_id",
      desc: false,
    },
  ]);
  const [columnFilters, setColumnFilters] = React.useState<ColumnFiltersState>(
    [],
  );
  const [columnVisibility, setColumnVisibility] =
    React.useState<VisibilityState>({
      technique_name: false,
    });
  const [rowSelection, setRowSelection] = React.useState({});

  // Create the data table filters instance
  const {
    columns: filterColumns,
    filters,
    actions,
    strategy,
  } = useDataTableFilters({
    strategy: "client",
    data: data as Script[],
    columnsConfig,
  });

  // Apply filters to data
  const filteredData = React.useMemo(() => {
    return applyFilters(data, filters, filterColumns);
  }, [data, filters, filterColumns]);

  const table = useReactTable({
    data: filteredData,
    columns,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    state: {
      sorting,
      columnFilters,
      columnVisibility,
      rowSelection,
    },
  });

  // Calculate pagination info
  const pageCount = table.getPageCount();
  const currentPage = table.getState().pagination.pageIndex + 1;
  const pageSize = table.getState().pagination.pageSize;

  // Generate page numbers to display
  const getVisiblePages = () => {
    const delta = 2;
    const range = [];
    const rangeWithDots = [];

    for (
      let i = Math.max(2, currentPage - delta);
      i <= Math.min(pageCount - 1, currentPage + delta);
      i++
    ) {
      range.push(i);
    }

    if (currentPage - delta > 2) {
      rangeWithDots.push(1, "...");
    } else {
      rangeWithDots.push(1);
    }

    rangeWithDots.push(...range);

    if (currentPage + delta < pageCount - 1) {
      rangeWithDots.push("...", pageCount);
    } else if (pageCount > 1) {
      rangeWithDots.push(pageCount);
    }

    return rangeWithDots;
  };

  // Function to handle row click and navigate to technique documentation
  const handleRowClick = React.useCallback(
    (row: any) => {
      const script = row.original as Script;
      const techniqueId = script.technique_id;
      const _techniqueName = script.technique_name;

      // Convert technique name to URL-friendly anchor format
      const anchor = script.name
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, "") // Remove special characters except spaces and hyphens
        .replace(/\s+/g, "-") // Replace spaces with hyphens
        .replace(/-+/g, "-") // Replace multiple hyphens with single hyphen
        .replace(/^-|-$/g, ""); // Remove leading/trailing hyphens

      // Navigate to the technique documentation page
      const url = `/docs/${techniqueId}#test-${script.test_number}---${anchor}`;
      router.push(url);
    },
    [router],
  );

  return (
    <div className="w-full">
      <div className="flex items-center py-4">
        <div className="flex-1">
          <DataTableFilter
            columns={filterColumns}
            filters={filters}
            actions={actions}
            strategy={strategy}
          />
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" className="ml-4">
              Columns <ChevronDown className="ml-2 h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {table
              .getAllColumns()
              .filter((column) => column.getCanHide())
              .map((column) => {
                return (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    className="capitalize"
                    checked={column.getIsVisible()}
                    onCheckedChange={(value) =>
                      column.toggleVisibility(!!value)
                    }
                  >
                    {column.id === "technique_id"
                      ? "Technique ID"
                      : column.id === "technique_name"
                        ? "Technique Name"
                        : column.id === "elevation_required"
                          ? "Elevation Required"
                          : column.id === "tcc_required"
                            ? "TCC Required"
                            : column.id.charAt(0).toUpperCase() +
                              column.id.slice(1)}
                  </DropdownMenuCheckboxItem>
                );
              })}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => {
                  return (
                    <TableHead key={header.id}>
                      {header.isPlaceholder
                        ? null
                        : flexRender(
                            header.column.columnDef.header,
                            header.getContext(),
                          )}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  data-state={row.getIsSelected() && "selected"}
                  onClick={() => handleRowClick(row)}
                  className="cursor-pointer hover:bg-muted/50 transition-colors"
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center"
                >
                  No results.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <div className="flex items-center justify-between space-x-2 py-4">
        <div className="flex items-center space-x-2">
          <Select
            value={`${pageSize}`}
            onValueChange={(value) => {
              table.setPageSize(Number(value));
            }}
          >
            <SelectTrigger className="h-8 w-auto min-w-[140px] border-none  px-0 font-normal shadow-none focus:ring-0">
              <span className="text-sm text-muted-foreground">
                Rows per page:
              </span>
              <SelectValue className="ml-2 font-medium" />
            </SelectTrigger>
            <SelectContent side="top">
              {[10, 20, 30, 40, 50].map((size) => (
                <SelectItem key={size} value={`${size}`}>
                  {size}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {pageCount > 1 && (
          <Pagination>
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  onClick={() => table.previousPage()}
                  className={
                    !table.getCanPreviousPage()
                      ? "pointer-events-none opacity-50"
                      : "cursor-pointer"
                  }
                />
              </PaginationItem>

              {getVisiblePages().map((page, index) => (
                <PaginationItem key={index}>
                  {page === "..." ? (
                    <PaginationEllipsis />
                  ) : (
                    <PaginationLink
                      onClick={() => table.setPageIndex(Number(page) - 1)}
                      isActive={currentPage === page}
                      className="cursor-pointer"
                    >
                      {page}
                    </PaginationLink>
                  )}
                </PaginationItem>
              ))}

              <PaginationItem>
                <PaginationNext
                  onClick={() => table.nextPage()}
                  className={
                    !table.getCanNextPage()
                      ? "pointer-events-none opacity-50"
                      : "cursor-pointer"
                  }
                />
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        )}
      </div>
    </div>
  );
}
