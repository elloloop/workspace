// Single source of truth for the documentation nav. Used by:
//   - the sidebar (rendered in DocsLayout)
//   - breadcrumbs
//   - prev/next links at the bottom of every page
//
// Keep `href` paths in sync with the file paths under src/pages/.

export interface NavItem {
  label: string;
  href: string;
}

export interface NavSection {
  title: string;
  items: NavItem[];
}

export const BASE = "/workspace";

export const sidebarSections: NavSection[] = [
  {
    title: "Getting Started",
    items: [
      { label: "Overview", href: `${BASE}/` },
      { label: "Introduction", href: `${BASE}/docs/introduction` },
      { label: "Quick Start", href: `${BASE}/docs/quickstart` },
    ],
  },
  {
    title: "Concepts",
    items: [
      { label: "Authorization Model", href: `${BASE}/docs/concepts/authorization-model` },
      { label: "Workspaces & Groups", href: `${BASE}/docs/concepts/workspaces-and-groups` },
      { label: "Projects & Multi-Tenancy", href: `${BASE}/docs/concepts/projects` },
      { label: "Security & Service Auth", href: `${BASE}/docs/concepts/security` },
    ],
  },
  {
    title: "Modeling Guides",
    items: [
      { label: "Roles & RBAC", href: `${BASE}/docs/guides/roles-and-rbac` },
      { label: "Groups & Nesting", href: `${BASE}/docs/guides/groups-and-nesting` },
      { label: "Hierarchies & Inheritance", href: `${BASE}/docs/guides/hierarchies-and-inheritance` },
      { label: "Sharing Resources", href: `${BASE}/docs/guides/sharing` },
      { label: "Check & Expand", href: `${BASE}/docs/guides/check-and-expand` },
    ],
  },
  {
    title: "Examples",
    items: [
      { label: "Workplace Collaboration Tool", href: `${BASE}/docs/examples/workplace-collaboration` },
      { label: "Learning Platform", href: `${BASE}/docs/examples/learning-platform` },
      { label: "Personal-Assistant App", href: `${BASE}/docs/examples/personal-assistant` },
    ],
  },
  {
    title: "API Reference",
    items: [
      { label: "Using the API", href: `${BASE}/docs/api-reference/overview` },
      { label: "Proto Reference", href: `${BASE}/proto/` },
      { label: "Live API Reference", href: `${BASE}/api` },
    ],
  },
  {
    title: "Operations",
    items: [
      { label: "Configuration", href: `${BASE}/docs/installation/configuration` },
      { label: "Deploy with Docker", href: `${BASE}/docs/deployment/docker` },
      { label: "Health & Metrics", href: `${BASE}/docs/operations/observability` },
    ],
  },
  {
    title: "Architecture Decisions",
    items: [
      { label: "ADR-0001 · Relation Tuples", href: `${BASE}/docs/adr/0001-relation-tuples-as-the-authz-primitive` },
      { label: "ADR-0002 · Personal & Team Workspaces", href: `${BASE}/docs/adr/0002-personal-and-team-workspaces` },
      { label: "ADR-0003 · Groups Separate from Workspaces", href: `${BASE}/docs/adr/0003-groups-separate-from-workspaces` },
    ],
  },
];

// Flat ordered list with section labels — drives breadcrumbs and prev/next.
export interface FlatNavItem extends NavItem {
  section: string;
}

export const flatNav: FlatNavItem[] = sidebarSections.flatMap((section) =>
  section.items.map((item) => ({ ...item, section: section.title })),
);

// Normalize a path to match how `href` is defined above (strip trailing slash,
// keep root as just the BASE).
function normalize(p: string): string {
  if (!p) return p;
  if (p === BASE || p === `${BASE}/`) return `${BASE}/`;
  return p.replace(/\/+$/, "");
}

export function findCurrent(currentPath: string): FlatNavItem | undefined {
  const target = normalize(currentPath);
  return flatNav.find(
    (item) => normalize(item.href) === target || item.href === target,
  );
}

export function findPrevNext(currentPath: string): {
  prev?: FlatNavItem;
  next?: FlatNavItem;
} {
  const target = normalize(currentPath);
  const idx = flatNav.findIndex(
    (item) => normalize(item.href) === target || item.href === target,
  );
  if (idx === -1) return {};
  return {
    prev: idx > 0 ? flatNav[idx - 1] : undefined,
    next: idx < flatNav.length - 1 ? flatNav[idx + 1] : undefined,
  };
}

export function buildBreadcrumbs(
  currentPath: string,
): { label: string; href?: string }[] {
  const current = findCurrent(currentPath);
  const docsRoot = { label: "Docs", href: `${BASE}/` };
  if (!current) return [docsRoot];
  // Root overview page — just "Docs".
  if (current.href === `${BASE}/`) return [docsRoot];
  return [
    docsRoot,
    { label: current.section },
    { label: current.label },
  ];
}
