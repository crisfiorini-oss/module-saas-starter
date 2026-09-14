#!/usr/bin/env node
// interface-docs-gate — the readability bar on the published interface.
//
// The normalized service catalog is the artifact an external documentation
// renderer reads to describe this module's interface to a non-engineer, and
// each operation's `description` is the sentence it prints. The catalog
// compiler already fails closed on an *absent* description, which stops an
// undocumented operation from shipping but not an unreadable one: "Delete
// one." and "JSONB user prefs." both satisfy "non-empty" and neither says what
// the operation does.
//
// This gate is the second half of that contract. It reads the committed
// catalog and holds every publicly exposed operation to a summary that stands
// on its own. Internal operations (EXPOSURE_INTERNAL) are never rendered
// externally, so they only have to be documented, not marketable.
//
// The rest of what item-by-item documentation would carry — who may call an
// operation, its limits, its rate class, its audit trail — is not prose here:
// it is the typed saas.policy.v1.MethodPolicy the compiler refuses to omit,
// and the buf.validate constraints on the request. Restating those in a
// comment would be a second source of truth that drifts.
//
//   node tools/interface-docs-gate.mjs check
//
// The module root is the parent of tools/, so this works identically in
// canonical's `module/` and a consumer's `modules/<name>/`.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const MODULE_ROOT = join(dirname(SCRIPT_PATH), "..");
const CATALOG_PATH = join(
  MODULE_ROOT,
  "services",
  "accounts",
  "generated",
  "service-catalog.json",
);

// An operation nobody outside the cluster can invoke is not part of the
// rendered interface.
const INTERNAL_EXPOSURE = "EXPOSURE_INTERNAL";

// The bounded context each operation belongs to. Protobuf services are an
// authoring unit, not a functional one: the external page groups the interface
// by what a reader is trying to do, and two of the services here deliberately
// span several of those groups. Assignment is exhaustive on purpose — a new
// service or a new module-facing capability has to be placed before it ships,
// because an operation nobody has placed is an operation nobody has described.
const SERVICE_CONTEXTS = {
  AccessibleScopeService: "authorization",
  APIKeyService: "identity",
  AuditService: "audit",
  AuthService: "identity",
  BillingService: "billing",
  ConsentService: "privacy",
  DashboardService: "dashboards",
  DatasourceService: "datasource",
  DelegationService: "authorization",
  GDPRService: "privacy",
  IdentityService: "identity",
  InstallationService: "authorization",
  IntrospectionService: "introspection",
  InvitationService: "tenancy",
  MFAService: "identity",
  NotificationService: "notifications",
  OnboardingService: "tenancy",
  OrganizationService: "tenancy",
  PermissionService: "authorization",
  PlatformAdminService: "platform administration",
  PrincipalService: "authorization",
  ResourceFollowService: "notifications",
  SSOAdminService: "identity",
  SolutionRegistryService: "platform administration",
  TeamService: "tenancy",
  UsageService: "entitlements",
  UserService: "identity",
  UserSettingsService: "identity",
  WaitlistService: "tenancy",
  WebhookService: "webhooks",
  WorkContextService: "authorization",
};

// ModuleCapabilitiesService is the whole module-facing spine behind one
// protobuf service, so every one of its methods is placed individually and it
// has no service-level default. PlatformAdminService keeps its default and
// only names the operations that belong to another context.
const METHOD_CONTEXTS = {
  "ModuleCapabilitiesService/AckJob": "jobs",
  "ModuleCapabilitiesService/CancelApproval": "approvals",
  "ModuleCapabilitiesService/ClaimJobs": "jobs",
  "ModuleCapabilitiesService/EmitAuditEvent": "audit",
  "ModuleCapabilitiesService/EnqueueJob": "jobs",
  "ModuleCapabilitiesService/FetchDatasourceBlob": "datasource",
  "ModuleCapabilitiesService/GetApproval": "approvals",
  "ModuleCapabilitiesService/HeartbeatJob": "jobs",
  "ModuleCapabilitiesService/ListReadableSourceCollections": "authorization",
  "ModuleCapabilitiesService/ListSubscriptions": "events",
  "ModuleCapabilitiesService/MintModuleRegistration": "authorization",
  "ModuleCapabilitiesService/MintModuleWorkContext": "authorization",
  "ModuleCapabilitiesService/MintSolutionRegistration": "authorization",
  "ModuleCapabilitiesService/NackJob": "jobs",
  "ModuleCapabilitiesService/NotifyUser": "notifications",
  "ModuleCapabilitiesService/PublishEvent": "events",
  "ModuleCapabilitiesService/ReplayEvents": "events",
  "ModuleCapabilitiesService/RequestApproval": "approvals",
  "ModuleCapabilitiesService/Subscribe": "events",
  "ModuleCapabilitiesService/Unsubscribe": "events",
  "PlatformAdminService/GetEventOperations": "events",
  "PlatformAdminService/GetJob": "jobs",
  "PlatformAdminService/GetJobOperations": "jobs",
  "PlatformAdminService/GetOrgEntitlements": "entitlements",
  "PlatformAdminService/ListEventSubscriptions": "events",
  "PlatformAdminService/ListJobs": "jobs",
  "PlatformAdminService/OverrideEntitlement": "entitlements",
  "PlatformAdminService/ReplayJob": "jobs",
};

export const boundedContextOf = (method) =>
  METHOD_CONTEXTS[`${method.service}/${method.method}`] ?? SERVICE_CONTEXTS[method.service];

// A summary this short is a verb with nothing attached: "Read branding." never
// says whose branding. Three words is where an operation can name an action and
// its object, so it is a floor on shape, not a target length — "Delete a team."
// is complete and passes, and no summary is improved by padding it out.
const MIN_SUMMARY_WORDS = 3;

// The other way to reach three words without naming anything: let a pronoun be
// the whole object. "Delete one." and "Mark all read." are the real failures
// here. The trailing-word allowance is what keeps this off "Delete one of the
// caller's notifications.", where the pronoun is a determiner and a real object
// follows it.
const PLACEHOLDER_OBJECT = /^\S+\s+(?:one|all|it|them|this|that|these|those)\b(?:\s+\w+)?[.]$/i;

// Long enough to say who and what, short enough that a renderer can put it in a
// table cell.
const MAX_SUMMARY_CHARACTERS = 200;

// Shorthand that reads as a signature rather than a sentence.
const ENGINEERING_SHORTHAND = /→|->|\bTODO\b|\bFIXME\b|\bXXX\b/;

// A summary that opens by declaring its own audience is addressed to the wrong
// reader: the catalog already carries exposure and policy machine-readably.
const AUDIENCE_PREFIX = /^(internal|deprecated|note)\b\s*:/i;

// The first sentence ends at the first period that starts a new sentence: one
// followed by whitespace and a capital, or by the end of the text. Requiring
// the capital is what keeps "e.g.", "i.e." and "cf." from truncating a
// description mid-clause and reporting the remainder as too short.
const summaryOf = (description) => {
  const match = description.match(/^[\s\S]*?[.](?=\s+[A-Z]|\s*$)/);
  return (match ? match[0] : description).trim();
};

// Every error this gate can raise, for one operation.
function operationErrors(method) {
  const procedure = method.procedure;
  const description = (method.description ?? "").trim();
  if (description === "") {
    return [`${procedure} has no description`];
  }

  const errors = [];
  if (boundedContextOf(method) === undefined) {
    errors.push(`${procedure} belongs to no bounded context; place it in interface-docs-gate.mjs`);
  }
  const internal = method.policy?.exposure === INTERNAL_EXPOSURE;
  if (!description.endsWith(".")) {
    errors.push(`${procedure} description does not end in a period`);
  }
  if (description[0] !== description[0].toUpperCase()) {
    errors.push(`${procedure} description does not start with a capital`);
  }
  if (internal) {
    return errors;
  }

  const summary = summaryOf(description);
  if (summary.split(/\s+/).length < MIN_SUMMARY_WORDS || PLACEHOLDER_OBJECT.test(summary)) {
    errors.push(
      `${procedure} summary does not name what it acts on: ${JSON.stringify(summary)}`,
    );
  }
  if (summary.length > MAX_SUMMARY_CHARACTERS) {
    errors.push(
      `${procedure} summary is over ${MAX_SUMMARY_CHARACTERS} characters; move the detail to a later sentence`,
    );
  }
  if (ENGINEERING_SHORTHAND.test(summary)) {
    errors.push(`${procedure} summary uses shorthand a non-engineer cannot read: ${JSON.stringify(summary)}`);
  }
  if (AUDIENCE_PREFIX.test(summary)) {
    errors.push(
      `${procedure} summary opens with an audience marker; exposure is already machine-readable in the catalog`,
    );
  }
  return errors;
}

// A summary reused verbatim across two operations describes neither: whichever
// one the reader landed on, the sentence is about some other operation too.
function duplicateSummaryErrors(methods) {
  const bySummary = new Map();
  for (const method of methods) {
    if (method.policy?.exposure === INTERNAL_EXPOSURE) {
      continue;
    }
    const summary = summaryOf((method.description ?? "").trim());
    if (summary === "") {
      continue;
    }
    const seen = bySummary.get(summary);
    if (seen) {
      seen.push(method.procedure);
      continue;
    }
    bySummary.set(summary, [method.procedure]);
  }
  return [...bySummary.entries()]
    .filter(([, procedures]) => procedures.length > 1)
    .map(([summary, procedures]) => `${procedures.join(" and ")} share the summary ${JSON.stringify(summary)}`);
}

export function interfaceDocsErrors(catalog) {
  const methods = catalog.methods ?? [];
  if (methods.length === 0) {
    return ["the service catalog carries no methods"];
  }
  return [...methods.flatMap(operationErrors), ...duplicateSummaryErrors(methods)].sort();
}

function check() {
  const catalog = JSON.parse(readFileSync(CATALOG_PATH, "utf8"));
  const errors = interfaceDocsErrors(catalog);
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(`error: ${error}`);
    }
    console.error(
      `\n${errors.length} undocumented or unreadable operation(s). Edit rpcDescriptions in` +
        " services/accounts/code/pkg/business/introspection.go and regenerate the catalog.",
    );
    process.exit(1);
  }
  const rendered = (catalog.methods ?? []).filter(
    (method) => method.policy?.exposure !== INTERNAL_EXPOSURE,
  ).length;
  console.log(`interface docs OK: ${rendered} public operations carry a readable summary`);
}

// The bounded contexts are enforced here, so this is where they are published:
// an external renderer that groups the interface by context reads them from
// this command rather than re-deriving a grouping the gate would not defend.
function contexts() {
  const catalog = JSON.parse(readFileSync(CATALOG_PATH, "utf8"));
  const grouped = {};
  for (const method of catalog.methods ?? []) {
    const context = boundedContextOf(method);
    (grouped[context] ??= []).push(method.procedure);
  }
  const ordered = {};
  for (const context of Object.keys(grouped).sort()) {
    ordered[context] = grouped[context].sort();
  }
  console.log(JSON.stringify(ordered, null, 2));
}

if (process.argv[1] === SCRIPT_PATH) {
  const command = process.argv[2];
  if (command === "check") {
    check();
  } else if (command === "contexts") {
    contexts();
  } else {
    console.error("usage: node tools/interface-docs-gate.mjs <check|contexts>");
    process.exit(2);
  }
}
