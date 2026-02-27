// Asset / Scan domain types
export type AssetType = "domain" | "ip" | "email" | "cloud";
export type ScanStatus =
  | "not_scanned"
  | "queued"
  | "running"
  | "completed"
  | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

// M7: Finding categories from the detection engine
export type FindingCategory =
  | "ssl"
  | "ports"
  | "headers"
  | "cve"
  | "dns"
  | "tech"
  | "exposure"
  | "misconfiguration"
  | "vulnerability"
  | "cloud"
  | "other";

// Cloud asset sub-types
export type CloudCategory = "storage" | "registry" | "serverless" | "cdn";

// --------------------
// Asset Groups
// --------------------
export interface AssetGroup {
  id: string;
  name: string;
  assetCount: number;
  ipCount: number;
  domainCount: number;
  emailCount: number;
  cloudCount: number;
  createdAt: Date;
}
// --------------------
// Assets
// --------------------
export interface Asset {
  id: string;
  groupId: string;
  type: AssetType;
  value: string;
  label?: string;
  status: ScanStatus;
  lastScan?: Date;
  lastScanAt?: Date;
  latestScanId?: string;
  severity?: Severity;
  // Cloud asset fields
  provider?: string | null;
  cloudCategory?: CloudCategory | null;
}
// --------------------
// Scan Results
// --------------------
export interface ScanResult {
  id: string;
  assetId: string;
  status: "completed" | "failed";
  timestamp: Date;
  summary: string;
  details?: string;
  severity?: Severity;
  findingsCount?: number;
}
// --------------------
// Findings
// --------------------
export interface Finding {
  id: string;
  assetId: string;
  assetValue: string;
  assetType: AssetType;
  groupId: string;
  groupName?: string;
  severity: Severity;
  title: string;
  description: string;
  detectedAt: Date;
  status: "open" | "suppressed" | "resolved";
  resolved: boolean;
  resolvedAt?: Date | string | null;
  resolvedBy?: string | null;
  resolvedReason?: string | null;

  // M7: Enrichment fields from the detection engine
  category?: FindingCategory;
  remediation?: string;
  cwe?: string;
  confidence?: "high" | "medium" | "low";
  tags?: string[];
  engine?: string;
  analyzer?: string;
  templateId?: string;

  // Legacy / backwards compat
  cve?: string;
  cvssScore?: number;
  affectedComponent?: string;
  recommendations?: string[];
  remediationSteps?: string[];
  references?: string[];
  technicalDetails?: string;

  ignored?: boolean;
  ignoredAt?: Date;
  ignoredReason?: string;
  details?: any;
  scanJobId?: string;
}

// M7: Exposure score from the exposure_scorer analyzer
export interface ExposureScore {
  exposureScore: number;
  grade: string;
  gradeDescription: string;
  totalFindings: number;
  actionableFindings: number;
  severityCounts: Record<string, number>;
  categoryBreakdown: Record<string, {
    count: number;
    score: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  topIssues: Array<{
    title: string;
    severity: string;
    category: string;
    templateId: string;
  }>;
}

// --------------------
// Scan Jobs
// --------------------
export type JobStatus = "queued" | "running" | "completed" | "failed";
export interface ScanJob {
  id: string;
  assetId: string;
  assetValue: string;
  assetType: AssetType;
  groupId: string;
  groupName?: string;
  status: JobStatus;
  timeStarted: Date;
  timeCompleted?: Date;
  errorMessage?: string;
  // M3: Profile & Schedule support
  profileId?: string;
  profileName?: string;
  scheduleId?: string;
}
// --------------------
// Scan Profiles (M3)
// --------------------
export interface ScanProfile {
  id: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  isDefault: boolean;
  isActive: boolean;
  // Engine flags
  useShodan: boolean;
  useNmap: boolean;
  useNuclei: boolean;
  useSslyze: boolean;
  // Shodan settings
  shodanIncludeHistory: boolean;
  shodanIncludeCves: boolean;
  shodanIncludeDns: boolean;
  // Nmap settings
  nmapScanType: string | null;
  nmapPortRange: string | null;
  // Nuclei settings
  nucleiSeverityFilter: string | null;
  nucleiTemplates: string[] | null;
  // General
  timeoutSeconds: number;
  createdAt: string | null;
}
// --------------------
// Scan Schedules (M3)
// --------------------
export type ScheduleFrequency = "daily" | "weekly" | "monthly";
export interface ScanSchedule {
  id: string;
  scheduleType: "asset" | "group";
  assetId: string | null;
  assetValue?: string;
  assetType?: AssetType;
  groupId?: string;
  groupName?: string;
  profileId: string | null;
  profileName?: string;
  name: string | null;
  frequency: ScheduleFrequency;
  timeOfDay: string; // "HH:MM"
  dayOfWeek: number | null; // 0-6, 0=Monday
  dayOfMonth: number | null; // 1-31
  enabled: boolean;
  lastRunAt: string | null;
  nextRunAt: string | null;
  lastScanJobId: string | null;
  createdAt: string;
  updatedAt: string;
}

// --------------------
// Billing & Plans (M9)
// --------------------
export type PlanTier = "free" | "starter" | "professional" | "enterprise_silver" | "enterprise_gold";
export type PlanStatus = "active" | "trialing" | "cancelled" | "past_due" | "expired";
export type BillingCycle = "monthly" | "annual";

export interface PlanLimits {
  assets: number;
  scansPerMonth: number;
  teamMembers: number;
  scheduledScans: number;
  apiKeys: number;
  scanProfiles: string[];
  monitoring: boolean;
  monitoringFrequency: string | null;
  deepDiscovery: boolean;
  webhooks: boolean;
}

export interface PlanUsage {
  assets: number;
  scansThisMonth: number;
  teamMembers: number;
  scheduledScans: number;
  apiKeys: number;
}

export interface TrialInfo {
  plan: string;
  endsAt: string;
  daysRemaining: number;
  expired: boolean;
}

export interface BillingInfo {
  plan: PlanTier;
  planLabel: string;
  planStatus: PlanStatus;
  billingCycle: BillingCycle | null;
  planStartedAt: string | null;
  planExpiresAt: string | null;
  trial: TrialInfo | null;
  trialedTiers: string[];
  limits: PlanLimits;
  usage: PlanUsage;
  pricing: {
    monthly: number;
    annualMonthly: number;
    annualTotal: number;
  };
}

export interface PlanOption {
  key: PlanTier;
  label: string;
  priceMonthly: number;
  priceAnnualMonthly: number;
  priceAnnualTotal: number;
  trialDays: number;
  trialRequiresApproval: boolean;
  canTrial: boolean;
  isCurrent: boolean;
  limits: PlanLimits;
}