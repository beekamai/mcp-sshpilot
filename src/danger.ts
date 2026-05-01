export const DANGEROUS_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  { pattern: /\brm\s+(-[rRfF]+\s+)*[\/\*]/, reason: "Removing root/system files" },
  { pattern: /\brm\s+-[rRfF]*\s/, reason: "Recursive/forced removal" },
  { pattern: /\brmdir\b/, reason: "Directory removal" },
  { pattern: /\bmkfs\b/, reason: "Filesystem format" },
  { pattern: /\bdd\s+if=/, reason: "Low-level data copy (dd)" },
  { pattern: /\bfdisk\b/, reason: "Disk partitioning" },
  { pattern: /\bparted\b/, reason: "Disk partitioning" },
  { pattern: /\bshutdown\b/, reason: "System shutdown" },
  { pattern: /\breboot\b/, reason: "System reboot" },
  { pattern: /\binit\s+[06]\b/, reason: "Runlevel change" },
  { pattern: /\bsystemctl\s+(stop|disable|mask)\b/, reason: "Stopping/disabling services" },
  { pattern: /\bservice\s+\w+\s+stop\b/, reason: "Stopping a service" },
  { pattern: /\bchmod\s+[0-7]*7[0-7]*\b/, reason: "World-writable permissions" },
  { pattern: /\bchown\s+-R\b/, reason: "Recursive ownership change" },
  { pattern: /\buserdel\b/, reason: "User deletion" },
  { pattern: /\bgroupdel\b/, reason: "Group deletion" },
  { pattern: /\biptables\s+-F\b/, reason: "Firewall rules flush" },
  { pattern: /\bufw\s+disable\b/, reason: "Firewall disable" },
  { pattern: />\s*\/dev\/sd[a-z]/, reason: "Direct disk write" },
  { pattern: /\|\s*sh\b/, reason: "Pipe into shell (potentially unsafe)" },
  { pattern: /\|\s*bash\b/, reason: "Pipe into bash (potentially unsafe)" },
  { pattern: /\bapt\s+(remove|purge|autoremove)\b/, reason: "Package removal" },
  { pattern: /\byum\s+(remove|erase)\b/, reason: "Package removal" },
  { pattern: /\bdnf\s+(remove|erase)\b/, reason: "Package removal" },
  { pattern: /\bDROP\s+(DATABASE|TABLE|USER)\b/i, reason: "Database object drop" },
  { pattern: /\bTRUNCATE\b/i, reason: "Table truncation" },
  { pattern: /\bDELETE\s+FROM\b/i, reason: "Mass row deletion" },
  { pattern: /\bdocker\s+(rm|rmi|system\s+prune)\b/, reason: "Removing Docker containers/images" },
  { pattern: /\bdocker-compose\s+down\b/, reason: "Stopping Docker Compose stack" },
  { pattern: /\bkill\s+-9\b/, reason: "Forced process kill" },
  { pattern: /\bkillall\b/, reason: "Killing processes by name" },
  { pattern: /\bpkill\b/, reason: "Killing processes" },
];

export function checkDangerousCommand(command: string): { isDangerous: boolean; reasons: string[] } {
  const reasons: string[] = [];
  for (const { pattern, reason } of DANGEROUS_PATTERNS) {
    if (pattern.test(command)) reasons.push(reason);
  }
  return { isDangerous: reasons.length > 0, reasons };
}
