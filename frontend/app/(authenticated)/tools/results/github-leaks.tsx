"use client";

import React from "react";
import { GitBranch, Search, ExternalLink } from "lucide-react";
import { cn } from "../../../lib/utils";
import {
  Collapsible, IssuesList, ResultEmptyOk, SevIcon, SEV_BORDER, type Issue,
} from "./_shared";

export interface GitHubLeaksResponse {
  domain?: string;
  searchesCompleted?: number;
  totalLeaks?: number;
  hasGitHubToken?: boolean;
  rateLimited?: boolean;
  issues?: Issue[];
  severityCounts?: { critical?: number; high?: number };
  searches?: Array<{
    title: string;
    query: string;
    severity: string;
    totalResults: number;
    files?: Array<{ repository: string; path: string; htmlUrl?: string }>;
  }>;
  dorks?: Array<{ title: string; query: string; searchUrl: string }>;
}

export function GitHubLeaksResult({ data }: { data: GitHubLeaksResponse }) {
  const searches = data.searches || [];
  const dorks = data.dorks || [];
  const sevCounts = data.severityCounts || {};
  const searchesWithResults = searches.filter((s) => s.totalResults > 0);

  return (
    <div className="space-y-4">
      <div>
        <div className="text-sm font-medium text-foreground">{data.domain}</div>
        <div className="text-xs text-muted-foreground">
          {data.searchesCompleted} searches · {data.totalLeaks} leak(s)
          {!data.hasGitHubToken && <span className="text-yellow-400 ml-2">· No GITHUB_TOKEN</span>}
          {data.rateLimited && <span className="text-red-400 ml-2">· Rate limited</span>}
        </div>
      </div>
      {(data.totalLeaks ?? 0) > 0 && (
        <div className="flex gap-2 flex-wrap">
          {!!sevCounts.critical && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/20">{sevCounts.critical} Critical</span>}
          {!!sevCounts.high && <span className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-orange-500/15 text-orange-400 border border-orange-500/20">{sevCounts.high} High</span>}
        </div>
      )}
      <IssuesList issues={data.issues} />
      {searchesWithResults.length > 0 && (
        <Collapsible title={`GitHub Searches (${searchesWithResults.length} with results)`} defaultOpen>
          <div className="pt-3 space-y-2">
            {searchesWithResults.map((s, i) => (
              <div key={i} className={cn(
                "p-3 rounded-lg border-l-2 bg-card/30 border border-border",
                SEV_BORDER[s.severity] || SEV_BORDER.info,
              )}>
                <div className="flex items-center gap-2 mb-1">
                  <SevIcon severity={s.severity} />
                  <span className="text-sm font-medium text-foreground">{s.title}</span>
                  <span className="ml-auto text-xs font-semibold text-primary">{s.totalResults} result(s)</span>
                </div>
                <div className="text-xs font-mono text-muted-foreground mb-1">{s.query}</div>
                {s.files?.length ? (
                  <div className="space-y-1 mt-2">
                    {s.files.map((f, j) => (
                      <div key={j} className="flex items-center gap-2 p-2 rounded bg-background/30 border border-border text-xs">
                        <GitBranch className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        <span className="font-mono text-foreground truncate">{f.repository}</span>
                        <span className="text-muted-foreground truncate">/{f.path}</span>
                        {f.htmlUrl && (
                          <a href={f.htmlUrl} target="_blank" rel="noopener noreferrer" className="ml-auto shrink-0 text-primary hover:underline">
                            <ExternalLink className="w-3.5 h-3.5" />
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </div>
        </Collapsible>
      )}
      {dorks.length > 0 && (
        <Collapsible title={`Google Dorks (${dorks.length})`}>
          <div className="pt-3 space-y-2">
            {dorks.map((d, i) => (
              <div key={i} className="flex items-center gap-3 p-2.5 rounded-lg border border-border bg-background/30">
                <Search className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-semibold text-foreground">{d.title}</div>
                  <div className="text-[11px] font-mono text-muted-foreground truncate">{d.query}</div>
                </div>
                <a href={d.searchUrl} target="_blank" rel="noopener noreferrer" className="shrink-0 px-2.5 py-1 rounded text-xs font-medium bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20">
                  Search →
                </a>
              </div>
            ))}
          </div>
        </Collapsible>
      )}
      {data.totalLeaks === 0 && !data.rateLimited && (
        <ResultEmptyOk message="No leaked credentials found on GitHub." />
      )}
    </div>
  );
}
