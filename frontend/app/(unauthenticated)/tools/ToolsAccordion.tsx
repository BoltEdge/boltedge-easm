// app/(unauthenticated)/tools/ToolsAccordion.tsx
"use client";

import { useState } from "react";

import ToolAccordionRow from "./ToolAccordionRow";
import { VISIBLE_TOOLS } from "./tools-config";

export default function ToolsAccordion() {
  const [openId, setOpenId] = useState<string | null>(VISIBLE_TOOLS[0].id);

  return (
    <div className="space-y-3">
      {VISIBLE_TOOLS.map((tool) => (
        <ToolAccordionRow
          key={tool.id}
          tool={tool}
          isOpen={openId === tool.id}
          onToggle={() => setOpenId((cur) => (cur === tool.id ? null : tool.id))}
        />
      ))}
    </div>
  );
}
