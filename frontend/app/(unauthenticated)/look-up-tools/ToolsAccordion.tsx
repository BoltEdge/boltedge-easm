// app/(unauthenticated)/look-up-tools/ToolsAccordion.tsx
// Grid of tool cards. Click a card to expand it in place — only one card
// open at a time. Default: all collapsed for a clean first impression.
"use client";

import { useState } from "react";

import ToolAccordionRow from "./ToolAccordionRow";
import { VISIBLE_TOOLS } from "./tools-config";

export default function ToolsAccordion() {
  const [openId, setOpenId] = useState<string | null>(null);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5 items-start">
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
