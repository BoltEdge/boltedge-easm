"use client";

import * as React from "react";
import { createPortal } from "react-dom";

type ClickableProps = {
  onClick?: (e: React.MouseEvent<any>) => void;
};

type Ctx = {
  open: boolean;
  setOpen: (v: boolean) => void;
  anchorRef: React.RefObject<HTMLElement | null>;
  contentRef: React.RefObject<HTMLDivElement | null>;
};

const DropdownContext = React.createContext<Ctx | null>(null);

function mergeRefs<T>(...refs: Array<React.Ref<T> | undefined>) {
  return (value: T) => {
    for (const ref of refs) {
      if (!ref) continue;
      if (typeof ref === "function") ref(value);
      else (ref as React.MutableRefObject<T>).current = value;
    }
  };
}

function withMergedOnClickAndRef(
  child: React.ReactNode,
  opts: {
    onClick: (e: React.MouseEvent<any>) => void;
    ref?: React.Ref<any>;
  }
) {
  if (!React.isValidElement(child)) {
    throw new Error(
      "DropdownMenuTrigger with asChild expects a single valid React element child."
    );
  }

  const el = child as React.ReactElement<ClickableProps & { ref?: React.Ref<any> }>;
  const prevOnClick = el.props.onClick;

  const mergedOnClick: ClickableProps["onClick"] = (e) => {
    prevOnClick?.(e);
    opts.onClick(e);
  };

  return React.cloneElement(el, {
    onClick: mergedOnClick,
    ref: mergeRefs((el as any).ref, opts.ref),
  });
}

export function DropdownMenu({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = React.useState(false);
  const anchorRef = React.useRef<HTMLElement | null>(null);
  const contentRef = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (!open) return;
      const target = e.target as Node;

      const anchor = anchorRef.current;
      const content = contentRef.current;

      if (anchor && anchor.contains(target)) return;
      if (content && content.contains(target)) return;

      setOpen(false);
    };

    const onKey = (e: KeyboardEvent) => {
      if (open && e.key === "Escape") setOpen(false);
    };

    document.addEventListener("mousedown", onDown);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const value = React.useMemo(
    () => ({ open, setOpen, anchorRef, contentRef }),
    [open]
  );

  return (
    <DropdownContext.Provider value={value}>
      <div className="relative inline-block">{children}</div>
    </DropdownContext.Provider>
  );
}

export function DropdownMenuTrigger({
  asChild,
  children,
}: {
  asChild?: boolean;
  children: React.ReactNode;
}) {
  const ctx = React.useContext(DropdownContext);
  if (!ctx) throw new Error("DropdownMenuTrigger must be used within <DropdownMenu>");

  const handleClick = (e: React.MouseEvent<any>) => {
    e.preventDefault();
    e.stopPropagation();
    ctx.setOpen(!ctx.open);
  };

  const setAnchorRef: React.Ref<HTMLElement> = (node) => {
    ctx.anchorRef.current = node;
  };

  if (asChild) {
    return withMergedOnClickAndRef(children, {
      onClick: handleClick,
      ref: setAnchorRef,
    });
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      ref={(node) => {
        ctx.anchorRef.current = node;
      }}
    >
      {children}
    </button>
  );
}

export function DropdownMenuContent(props: {
  children: React.ReactNode;
  align?: "start" | "end";
  side?: "top" | "bottom";
  className?: string;
  sideOffset?: number;
}) {
  const ctx = React.useContext(DropdownContext);
  if (!ctx) throw new Error("DropdownMenuContent must be used within <DropdownMenu>");

  const align = props.align ?? "end";
  const side = props.side ?? "bottom";
  const sideOffset = props.sideOffset ?? 8;
  const className = props.className ?? "";

  const [position, setPosition] = React.useState({ top: 0, left: 0 });

  React.useEffect(() => {
    if (!ctx.open || !ctx.anchorRef.current) return;

    const updatePosition = () => {
      const anchor = ctx.anchorRef.current;
      if (!anchor) return;

      const rect = anchor.getBoundingClientRect();
      
      let top = side === "top" 
        ? rect.top - sideOffset
        : rect.bottom + sideOffset;
      
      let left = align === "start" 
        ? rect.left 
        : rect.right;

      setPosition({ top, left });
    };

    updatePosition();
    window.addEventListener("scroll", updatePosition, true);
    window.addEventListener("resize", updatePosition);

    return () => {
      window.removeEventListener("scroll", updatePosition, true);
      window.removeEventListener("resize", updatePosition);
    };
  }, [ctx.open, ctx.anchorRef, align, side, sideOffset]);

  if (!ctx.open) return null;
  if (typeof window === "undefined") return null;

  const alignClass = align === "start" ? "" : "-translate-x-full";
  const sideClass = side === "top" ? "-translate-y-full" : "";

  return createPortal(
    <div
      ref={(node) => {
        ctx.contentRef.current = node;
      }}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
      }}
      style={{
        position: "fixed",
        top: `${position.top}px`,
        left: `${position.left}px`,
      }}
      className={`z-50 min-w-[180px] rounded-md border border-border bg-card p-1 shadow-xl ${alignClass} ${sideClass} ${className}`}
    >
      {props.children}
    </div>,
    document.body
  );
}

export function DropdownMenuItem({
  children,
  onClick,
  onSelect,
  variant,
  className = "",
  disabled,
}: {
  children: React.ReactNode;
  onClick?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  onSelect?: (e: React.MouseEvent<HTMLButtonElement>) => void;
  variant?: "destructive";
  className?: string;
  disabled?: boolean;
}) {
  const ctx = React.useContext(DropdownContext);
  if (!ctx) throw new Error("DropdownMenuItem must be used within <DropdownMenu>");

  const base =
    "w-full flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors text-left";
  const style =
    variant === "destructive"
      ? "text-destructive hover:bg-destructive/10"
      : "text-foreground hover:bg-accent";

  const disabledStyle = disabled ? "opacity-50 pointer-events-none" : "";

  return (
    <button
      type="button"
      className={`${base} ${style} ${disabledStyle} ${className}`}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();

        if (disabled) return;

        onClick?.(e);
        onSelect?.(e);

        ctx.setOpen(false);
      }}
    >
      {children}
    </button>
  );
}