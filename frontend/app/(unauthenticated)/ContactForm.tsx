"use client";

import { useState } from "react";
import { Loader2, Send, CheckCircle2, AlertTriangle } from "lucide-react";

import { submitContactRequest } from "../lib/api";

type Variant = "card" | "inline";

export default function ContactForm({ variant = "card" }: { variant?: Variant }) {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  // Honeypot — real users never see or fill this. If it has a value on
  // submit, the backend silently drops the request as spam.
  const [website, setWebsite] = useState("");

  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<
    | { kind: "ok"; requestId?: string; message: string }
    | { kind: "err"; message: string; fieldErrors?: Record<string, string> }
    | null
  >(null);

  const canSubmit =
    name.trim().length > 0 &&
    email.trim().length > 0 &&
    message.trim().length > 0 &&
    !submitting;

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setResult(null);
    try {
      const res = await submitContactRequest({
        name: name.trim(),
        email: email.trim(),
        subject: subject.trim() || undefined,
        message: message.trim(),
        website,
      });
      setResult({
        kind: "ok",
        message: res.message,
        requestId: res.requestId,
      });
      setName("");
      setEmail("");
      setSubject("");
      setMessage("");
    } catch (err: any) {
      const payload = err?.payload;
      setResult({
        kind: "err",
        message: payload?.error || err?.message || "Something went wrong. Please try again.",
        fieldErrors: payload?.fieldErrors,
      });
    } finally {
      setSubmitting(false);
    }
  }

  const inputClass =
    "w-full h-11 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 text-sm text-white placeholder:text-white/25 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all disabled:opacity-50";

  // Success view
  if (result?.kind === "ok") {
    return (
      <div className={variant === "card" ? "rounded-2xl border border-emerald-500/20 bg-emerald-500/[0.04] p-6" : ""}>
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-xl bg-emerald-500/15 flex items-center justify-center shrink-0">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-base font-semibold text-white">Message received</h3>
            <p className="mt-1 text-sm text-white/60 leading-relaxed">{result.message}</p>
            {result.requestId && (
              <p className="mt-2 text-xs text-white/40">
                Reference: <span className="font-mono text-white/60">{result.requestId}</span>
              </p>
            )}
            <button
              type="button"
              onClick={() => setResult(null)}
              className="mt-4 text-xs text-teal-400 hover:text-teal-300 underline underline-offset-2"
            >
              Send another message
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <form
      onSubmit={onSubmit}
      className={
        variant === "card"
          ? "rounded-2xl border border-white/[0.08] bg-white/[0.02] p-6 space-y-4"
          : "space-y-4"
      }
    >
      {/* Honeypot — visually hidden, ignored by real users */}
      <div aria-hidden="true" className="absolute -left-[9999px] w-1 h-1 overflow-hidden">
        <label>
          Website
          <input
            type="text"
            tabIndex={-1}
            autoComplete="off"
            value={website}
            onChange={(e) => setWebsite(e.target.value)}
          />
        </label>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-white/50 block">Your name</label>
          <input
            className={inputClass}
            placeholder="Jane Smith"
            value={name}
            onChange={(e) => setName(e.target.value)}
            disabled={submitting}
            autoComplete="name"
            maxLength={120}
            required
          />
          {result?.kind === "err" && result.fieldErrors?.name && (
            <p className="text-[11px] text-red-300">{result.fieldErrors.name}</p>
          )}
        </div>
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-white/50 block">Email</label>
          <input
            type="email"
            className={inputClass}
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={submitting}
            autoComplete="email"
            maxLength={255}
            required
          />
          {result?.kind === "err" && result.fieldErrors?.email && (
            <p className="text-[11px] text-red-300">{result.fieldErrors.email}</p>
          )}
        </div>
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-white/50 block">
          Subject <span className="text-white/30">(optional)</span>
        </label>
        <input
          className={inputClass}
          placeholder="What's this about?"
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          disabled={submitting}
          maxLength={200}
        />
      </div>

      <div className="space-y-1.5">
        <label className="text-xs font-medium text-white/50 block">Message</label>
        <textarea
          rows={5}
          className="w-full rounded-lg border border-white/[0.08] bg-white/[0.03] px-3.5 py-2.5 text-sm text-white placeholder:text-white/25 outline-none focus:border-teal-500/40 focus:ring-2 focus:ring-teal-500/20 transition-all resize-y disabled:opacity-50"
          placeholder="How can we help?"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={submitting}
          maxLength={5000}
          required
        />
        <div className="flex items-center justify-between text-[11px] text-white/30">
          <span>
            {result?.kind === "err" && result.fieldErrors?.message && (
              <span className="text-red-300">{result.fieldErrors.message}</span>
            )}
          </span>
          <span>{message.length} / 5000</span>
        </div>
      </div>

      {result?.kind === "err" && !result.fieldErrors && (
        <div className="rounded-lg border border-red-500/20 bg-red-500/[0.06] px-3.5 py-2.5 text-sm text-red-300 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>{result.message}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={!canSubmit}
        className="w-full sm:w-auto inline-flex items-center justify-center gap-2 h-11 px-5 rounded-lg bg-teal-600 hover:bg-teal-500 text-sm font-semibold text-white shadow-md shadow-teal-900/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-teal-600"
      >
        {submitting ? (
          <>
            <Loader2 className="w-4 h-4 animate-spin" />Sending…
          </>
        ) : (
          <>
            <Send className="w-4 h-4" />Send message
          </>
        )}
      </button>
    </form>
  );
}
