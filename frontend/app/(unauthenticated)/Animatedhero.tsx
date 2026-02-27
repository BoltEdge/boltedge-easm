// app/(unauthenticated)/Animatedhero.tsx
"use client";

import { motion, type Variants } from "framer-motion";
import type { ReactNode } from "react";

interface AnimatedProps {
  children: ReactNode;
  className?: string;
}

interface FadeInProps extends AnimatedProps {
  delay?: number;
}

const container: Variants = {
  hidden: {},
  show: {
    transition: { staggerChildren: 0.12, delayChildren: 0.1 },
  },
};

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5, ease: "easeOut" } },
};

const scaleIn: Variants = {
  hidden: { opacity: 0, y: 30, scale: 0.98 },
  show: { opacity: 1, y: 0, scale: 1, transition: { duration: 0.7, ease: "easeOut" } },
};

export function HeroStagger({ children }: { children: ReactNode }) {
  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="flex flex-col items-center text-center"
    >
      {children}
    </motion.div>
  );
}

export function HeroItem({ children, className = "" }: AnimatedProps) {
  return (
    <motion.div variants={fadeUp} className={className}>
      {children}
    </motion.div>
  );
}

export function HeroDashboard({ children, className = "" }: AnimatedProps) {
  return (
    <motion.div
      variants={scaleIn}
      initial="hidden"
      animate="show"
      transition={{ delay: 0.6 }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function HeroFadeIn({ children, className = "", delay = 0 }: FadeInProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, ease: "easeOut", delay }}
      className={className}
    >
      {children}
    </motion.div>
  );
}