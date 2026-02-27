"use client";

import { useEffect, useState } from "react";
import { me } from "../lib/api";
import { setUser, setOrganization, setRole, getAccessToken } from "../lib/auth";

export function useAuthContext() {
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const token = getAccessToken();
    if (!token) {
      setLoaded(true);
      return;
    }

    // Fetch current user context on mount
    me()
      .then((data) => {
        setUser(data.user);
        setOrganization(data.organization);
        setRole(data.role);
      })
      .catch((err) => {
        console.error("Failed to load user context:", err);
      })
      .finally(() => {
        setLoaded(true);
      });
  }, []);

  return { loaded };
}