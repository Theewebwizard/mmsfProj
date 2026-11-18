import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, onUnauthorized, tokenStore } from "@/api/client";
import type { TokenResponse, User } from "@/api/types";

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, full_name: string, role: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [token, setToken] = useState<string | null>(() => tokenStore.get());

  const me = useQuery({
    queryKey: ["me", token],
    queryFn: () => api.get<User>("/auth/me"),
    enabled: !!token,
    retry: false,
  });

  const logout = useCallback(() => {
    tokenStore.set(null);
    setToken(null);
    qc.clear();
  }, [qc]);

  useEffect(() => onUnauthorized(logout), [logout]);

  const accept = (t: TokenResponse) => {
    tokenStore.set(t.access_token);
    setToken(t.access_token);
  };

  const value: AuthCtx = {
    user: token ? (me.data ?? null) : null,
    loading: !!token && me.isLoading,
    login: async (email, password) => accept(await api.post<TokenResponse>("/auth/login", { email, password })),
    register: async (email, password, full_name, role) =>
      accept(await api.post<TokenResponse>("/auth/register", { email, password, full_name, role })),
    logout,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
}

export function useUsers() {
  return useQuery({ queryKey: ["users"], queryFn: () => api.get<User[]>("/auth/users"), staleTime: 60_000 });
}
