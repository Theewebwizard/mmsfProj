import { useQuery } from "@tanstack/react-query";
import { FlaskConical, FolderLock, LogOut, Moon, ScanSearch, ShieldCheck, Sun } from "lucide-react";
import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "@/api/client";
import type { LogStats } from "@/api/types";
import { useAuth } from "@/auth";
import { StatusBadge } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn, safeStorageSet } from "@/lib/utils";

const NAV = [
  { to: "/cases", label: "Vault & Cases", icon: FolderLock },
  { to: "/trace", label: "MediaTrace", icon: ScanSearch },
  { to: "/research", label: "Research", icon: FlaskConical },
];

function ThemeToggle() {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Toggle theme"
      onClick={() => {
        const next = !dark;
        document.documentElement.classList.toggle("dark", next);
        safeStorageSet("tc-theme", next ? "dark" : "light");
        setDark(next);
      }}
    >
      {dark ? <Sun /> : <Moon />}
    </Button>
  );
}

export function Layout() {
  const { user, logout } = useAuth();
  const stats = useQuery({
    queryKey: ["log-stats"],
    queryFn: () => api.get<LogStats>("/log/stats"),
    refetchInterval: 15_000,
  });
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b bg-card/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-4 gap-y-2 px-4 py-2">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldCheck className="size-5 text-primary" />
            <span>TrustChain</span>
            <span className="text-muted-foreground">+ MediaTrace</span>
          </div>
          <nav className="flex flex-wrap gap-1">
            {NAV.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm",
                    isActive ? "bg-muted font-medium" : "text-muted-foreground hover:text-foreground",
                  )
                }
              >
                <Icon className="size-4" />
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2 text-xs">
            {stats.data && (
              <span className="hidden items-center gap-2 md:inline-flex" title={stats.data.root_hash}>
                <span className="text-muted-foreground">log size</span>
                <span className="font-mono">{stats.data.tree_size}</span>
                {stats.data.latest_checkpoint && (
                  <StatusBadge status={stats.data.latest_checkpoint.witness.status} label="witness" />
                )}
              </span>
            )}
            {user && (
              <span className="inline-flex items-center gap-2">
                <span className="hidden sm:inline">{user.full_name}</span>
                <Badge tone={user.role === "INVESTIGATOR" ? "info" : "neutral"}>{user.role}</Badge>
              </span>
            )}
            <ThemeToggle />
            <Button variant="ghost" size="icon" aria-label="Log out" onClick={logout}>
              <LogOut />
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}
