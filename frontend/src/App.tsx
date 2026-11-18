import { lazy, Suspense, type ReactNode } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useAuth } from "@/auth";
import { Layout } from "@/components/Layout";
import CasesPage from "@/pages/Cases";
import EvidencePage from "@/pages/Evidence";
import LoginPage from "@/pages/Login";
import TracePage from "@/pages/Trace";

const ResearchPage = lazy(() => import("@/pages/Research"));

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <div className="p-8 text-sm text-muted-foreground">Loading…</div>;
  if (!user) return <Navigate to="/login" state={{ from: loc.pathname }} replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/cases" element={<CasesPage />} />
        <Route path="/evidence/:id" element={<EvidencePage />} />
        <Route path="/trace" element={<TracePage />} />
        <Route
          path="/research"
          element={
            <Suspense fallback={<p className="text-sm text-muted-foreground">Loading…</p>}>
              <ResearchPage />
            </Suspense>
          }
        />
      </Route>
      <Route path="*" element={<Navigate to="/cases" replace />} />
    </Routes>
  );
}
