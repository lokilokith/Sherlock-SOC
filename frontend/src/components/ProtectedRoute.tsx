import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function ProtectedRoute() {
  const auth = useAuth();
  const location = useLocation();
  if (auth.loading) return <div className="route-loading">Restoring session…</div>;
  if (!auth.user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}
