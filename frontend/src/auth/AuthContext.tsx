import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api } from "../services/api";

export type AuthUser = { username: string; role: string };
type AuthContextValue = {
  user: AuthUser | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
};
const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  async function refresh() {
    try { setUser(await api.me()); } catch { setUser(null); } finally { setLoading(false); }
  }
  useEffect(() => { void refresh(); }, []);
  async function login(username: string, password: string) {
    setUser(await api.login(username, password));
  }
  async function logout() {
    await api.logout();
    setUser(null);
  }
  return <AuthContext.Provider value={{ user, loading, login, logout, refresh }}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
