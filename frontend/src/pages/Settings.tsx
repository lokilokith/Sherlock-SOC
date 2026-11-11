import { Settings as SettingsIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { SectionTitle } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { api } from "../services/api";
import { useAuth } from "../auth/AuthContext";

type ManagedUser = {
  username: string; email?: string | null; role: string; active: boolean;
  created_at?: string | null; last_login_at?: string | null;
};

export function Settings() {
  const mode = useApi(api.runtimeMode);
  const identity = useApi(api.me);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const auth = useAuth();
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [adminBusy, setAdminBusy] = useState(false);

  async function loadUsers() {
    if (auth.user?.role !== "admin") return;
    try { setUsers(await api.adminUsers()); } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to load accounts."); }
  }
  useEffect(() => { void loadUsers(); }, [auth.user?.role]);
  async function createAnalyst() {
    setAdminBusy(true); setMessage("");
    try {
      await api.createAnalyst(newUsername, newPassword);
      setNewUsername(""); setNewPassword("");
      setMessage("Analyst account created.");
      await loadUsers();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to create account."); }
    finally { setAdminBusy(false); }
  }
  async function setActive(user: ManagedUser, active: boolean) {
    try {
      await api.updateUser(user.username, user.role, active, user.email);
      setMessage(active ? "Account activated." : "Account deactivated.");
      await loadUsers();
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to update account."); }
  }
  async function resetPassword(user: ManagedUser) {
    const password = window.prompt(`Enter a new password for ${user.username} (12 characters minimum):`);
    if (!password) return;
    try {
      await api.resetUserPassword(user.username, password);
      setMessage(`Password reset for ${user.username}.`);
    } catch (error) { setMessage(error instanceof Error ? error.message : "Unable to reset password."); }
  }
  async function login() {
    setBusy(true); setMessage("");
    try { await api.login(username, password); setPassword(""); await identity.reload(); setMessage("Analyst session active."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "Login failed."); }
    finally { setBusy(false); }
  }
  async function logout() {
    await api.logout(); await identity.reload(); setMessage("Analyst session ended.");
  }
  return <><div className="page-heading"><div><span className="eyebrow">PLATFORM CONFIGURATION</span><h2>Settings</h2><p>Environment details for this local prototype.</p></div></div><section className="panel settings-panel"><SectionTitle title="Connection" eyebrow="BACKEND" /><div className="setting-row"><div><strong>API base URL</strong><span>Configured through VITE_API_BASE_URL; empty uses the Vite development proxy.</span></div><SettingsIcon size={20} /></div><div className="setting-row"><div><strong>Operating mode</strong><span>{mode.data?.provider ?? "Mode unavailable"} · restart the backend after changing SHERLOCK_AGENT_MODE.</span></div><span className={`badge badge-${mode.data?.mode === "live" ? "violet" : "success"}`}>{mode.data?.label ?? "Unavailable"}</span></div><div className="setting-row"><div><strong>Authentication</strong><span>{identity.data ? `Signed in as ${identity.data.username}.` : "Public demo access is read-only; sign in for analyst operations."}</span></div>{identity.data ? <button className="secondary-btn" onClick={() => void logout()}>Sign out</button> : <span className="badge badge-muted">Analyst login below</span>}</div>{!identity.data && <div className="setting-row"><div><strong>Analyst sign in</strong><span>Credentials are configured through the backend environment.</span></div><div className="setting-form"><input aria-label="Username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="Username" /><input aria-label="Password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Password" /><button className="primary-btn" disabled={busy || !username || !password} onClick={() => void login()}>{busy ? "Signing in..." : "Sign in"}</button></div></div>}{auth.user?.role === "admin" && <div className="account-management"><SectionTitle title="Account management" eyebrow="ADMINISTRATOR" /><div className="setting-form account-create"><input aria-label="New analyst username" value={newUsername} onChange={(event) => setNewUsername(event.target.value)} placeholder="New analyst username" /><input aria-label="New analyst password" type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} placeholder="Initial password (12+ characters)" /><button className="primary-btn" disabled={adminBusy || !newUsername || newPassword.length < 12} onClick={() => void createAnalyst()}>{adminBusy ? "Creating..." : "Create analyst"}</button></div><div className="account-table"><div className="account-table-head"><strong>User</strong><strong>Role</strong><strong>Status</strong><strong>Created</strong><strong>Last login</strong><strong>Actions</strong></div>{users.map((user) => <div className="account-table-row" key={user.username}><span>{user.username}</span><span>{user.role}</span><span>{user.active ? "Active" : "Inactive"}</span><span>{user.created_at ? new Date(user.created_at).toLocaleString() : "Unknown"}</span><span>{user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "Never"}</span><span className="account-actions">{user.username !== auth.user?.username && <><button className="secondary-btn" onClick={() => void setActive(user, !user.active)}>{user.active ? "Deactivate" : "Activate"}</button><button className="secondary-btn" onClick={() => void resetPassword(user)}>Reset password</button></>}</span></div>)}</div></div>}{message && <div className="notice">{message}</div>}</section></>
}
