import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const auth = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  if (!auth.loading && auth.user) return <Navigate to="/" replace />;
  async function submit() {
    setError("");
    try {
      await auth.login(username, password);
      const destination = (location.state as { from?: string } | null)?.from ?? "/";
      navigate(destination, { replace: true });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Login failed.");
    }
  }
  return <main className="login-page"><form className="panel login-panel" onSubmit={(event) => { event.preventDefault(); void submit(); }}>
    <div className="brand"><div className="brand-mark">S</div><strong>SHERLOCK</strong></div>
    <h1>Analyst sign in</h1>
    <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" /></label>
    <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" /></label>
    {error && <div className="notice">{error}</div>}
    <button className="primary-btn" disabled={!username || !password}>Sign in</button>
  </form></main>;
}
