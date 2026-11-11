import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Shell } from "./components/Shell";
const Overview = lazy(() => import("./pages/Overview").then((module) => ({ default: module.Overview })));
const Alerts = lazy(() => import("./pages/Alerts").then((module) => ({ default: module.Alerts })));
const AlertDetail = lazy(() => import("./pages/AlertDetail").then((module) => ({ default: module.AlertDetail })));
const Investigations = lazy(() => import("./pages/Investigations").then((module) => ({ default: module.Investigations })));
const Investigation = lazy(() => import("./pages/Investigation").then((module) => ({ default: module.Investigation })));
const Agents = lazy(() => import("./pages/Agents").then((module) => ({ default: module.Agents })));
const ThreatIntel = lazy(() => import("./pages/ThreatIntel").then((module) => ({ default: module.ThreatIntel })));
const Events = lazy(() => import("./pages/Events").then((module) => ({ default: module.Events })));
const Settings = lazy(() => import("./pages/Settings").then((module) => ({ default: module.Settings })));
const ValidationLab = lazy(() => import("./pages/ValidationLab").then((module) => ({ default: module.ValidationLab })));
const AdvancedSOC = lazy(() => import("./pages/AdvancedSOC").then((module) => ({ default: module.AdvancedSOC })));
const Login = lazy(() => import("./pages/Login").then((module) => ({ default: module.Login })));
import { ProtectedRoute } from "./components/ProtectedRoute";
export default function App() { return <BrowserRouter><Suspense fallback={<div className="route-loading">Loading workspace…</div>}><Routes><Route path="/login" element={<Login />} /><Route element={<ProtectedRoute />}><Route element={<Shell />}><Route path="/" element={<Overview />} /><Route path="/alerts" element={<Alerts />} /><Route path="/alerts/:alertId" element={<AlertDetail />} /><Route path="/investigations" element={<Investigations />} /><Route path="/investigations/:investigationId" element={<Investigation />} /><Route path="/agents" element={<Agents />} /><Route path="/threat-intelligence" element={<ThreatIntel />} /><Route path="/events" element={<Events />} /><Route path="/settings" element={<Settings />} /><Route path="/validation" element={<ValidationLab />} /><Route path="/advanced" element={<AdvancedSOC />} /></Route></Route></Routes></Suspense></BrowserRouter> }
