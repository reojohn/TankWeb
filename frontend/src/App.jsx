import React from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import AppShell from './components/AppShell.jsx';
import Overview from './pages/Overview.jsx';
import AccessActivity from './pages/AccessActivity.jsx';
import Analytics from './pages/Analytics.jsx';
import Threats from './pages/Threats.jsx';
import AIDefense from './pages/AIDefense.jsx';
import SecurityLogs from './pages/SecurityLogs.jsx';
import BlockedIPs from './pages/BlockedIPs.jsx';
import SecurityControls from './pages/SecurityControls.jsx';
import CurrentOperator from './pages/CurrentOperator.jsx';
import Vault from './pages/Vault.jsx';

function ShellRoutes() {
  return (
    <AppShell>
      <Routes>
        <Route path="/overview" element={<Overview />} />
        <Route path="/activity" element={<AccessActivity />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/ai-defense" element={<AIDefense />} />
        <Route path="/logs" element={<SecurityLogs />} />
        <Route path="/blocked-ips" element={<BlockedIPs />} />
        <Route path="/security-controls" element={<SecurityControls />} />
        <Route path="/operator" element={<CurrentOperator />} />
        <Route path="*" element={<Navigate to="/overview" replace />} />
      </Routes>
    </AppShell>
  );
}

export default function App() {
  const location = useLocation();
  if (location.pathname === '/vault') return <Vault />;
  return <ShellRoutes />;
}
