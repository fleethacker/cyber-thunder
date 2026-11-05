import { Route, Routes } from 'react-router-dom';
import { Empty } from './components/common';
import { Shell } from './components/Shell';
import Assets from './pages/Assets';
import Audit from './pages/Audit';
import Commander from './pages/Commander';
import Content from './pages/Content';
import Decisions from './pages/Decisions';
import Findings from './pages/Findings';
import Mission from './pages/Mission';
import Reports from './pages/Reports';
import Scans from './pages/Scans';
import Settings from './pages/Settings';

export default function App() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Decisions />} />
        <Route path="/mission" element={<Mission />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/content" element={<Content />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/commander" element={<Commander />} />
        <Route path="*" element={<Empty title="Page not found" />} />
      </Routes>
    </Shell>
  );
}
