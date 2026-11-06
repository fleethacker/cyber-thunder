import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import './app.css';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter } from 'react-router-dom';
import App from './App';
import { AppStateProvider } from './state/AppState';
import { IdentityBoundary } from './state/Identity';
import { theme } from './theme';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MantineProvider theme={theme} defaultColorScheme="dark">
      <Notifications position="bottom-right" limit={4} />
      <IdentityBoundary><AppStateProvider>
        <HashRouter>
          <App />
        </HashRouter>
      </AppStateProvider></IdentityBoundary>
    </MantineProvider>
  </StrictMode>,
);
