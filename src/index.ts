import { serve } from '@hono/node-server';
import { createApp } from './app.js';
import { loadConfig } from './config.js';
import { GrantService, Sweeper } from './grants.js';
import { ImmichClient } from './immich.js';
import { GrantStore } from './store.js';

const config = loadConfig();
const store = new GrantStore(config.databasePath);
const immich = new ImmichClient(config.immichApiUrl);
const grants = new GrantService(config, immich, store);
const sweeper = new Sweeper(grants, config.sweepInterval * 1000);
const { app } = createApp({ config, immich, grants, sweeper });

sweeper.start();
const server = serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(
    JSON.stringify({
      message: 'immich-device-auth listening',
      port: info.port,
      publicUrl: config.publicUrl,
      immich: config.immichApiUrl,
      nativeKeyExpiry: config.nativeKeyExpiry,
      grants: store.counts(),
    }),
  );
});

// Approval needs Immich's OAuth sign-in; warn early if it is off.
immich
  .getFeatures()
  .then((features) => {
    if (!features.oauth) {
      console.warn(JSON.stringify({ message: 'OAuth is not enabled on this Immich server; nobody will be able to approve requests' }));
    }
  })
  .catch((error) => console.warn(JSON.stringify({ message: 'could not reach Immich at startup', error: String(error) })));

const shutdown = async () => {
  server.close();
  await sweeper.stop();
  store.close();
  process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
