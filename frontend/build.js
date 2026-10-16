const esbuild = require('esbuild');
const path = require('path');

const outJs = path.resolve(__dirname, 'threat_actor_flow.bundle.js');
const outCss = path.resolve(__dirname, 'threat_actor_flow.bundle.css');

esbuild.build({
  entryPoints: [path.resolve(__dirname, 'src/index.jsx')],
  bundle: true,
  minify: true,
  sourcemap: false,
  format: 'iife',
  globalName: 'ThreatActorFlowLib',
  outfile: outJs,
  loader: {
    '.js': 'jsx',
    '.jsx': 'jsx',
    '.css': 'css',
  },
  define: {
    'process.env.NODE_ENV': '"production"',
  },
}).then(() => {
  console.log('✅ Bundle React Flow généré avec succès dans :', outJs);
}).catch((err) => {
  console.error('❌ Erreur de build React Flow :', err);
  process.exit(1);
});
