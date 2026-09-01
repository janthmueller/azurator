import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://janthmueller.github.io',
  base: '/azurator',
  scopedStyleStrategy: 'where',
  integrations: [
    starlight({
      title: 'Azurator',
      description: 'Rotate shared-key credentials for Azure services and update supported places where they are stored.',
      disable404Route: true,
      customCss: ['./src/styles/custom.css'],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/janthmueller/azurator',
        },
      ],
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Installation', link: '/getting-started/installation/' },
            { label: 'Authentication', link: '/getting-started/authentication/' },
            { label: 'First Rotation', link: '/getting-started/first-rotation/' },
          ],
        },
        {
          label: 'Workflows',
          items: [
            { label: 'Rotate a dotenv File', link: '/guides/rotate-dotenv-file/' },
            { label: 'Rotate a SOPS File', link: '/guides/rotate-sops-file/' },
            { label: 'Export Keys', link: '/guides/export-keys/' },
            { label: 'Resume a Rotation', link: '/guides/resume-rotation/' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Supported Keys and Bindings', link: '/reference/supported-keys-and-bindings/' },
            { label: 'CLI Reference', link: '/reference/cli/' },
          ],
        },
      ],
    }),
  ],
});
