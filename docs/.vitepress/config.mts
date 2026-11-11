import { defineConfig } from 'vitepress'

// Published to GitHub Pages at /sovereign-swap/ and linked from the Ghost home at twentyone.life/swap
// (later swap.twentyone.life via Cloudflare). This is the technical and trust documentation; the Ghost
// page is the marketing landing. Content is PUBLIC: no infrastructure details ever.
export default defineConfig({
  lang: 'en-US',
  title: 'Sovereign Swap',
  description:
    'Peer-to-peer, non-custodial atomic swaps between Bitcoin and Bitcoin Blake2b (xBTC). ' +
    'No custody, no KYC, post-quantum sealed, Tor-first.',
  base: '/sovereign-swap/',
  cleanUrls: true,
  lastUpdated: true,
  // Every link is checked: a real broken link fails the build. (0021 and 0022 are now on main.)
  head: [
    ['link', { rel: 'icon', type: 'image/png', href: '/sovereign-swap/icon.png' }],
    ['meta', { name: 'theme-color', content: '#F7931A' }],
  ],
  themeConfig: {
    logo: '/logo.svg',
    nav: [
      { text: 'Guide', link: '/guide/overview' },
      { text: 'How it works', link: '/guide/how-it-works' },
      { text: 'Architecture', link: '/guide/architecture' },
      { text: 'Security', link: '/guide/security-model' },
      { text: 'Design decisions', link: '/design/' },
    ],
    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'Overview', link: '/guide/overview' },
            { text: 'User journey', link: '/guide/user-journey' },
          ],
        },
        {
          text: 'How it works',
          items: [
            { text: 'Atomic swap and replay guard', link: '/guide/how-it-works' },
            { text: 'Safe swap lifecycle', link: '/guide/lifecycle' },
            { text: 'Fees', link: '/guide/fees' },
          ],
        },
        {
          text: 'Architecture',
          items: [
            { text: 'Components', link: '/guide/architecture' },
            { text: 'Transport and privacy', link: '/guide/transport-and-privacy' },
            { text: 'The post-quantum envelope', link: '/guide/envelope' },
          ],
        },
        {
          text: 'Trust',
          items: [
            { text: 'Security model', link: '/guide/security-model' },
            { text: 'Run your own', link: '/guide/run-your-own' },
          ],
        },
      ],
      '/design/': [
        {
          text: 'Design decisions',
          items: [{ text: 'Index', link: '/design/' }],
        },
      ],
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/TwentyOneLife/sovereign-swap' },
    ],
    search: { provider: 'local' },
    footer: {
      message: 'Sovereign, non-custodial atomic swaps. No custody, no KYC.',
      copyright: 'TwentyOne.Life',
    },
  },
})
