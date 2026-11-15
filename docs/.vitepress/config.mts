import { defineConfig } from 'vitepress'

// Published to GitHub Pages at /sovereign-swap/. The marketing / coming-soon landing for the hosted
// service is the Ghost page at twentyone.life/swap (served at swap.twentyone.life). This site is the
// technical and trust documentation it links to. Content is PUBLIC: no infrastructure details ever.

// Practical, task-oriented how-tos (docs/guides/*). Listed in the sidebar so a reader can actually find
// them: the coin-split / replay-protection guides in particular are a headline feature for pre-fork
// holders and were previously reachable only by a direct URL.
const howToGuides = {
  text: 'Guides (how-to)',
  items: [
    { text: 'Your first swap', link: '/guides/your-first-swap' },
    { text: 'Protect your coins (replay protection)', link: '/guides/protect-your-coins' },
    { text: 'Separate your coins', link: '/guides/separating-coins' },
    { text: 'Set a silent-payment fee address', link: '/guides/fee-silent-payment-address' },
  ],
}

export default defineConfig({
  lang: 'en-US',
  title: 'Sovereign Swap',
  description:
    'Peer-to-peer, non-custodial atomic swaps between BTC (SHA256) and BTC (Blake2b). ' +
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
      { text: 'Guides (how-to)', link: '/guides/your-first-swap' },
      { text: 'How it works', link: '/guide/how-it-works' },
      { text: 'Architecture', link: '/guide/architecture' },
      { text: 'Security', link: '/guide/security-model' },
      { text: 'Roadmap', link: '/guide/roadmap' },
      { text: 'Design decisions', link: '/design/' },
      { text: 'Hosted service (soon)', link: 'https://twentyone.life/swap' },
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
            { text: 'Configuration', link: '/guide/configuration' },
          ],
        },
        {
          text: 'Project',
          items: [
            { text: 'Roadmap', link: '/guide/roadmap' },
            { text: 'Hosted service (coming soon)', link: 'https://twentyone.life/swap' },
          ],
        },
        howToGuides,
      ],
      '/guides/': [
        howToGuides,
        {
          text: 'Reference',
          items: [
            { text: 'Overview', link: '/guide/overview' },
            { text: 'How it works', link: '/guide/how-it-works' },
            { text: 'Security model', link: '/guide/security-model' },
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
      copyright:
        '<a href="https://twentyone.life" target="_blank" rel="noopener noreferrer">TwentyOne.Life</a>',
    },
  },
})
