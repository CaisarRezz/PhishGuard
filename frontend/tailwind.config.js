/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: '#080c14',
          panel: '#0e1526',
          card: '#131d33',
          cardHover: '#182440',
          border: '#1f2d4d',
          borderLight: '#2a3b63',
          primary: '#0ea5e9',
          primaryGlow: 'rgba(14, 165, 233, 0.25)',
          success: '#10b981',
          successGlow: 'rgba(16, 185, 129, 0.25)',
          warning: '#f59e0b',
          warningGlow: 'rgba(245, 158, 11, 0.25)',
          danger: '#ef4444',
          dangerGlow: 'rgba(239, 68, 68, 0.25)',
          muted: '#94a3b8',
          text: '#f8fafc',
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'soc-glow': '0 0 20px -5px rgba(14, 165, 233, 0.2)',
        'soc-glow-danger': '0 0 20px -5px rgba(239, 68, 68, 0.3)',
        'soc-card': '0 4px 20px -2px rgba(0, 0, 0, 0.5)',
      }
    },
  },
  plugins: [],
}
