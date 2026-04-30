module.exports = {
  content: [
    "./src/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        serif: ['Playfair Display', 'Georgia', 'serif'],
        display: ['Outfit', 'system-ui', 'sans-serif'],
        'season-mix': ['Playfair Display', 'Georgia', 'serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        background: '#F8F9FB',
        foreground: '#131313',
        'muted-foreground': '#999999',
        accent: '#556ADC',
        'accent-indigo': '#556ADC',
        'sr-indigo-100': 'rgba(85,106,220,0.12)',
        card: '#FFFFFF',
        border: 'rgba(0,0,0,0.08)',
      },
    },
  },
  plugins: [],
};