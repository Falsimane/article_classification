/** Palette sobre, proche de Blueprint (Palantir) : gris-bleu sombres, un seul accent, aucune ombre ni dégradé. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#111418",
        panel: "#1c2127",
        raised: "#252a31",
        line: "#2f343c",
        "line-strong": "#404854",
        ink: "#f6f7f9",
        muted: "#abb3bf",
        faint: "#738091",
        accent: "#4c90f0",
        danger: "#e76a6e",
        warn: "#fbb360",
        ok: "#72ca9b",
      },
      fontFamily: {
        sans: ['"Inter Variable"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono Variable"', "ui-monospace", "monospace"],
      },
      borderRadius: { DEFAULT: "2px", md: "3px" },
      fontSize: { xs: ["11px", "16px"], sm: ["12px", "18px"], base: ["13px", "20px"] },
    },
  },
  plugins: [],
};
