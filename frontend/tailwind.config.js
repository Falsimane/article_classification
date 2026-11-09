/** Console d'enquête inspirée de Gotham (Palantir) : fond bleu marine, une couleur par état.
 * Ambre = ce que l'utilisateur a sélectionné ; cyan = ce que l'assistant a cité ; bleu = contrôles. Aucune ombre ni dégradé. */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "#121a24",
        panel: "#18212d",
        raised: "#223040",
        line: "#2b394a",
        "line-strong": "#3a4b60",
        ink: "#e6edf5",
        muted: "#9fb0c3",
        faint: "#7e8fa3",
        accent: "#4c90f0",
        select: "#e8b04b",
        cited: "#5fd4e8",
        danger: "#e76a6e",
        warn: "#fbb360",
        ok: "#72ca9b",
      },
      fontFamily: {
        sans: ['"Barlow"', "system-ui", "sans-serif"],
        display: ['"Barlow Semi Condensed"', '"Barlow"', "sans-serif"],
        mono: ['"JetBrains Mono Variable"', "ui-monospace", "monospace"],
      },
      borderRadius: { DEFAULT: "3px", md: "4px" },
      fontSize: { xs: ["12px", "16px"], sm: ["13px", "18px"], base: ["14px", "20px"] },
    },
  },
  plugins: [],
};
