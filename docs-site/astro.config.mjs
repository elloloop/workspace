import { defineConfig } from "astro/config";
import tailwind from "@astrojs/tailwind";
import expressiveCode from "astro-expressive-code";
import pagefind from "astro-pagefind";

export default defineConfig({
  site: "https://elloloop.github.io",
  base: "/workspace",
  integrations: [
    expressiveCode({
      themes: ["github-dark-dimmed"],
      styleOverrides: {
        // Minimal, modern chrome — drop the macOS "traffic light" decoration.
        frames: {
          frameBoxShadowCssValue: "none",
          editorTabBarBackground: "hsl(var(--muted))",
          editorActiveTabIndicatorBottomColor: "hsl(var(--primary))",
          editorActiveTabBorderColor: "transparent",
          terminalTitlebarBackground: "hsl(var(--muted))",
          terminalTitlebarBorderBottomColor: "hsl(var(--border))",
          terminalBackground: "#22272e",
          tooltipSuccessBackground: "hsl(var(--primary))",
        },
        borderRadius: "0.5rem",
        codeFontFamily: "var(--font-mono)",
        codeFontSize: "13px",
        codeLineHeight: "1.65",
        uiFontFamily: "var(--font-sans)",
      },
      defaultProps: {
        // Hide the macOS-style window decoration buttons globally.
        frame: "code",
      },
      shiki: {
        // Match the prior Shiki configuration so language tags continue to work.
      },
    }),
    tailwind({ applyBaseStyles: false }),
    pagefind(),
  ],
  output: "static",
});
