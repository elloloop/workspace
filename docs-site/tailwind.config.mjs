import { refractionPreset } from "@refraction-ui/tailwind-config";

/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}",
    // refraction-ui's components ship Tailwind utility classes inside
    // node_modules. Without scanning them, classes like the AppShellOverlay's
    // `bg-black/50` and `z-30` get purged and the mobile sidebar backdrop
    // becomes invisible — making the hamburger appear broken.
    "./node_modules/@refraction-ui/astro/dist/**/*.{astro,js,mjs,ts}",
    "./node_modules/.pnpm/@refraction-ui+astro@*/node_modules/@refraction-ui/astro/dist/**/*.{astro,js,mjs,ts}",
  ],
  presets: [refractionPreset],
  darkMode: "class",
  // The .dark class is toggled by the theme script at runtime, and Tailwind's
  // JIT only emits a base-layer rule if its selector appears in `content`.
  // Safelist `dark` so the CSS-variable overrides survive the purge step.
  safelist: ["dark"],
  theme: {
    extend: {
      fontFamily: {
        sans: ["var(--font-sans)"],
        mono: ["var(--font-mono)"],
      },
    },
  },
};
