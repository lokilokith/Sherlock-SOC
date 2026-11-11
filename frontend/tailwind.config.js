/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        navy: "#0B1020",
        surface: "#172033",
        elevated: "#1E293B",
        border: "#29364D",
      },
    },
  },
  plugins: [],
};
