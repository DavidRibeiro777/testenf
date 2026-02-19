/** @type {import('tailwindcss').Config} */
export default {
  // Aqui dizemos ao Tailwind para monitorar seus dois arquivos HTML
  content: ["./index.html", "./admin-v2.html"], 
  theme: {
    extend: {
      colors: {
        petroleo: '#004d4d',
        musgo: '#4B5320',
        dourado: '#C5A059',
      },
      fontFamily: {
        bebas: ['"Bebas Neue"', 'cursive'],
        inter: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}