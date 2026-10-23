// ShopNorth checkout: formats the card number as you type (demo).
document.querySelector("#cc-number")?.addEventListener("input", (e) => {
  const d = e.target.value.replace(/\D/g, "").slice(0, 16);
  e.target.value = d.replace(/(.{4})/g, "$1 ").trim();
});
