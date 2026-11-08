// Applied before first paint so the saved theme does not flash.
try {
  var t = localStorage.getItem("cc_theme");
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
} catch (e) {}
