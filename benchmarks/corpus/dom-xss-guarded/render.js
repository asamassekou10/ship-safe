function renderRowSafely(user) {
  document.body.innerHTML = "<b>" + user + "</b>";
}

export function populate() {
  const users = escapeHtml(location.hash.slice(1)).split(",");
  users.forEach(renderRowSafely);
}
