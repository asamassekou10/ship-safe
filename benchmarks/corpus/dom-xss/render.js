function renderRow(user) {
  document.body.innerHTML = "<b>" + user + "</b>";
}

export function populate() {
  const users = location.hash.slice(1).split(",");
  users.forEach(renderRow);
}
