// Floating particles
for (let i = 0; i < 40; i++) {
  let p = document.createElement("div");
  p.classList.add("particle");
  p.style.left = Math.random() * 100 + "vw";
  p.style.bottom = Math.random() * -40 + "vh";
  p.style.animationDelay = Math.random() * 10 + "s";
  p.style.opacity = Math.random() * 0.5 + 0.2;
  document.body.appendChild(p);
}

// Live clock
function updateClock() {
  const clock = document.getElementById('liveClock');
  const now = new Date();
  const formatted =
    now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0')+' '
    +String(now.getHours()).padStart(2,'0')+':'+String(now.getMinutes()).padStart(2,'0')+':'+String(now.getSeconds()).padStart(2,'0');
  clock.textContent = formatted;
}
setInterval(updateClock, 1000);

// Troll button functionality
const trollBtn = document.getElementById('trollBtn');
const trollCard = document.getElementById('trollCard');

trollBtn.addEventListener('click', () => {
  trollCard.style.display = 'block';
  // Reset animation
  trollCard.style.animation = 'none';
  void trollCard.offsetWidth;
  trollCard.style.animation = 'popUp 0.5s ease forwards';
});
