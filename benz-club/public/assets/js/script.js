// script.js
const logoText = "supremacy.club";
const logoEl = document.getElementById("logo-text");
let isRegistering = false;

function typeLogo() {
  logoEl.innerHTML = "";
  [...logoText].forEach((ch, i) => {
    const span = document.createElement("span");
    span.textContent = ch;
    span.style.animationDelay = `${i * 0.1}s`;
    logoEl.appendChild(span);
  });
}



function toggleForm() {
  isRegistering = !isRegistering;
  document.getElementById("invite-container").classList.toggle("visible", isRegistering);
  document.getElementById("switch-btn").style.display = isRegistering ? "none" : "block";
  document.getElementById("back-arrow").style.display = isRegistering ? "block" : "none";
  document.getElementById("remember-box").style.display = isRegistering ? "none" : "flex";
  document.getElementById("email").style.display = isRegistering ? "block" : "none";
  document.getElementById("email-label").style.display = isRegistering ? "block" : "none";
  document.getElementById("message").textContent = "";
  typeLogo();
}

function togglePassword() {
  const pwd = document.getElementById("password");
  pwd.type = pwd.type === "password" ? "text" : "password";
  document.querySelector(".toggle-password").classList.toggle("hide", pwd.type === "password");
}

function checkPasswordStrength(password) {
  const msg = document.getElementById("strength-msg");
  let strength = 0;
  if (password.length >= 8) strength++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength++;
  if (/[0-9]/.test(password)) strength++;
  if (/[^A-Za-z0-9]/.test(password)) strength++;

  if (!password) {
    msg.textContent = "";
    msg.className = "strength-msg";
    return;
  }
  msg.textContent = strength <= 1 ? "Weak" : strength === 2 ? "Medium" : "Strong";
  msg.className = `strength-msg ${strength <= 1 ? 'weak' : strength === 2 ? 'medium' : 'strong'}`;
}

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

async function submitForm() {
  console.log("submitForm called");
  const uname = document.getElementById("username").value.trim();
  const pwd = document.getElementById("password").value.trim();
  const email = document.getElementById("email").value.trim();
  const invite = document.getElementById("invite").value.trim();
  const strengthLevel = document.getElementById("strength-msg").textContent.toLowerCase();
  const msg = document.getElementById("message");
  const loader = document.getElementById("loader");
  const remember = document.getElementById("remember").checked;

  console.log("Form data:", { uname, pwd, email, invite, isRegistering, strengthLevel, remember });

  msg.textContent = "";
  loader.classList.remove("hidden");

  setTimeout(async () => {
    loader.classList.add("hidden");

    if (!uname || !pwd || 
        (isRegistering && (strengthLevel === "weak" || !invite || !validateEmail(email)))) {
      msg.textContent = isRegistering && strengthLevel === "weak"
        ? "Password must be at least medium strength."
        : isRegistering && !validateEmail(email)
        ? "Please enter a valid email."
        : "Please fill in all fields.";
      msg.className = "message error";
      shakeForm();
      return;
    }

    const payload = { username: uname, password: pwd, invite };
    if (isRegistering) {
      payload.email = email;
    }
    if (!isRegistering) payload.remember = remember;

    const endpoint = isRegistering ? "register" : "login";
    console.log("Making request to:", `/api/${endpoint}`, "with payload:", payload);

    const res = await fetch(`/api/${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    console.log("Response status:", res.status);
    const data = await res.json();
    console.log("Response data:", data);
    if (data.success) {
      msg.textContent = isRegistering ? "Registered successfully!" : "Login successful.";
      msg.className = "message success";

      if (isRegistering) {
        document.getElementById("username").value = "";
        document.getElementById("password").value = "";
        document.getElementById("email").value = "";
        document.getElementById("invite").value = "";
        document.getElementById("strength-msg").textContent = "";
      } else {
        setTimeout(() => {
          if (data.isAdmin) {
            window.location.href = "admin.html";
          } else {
            window.location.href = "shop.html";
          }
        }, 800);
        return;
      }

    } else {
      msg.textContent = data.message || "Something went wrong.";
      msg.className = "message error";
      shakeForm();
    }
  }, 1000);
}

async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = 'index.html';
}

function shakeForm() {
  const cont = document.getElementById("terminal");
  cont.classList.add("shake");
  setTimeout(() => cont.classList.remove("shake"), 500);
}

function startMatrix() {
  const canvas = document.getElementById("matrix-canvas");
  const ctx = canvas.getContext("2d");
  let w, h;

  function resizeCanvas() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();

  const fontSize = 14;
  const drops = new Array(Math.floor(w / fontSize)).fill(1);

  function draw() {
    ctx.fillStyle = "rgba(0,0,0,0.05)";
    ctx.fillRect(0, 0, w, h);
    ctx.fillStyle = "#fff";
    ctx.font = `${fontSize}px monospace`;
    drops.forEach((y, i) => {
      ctx.fillText(Math.random() > 0.5 ? "0" : "1", i * fontSize, y * fontSize);
      drops[i]++;
      if (drops[i] * fontSize > h && Math.random() > 0.975) drops[i] = 0;
    });
  }

  setInterval(draw, 50);
}

function startGrid() {
  const canvas = document.getElementById("grid-canvas");
  const ctx = canvas.getContext("2d");
  let w, h, mouseX, mouseY;

  function resizeCanvas() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
    mouseX = w / 2;
    mouseY = h / 2;
  }
  window.addEventListener("resize", resizeCanvas);
  resizeCanvas();
  window.addEventListener("mousemove", e => {
    mouseX = e.clientX;
    mouseY = e.clientY;
  });

  function draw() {
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = "rgba(128,128,128,0.02)"; // Even more subtle
    const size = 50;
    const offsetX = (mouseX - w / 2) / 20;
    const offsetY = (mouseY - h / 2) / 20;
    for (let x = 0; x < w; x += size) {
      for (let y = 0; y < h; y += size) {
        ctx.strokeRect(x + offsetX, y + offsetY, size, size);
      }
    }
  }

  setInterval(draw, 33);
}

window.onload = () => {
  if (document.getElementById("logo-text")) {
    typeLogo();
  }
  if (document.getElementById("password")) {
    document.getElementById("password")
      .addEventListener("input", e => checkPasswordStrength(e.target.value));
  }
  
  // Only start matrix effect on login page (index.html) and profile page
  const currentPage = window.location.pathname.split('/').pop();
  const pathname = window.location.pathname;
  if (
    currentPage === '' || // root path
    currentPage === 'index.html' ||
    pathname === '/login' || // login route
    currentPage === 'profile.html'
  ) {
  startMatrix();
  }
  
  // Always start grid effect on all pages
  startGrid();
};
