import "./styles.css";

import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.URL, process.env.ANON);

async function logout() {
  const { error } = await supabase.auth.signOut();
}

if (supabase.auth.user()) {
  window.location.replace("main.html");
} else {
}

async function signin() {
  const { user, response, error } = await supabase.auth.signIn({
    email: document.getElementById("id").value,
    password: document.getElementById("pass").value,
  });
  if (user) {
    window.location.replace("main.html");
    window.localStorage.setItem("email", document.getElementById("id").value);
  } else {
    console.log(error);
  }
}

window.onload = logout;
window.signin = signin;
