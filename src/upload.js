import { createClient } from "@supabase/supabase-js";
import "./styles.css";

// Create a single supabase client for interacting with your database
const supabase = createClient(
  "https://rsfcqodmucagrxohmkgx.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzZmNxb2RtdWNhZ3J4b2hta2d4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE2NjA5MjY5NDksImV4cCI6MTk3NjUwMjk0OX0.emUFAjUIpou6UOyQlIzvlvv9E4tClWoluh6SOoMNc8I"
);
import 'js-loading-overlay'

var overlayobj={
  'overlayBackgroundColor': '#FFFFFF',
  'overlayOpacity': 1,
  'spinnerIcon': 'ball-atom',
  'spinnerColor': '#000',
  'spinnerSize': '2x',
  'overlayIDName': 'overlay',
  'spinnerIDName': 'spinner',
}

JsLoadingOverlay.show(overlayobj);

window.onload=JsLoadingOverlay.hide();


async function logout() {
  await supabase.auth.signOut();
  window.location.replace("index.html");
}
console.log(supabase.auth.user());

if (supabase.auth.user()) {
  document.getElementById("formie").classList.remove("hidden");
  document.getElementById("notlogged").classList.add("hidden");
  JsLoadingOverlay.hide()

} else {
  JsLoadingOverlay.hide()

  document.getElementById("formie").classList.add("hidden");
  document.getElementById("notlogged").classList.remove("hidden");
}

function accessAdmin() {
  if (document.getElementById("admin").classList.contains("hidden")) {
    JSAlert.alert(
      "<code>Error:- You have not been granted Admin access</code>",
      null,
      JSAlert.Icons.Failed
    );
  } else {
    window.location.href = "admin.html";
  }
}

function openNav() {
  document.getElementById("mySidenav").style.width = "250px";
}

function closeNav() {
  document.getElementById("mySidenav").style.width = "0";
}

var files = [];
document.getElementById("files").addEventListener("change", function (e) {
  files = e.target.files;
});

document.getElementById("send").addEventListener("click", async function () {
  if (files.length != 0) {
    for (let i = 0; i < files.length; i++) {
      const { data, error } = await supabase.storage
        .from("forms")
        .upload(
          document.getElementById("level").value +
            "/" +
            document.getElementById("folder").value +
            "/" +
            files[i].name,
          files[i],
          {
            cacheControl: "3600",
            upsert: false,
          }
        );
    }
  }
});

window.openNav = openNav;
window.closeNav = closeNav;

window.logout = logout;
window.accessAdmin = accessAdmin;
